// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
//
// fuzzfw-ir-analyze: read-only LLVM IR fact extractor.
//
// This first implementation walks the Module/Function/Instruction graph and
// produces conservative argument-use facts. It does not transform IR and does
// not claim alias or initialization proofs. Later revisions can add New PM
// analyses (AA/MemorySSA/DominatorTree) behind the same JSON contract.

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

using namespace llvm;

struct ArgFact {
  std::set<std::string> uses;
  bool may_escape = false;
};

bool isMemoryCallee(const Function *function) {
  if (function == nullptr)
    return false;
  StringRef name = function->getName();
  return name == "memcpy" || name == "memmove" || name == "memset" ||
         name == "memcmp" || name == "strlen" || name == "strnlen" ||
         name == "strcmp" || name == "strncmp" || name == "strcpy" ||
         name == "strncpy" || name == "strcat" || name == "strncat" ||
         name.starts_with("__builtin_mem") || name.starts_with("__builtin_str");
}

bool isAllocationCallee(StringRef name) {
  return name == "malloc" || name == "calloc" || name == "realloc" ||
         name == "aligned_alloc" || name == "memalign";
}

void markUses(std::vector<ArgFact> &uses, uint64_t mask, const std::string &use) {
  for (std::size_t i = 0; i < uses.size() && i < 63; ++i) {
    if (mask & (uint64_t{1} << i))
      uses[i].uses.insert(use);
  }
}

void markEscape(std::vector<ArgFact> &uses, uint64_t mask) {
  for (std::size_t i = 0; i < uses.size() && i < 63; ++i) {
    if (mask & (uint64_t{1} << i))
      uses[i].may_escape = true;
  }
}

uint64_t operandMask(const Instruction &instruction,
                     const DenseMap<const Value *, uint64_t> &taint) {
  uint64_t mask = 0;
  for (const Use &operand : instruction.operands()) {
    auto it = taint.find(operand.get());
    if (it != taint.end())
      mask |= it->second;
  }
  return mask;
}

std::string globalName(const Value *value) {
  if (const auto *global = dyn_cast<GlobalVariable>(value->stripPointerCasts()))
    return global->getName().str();
  return "";
}

struct FunctionFacts {
  std::string symbol;
  std::vector<ArgFact> uses;
  std::set<std::string> globals;
  std::set<std::string> flags;
  std::set<std::string> unknowns;
  bool dataDependent = false;
  unsigned branchCount = 0;
  unsigned loadCount = 0;
  unsigned storeCount = 0;
  unsigned indirectCalls = 0;
  std::string targetTriple;
};

FunctionFacts analyzeFunction(const Function &function, const Module &module,
                              const std::set<std::string> &defined) {
  FunctionFacts facts;
  facts.symbol = function.getName().str();
  facts.targetTriple = module.getTargetTriple().str();
  facts.uses.resize(function.arg_size());
  DenseMap<const Value *, uint64_t> taint;
  DenseMap<const Value *, uint64_t> memory;
  std::size_t index = 0;
  for (const Argument &argument : function.args()) {
    if (index < 63)
      taint[&argument] = uint64_t{1} << index;
    ++index;
  }
  for (const BasicBlock &block : function) {
    for (const Instruction &instruction : block) {
      if (isa<AllocaInst>(instruction))
        memory[&instruction] = 0;
    }
  }
  for (int pass = 0; pass < 4; ++pass) {
    for (const BasicBlock &block : function) {
      for (const Instruction &instruction : block) {
        if (const auto *store = dyn_cast<StoreInst>(&instruction)) {
          const Value *pointer = store->getPointerOperand();
          uint64_t valueMask = 0;
          auto valueIt = taint.find(store->getValueOperand());
          if (valueIt != taint.end())
            valueMask = valueIt->second;
          auto memoryIt = memory.find(pointer);
          if (memoryIt != memory.end())
            memoryIt->second |= valueMask;
          auto pointerIt = taint.find(pointer);
          uint64_t pointerMask = pointerIt != taint.end() ? pointerIt->second : 0;
          if (pointerMask)
            markUses(facts.uses, pointerMask, "memory_write");
          if (!globalName(pointer).empty())
            facts.globals.insert("write:" + globalName(pointer));
          if (store->isVolatile())
            facts.flags.insert("MMIO_DIRECT");
          continue;
        }
        if (const auto *load = dyn_cast<LoadInst>(&instruction)) {
          const Value *pointer = load->getPointerOperand();
          uint64_t mask = 0;
          auto pointerIt = taint.find(pointer);
          if (pointerIt != taint.end())
            mask |= pointerIt->second;
          auto memoryIt = memory.find(pointer);
          if (memoryIt != memory.end())
            mask |= memoryIt->second;
          if (mask)
            markUses(facts.uses, mask, "memory_read");
          if (!globalName(pointer).empty())
            facts.globals.insert("read:" + globalName(pointer));
          if (load->isVolatile())
            facts.flags.insert("MMIO_DIRECT");
          taint[load] = mask;
          continue;
        }
        if (const auto *gep = dyn_cast<GetElementPtrInst>(&instruction)) {
          uint64_t mask = operandMask(instruction, taint);
          if (mask)
            markUses(facts.uses, mask, "indexed");
          taint[gep] = mask;
          continue;
        }
        if (const auto *cmp = dyn_cast<ICmpInst>(&instruction)) {
          uint64_t mask = operandMask(instruction, taint);
          if (mask)
            markUses(facts.uses, mask, "compare");
          for (const Value *operand : cmp->operands()) {
            if (const auto *constant = dyn_cast<ConstantInt>(operand)) {
              for (std::size_t i = 0; i < facts.uses.size() && i < 63; ++i) {
                if (mask & (uint64_t{1} << i))
                  facts.uses[i].uses.insert("compare_constant:" + std::to_string(constant->getSExtValue()));
              }
            }
          }
          taint[&instruction] = mask;
          continue;
        }
        if (isa<FCmpInst>(instruction)) {
          uint64_t mask = operandMask(instruction, taint);
          if (mask)
            markUses(facts.uses, mask, "compare");
          taint[&instruction] = mask;
          continue;
        }
        if (isa<BranchInst>(instruction) || isa<SwitchInst>(instruction) ||
            isa<IndirectBrInst>(instruction)) {
          facts.branchCount++;
          uint64_t mask = operandMask(instruction, taint);
          if (mask)
            markUses(facts.uses, mask, "branch");
          continue;
        }
        if (isa<PHINode>(instruction) || isa<SelectInst>(instruction) ||
            isa<CastInst>(instruction) || isa<FreezeInst>(instruction)) {
          if (isa<IntToPtrInst>(instruction) || isa<PtrToIntInst>(instruction))
            facts.flags.insert("MMIO_DIRECT");
          taint[&instruction] = operandMask(instruction, taint);
          continue;
        }
        if (const auto *call = dyn_cast<CallBase>(&instruction)) {
          uint64_t mask = 0;
          for (const Use &argument : call->args()) {
            auto it = taint.find(argument.get());
            if (it != taint.end())
              mask |= it->second;
          }
          if (mask) {
            markUses(facts.uses, mask, "passed_to_call");
            markEscape(facts.uses, mask);
          }
          if (isa<InlineAsm>(call->getCalledOperand()))
            facts.flags.insert("ARCH_ASM");
          const Function *callee = call->getCalledFunction();
          if (callee == nullptr) {
            facts.indirectCalls++;
            facts.flags.insert("INDIRECT_UNKNOWN");
          } else if (!callee->getName().starts_with("llvm.") &&
                     defined.find(callee->getName().str()) == defined.end()) {
            facts.unknowns.insert("external_call:" + callee->getName().str());
          }
          if (!call->getType()->isVoidTy())
            taint[call] = mask;
          continue;
        }
        if (const auto *ret = dyn_cast<ReturnInst>(&instruction)) {
          if (const Value *value = ret->getReturnValue()) {
            auto it = taint.find(value);
            if (it != taint.end()) {
              markUses(facts.uses, it->second, "may_escape");
              markEscape(facts.uses, it->second);
            }
          }
          continue;
        }
        if (isa<AtomicRMWInst>(instruction) || isa<AtomicCmpXchgInst>(instruction) ||
            isa<FenceInst>(instruction)) {
          facts.flags.insert("RTOS_CONTEXT");
          continue;
        }
        if (isa<CallBrInst>(instruction))
          facts.flags.insert("ARCH_ASM");
      }
    }
  }
  DominatorTree dominatorTree(const_cast<Function &>(function));
  LoopInfo loopInfo(dominatorTree);
  for (Loop *loop : loopInfo) {
    SmallVector<BasicBlock *, 8> blocks;
    blocks.push_back(loop->getHeader());
    if (BasicBlock *latch = loop->getLoopLatch())
      blocks.push_back(latch);
    for (BasicBlock *block : blocks) {
      const Instruction *terminator = block->getTerminator();
      if (terminator == nullptr)
        continue;
      uint64_t mask = operandMask(*terminator, taint);
      if (mask)
        markUses(facts.uses, mask, "loop_bound");
    }
  }
  for (const ArgFact &arg : facts.uses) {
    if (arg.uses.count("memory_read"))
      facts.loadCount++;
    if (arg.uses.count("memory_write"))
      facts.storeCount++;
    if (arg.uses.count("branch") || arg.uses.count("compare") ||
        arg.uses.count("indexed") || arg.uses.count("loop_bound") ||
        arg.uses.count("memory_read"))
      facts.dataDependent = true;
  }
  return facts;
}

llvm::json::Object factsJSON(const FunctionFacts &facts) {
  llvm::json::Object object;
  object["schema_version"] = 1;
  object["link_symbol"] = facts.symbol;
  object["ir_mapping"] = "resolved";
  if (!facts.targetTriple.empty())
    object["target_triple"] = facts.targetTriple;
  llvm::json::Array arguments;
  for (std::size_t i = 0; i < facts.uses.size(); ++i) {
    if (facts.uses[i].uses.empty() && !facts.uses[i].may_escape)
      continue;
    llvm::json::Object arg;
    arg["index"] = static_cast<int>(i);
    llvm::json::Array uses;
    for (const auto &use : facts.uses[i].uses)
      uses.push_back(use);
    if (!uses.empty())
      arg["observed_use"] = std::move(uses);
    arg["may_escape"] = facts.uses[i].may_escape;
    arguments.push_back(std::move(arg));
  }
  object["arguments"] = std::move(arguments);
  auto addArray = [&](const char *key, const std::set<std::string> &values) {
    if (values.empty())
      return;
    llvm::json::Array array;
    for (const auto &value : values)
      array.push_back(value);
    object[key] = std::move(array);
  };
  addArray("global_effects", facts.globals);
  addArray("hardware_flags", facts.flags);
  addArray("unknowns", facts.unknowns);
  object["branch_count"] = facts.branchCount;
  object["load_count"] = facts.loadCount;
  object["store_count"] = facts.storeCount;
  object["indirect_calls"] = facts.indirectCalls;
  object["data_dependent"] = facts.dataDependent;
  return object;
}

int run(const std::string &input, const std::string &output) {
  LLVMContext context;
  SMDiagnostic error;
  std::unique_ptr<Module> module = parseIRFile(input, error, context);
  if (!module) {
    error.print("fuzzfw-ir-analyze", errs());
    return 2;
  }
  std::set<std::string> defined;
  for (const Function &function : *module)
    if (!function.isDeclaration())
      defined.insert(function.getName().str());
  llvm::json::Object document;
  document["schema_version"] = 1;
  document["generator"] = "fuzzfw-ir-analyze/0.1";
  document["target_triple"] = module->getTargetTriple().str();
  llvm::json::Array facts;
  for (const Function &function : *module) {
    if (function.isDeclaration())
      continue;
    FunctionFacts functionFacts = analyzeFunction(function, *module, defined);
    facts.push_back(factsJSON(functionFacts));
  }
  document["facts"] = std::move(facts);
  std::ofstream stream(output, std::ios::binary | std::ios::trunc);
  if (!stream) {
    errs() << "fuzzfw-ir-analyze: cannot write " << output << "\n";
    return 2;
  }
  llvm::json::Value value(std::move(document));
  stream << formatv("{0:2}", value).str() << "\n";
  return stream ? 0 : 2;
}

} // namespace

int main(int argc, char **argv) {
  std::string input;
  std::string output;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--input" && i + 1 < argc)
      input = argv[++i];
    else if (arg == "--output" && i + 1 < argc)
      output = argv[++i];
    else if (arg == "--version") {
      outs() << "fuzzfw-ir-analyze 0.1 (LLVM IR)\n";
      return 0;
    } else {
      errs() << "fuzzfw-ir-analyze: unknown argument " << arg << "\n";
      return 2;
    }
  }
  if (input.empty() || output.empty()) {
    errs() << "usage: fuzzfw-ir-analyze --input MODULE.ll --output FACTS.json\n";
    return 2;
  }
  return run(input, output);
}
