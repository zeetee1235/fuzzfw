// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
//
// fuzzfw-analyze: read-only Clang LibTooling AST analysis.
//
// The tool accepts a JSON invocation (one translation unit and its original
// compilation arguments) and emits the analysis fragment contract consumed by
// the Go planner. It never rewrites or instruments user code.

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Mangle.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Index/USRGeneration.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using namespace clang;
using namespace clang::tooling;

struct Invocation {
  std::string root;
  std::string directory;
  std::string file;
  std::string language;
  std::string variant;
  std::vector<std::string> arguments;
};

struct CallFact {
  std::string name;
  std::string qualified;
  std::string symbol;
  std::string source;
  int line = 0;
  bool direct = true;
};

struct ParamFact {
  int index = 0;
  std::string name;
  std::string type;
  std::string canonical;
  bool is_const = false;
  bool is_pointer = false;
  bool is_integer = false;
  bool is_signed = false;
  bool is_volatile = false;
  bool is_void_pointer = false;
  int bits = 0;
};

struct FunctionFact {
  std::string language;
  std::string name;
  std::string qualified;
  std::string mangled;
  std::string usr;
  std::string signature;
  std::string return_type;
  std::string source;
  int line = 0;
  int column = 0;
  bool definition = true;
  bool internal_linkage = false;
  bool is_method = false;
  bool is_static_method = false;
  bool variadic = false;
  std::vector<ParamFact> params;
  std::vector<CallFact> calls;
  std::vector<std::string> unresolved;
  std::vector<std::string> indirect;
  std::vector<std::string> global_reads;
  std::vector<std::string> global_writes;
  std::vector<std::string> hardware_flags;
  std::vector<std::string> evidence;
};

struct DeclarationFact {
  std::string name;
  std::string qualified;
  std::string mangled;
  std::string signature;
  std::string source;
  int line = 0;
  std::string language;
};

std::string jsonString(const llvm::json::Value &value, llvm::StringRef key,
                       std::string fallback = "") {
  if (const auto *object = value.getAsObject()) {
    if (auto v = object->getString(key))
      return v->str();
  }
  return fallback;
}

std::string absoluteRelative(const std::string &root, const std::string &path) {
  if (path.empty())
    return path;
  std::error_code ec;
  fs::path rootPath = fs::weakly_canonical(fs::path(root), ec);
  fs::path filePath = fs::weakly_canonical(fs::path(path), ec);
  if (!ec) {
    fs::path relative = filePath.lexically_relative(rootPath);
    if (!relative.empty() && relative.native().rfind("..", 0) != 0)
      return relative.generic_string();
  }
  return path;
}

bool isInside(const std::string &root, const std::string &path) {
  std::error_code ec;
  fs::path rootPath = fs::weakly_canonical(fs::path(root), ec);
  fs::path filePath = fs::weakly_canonical(fs::path(path), ec);
  if (ec)
    return false;
  auto relative = filePath.lexically_relative(rootPath);
  return !relative.empty() && relative.native().rfind("..", 0) != 0;
}

std::string mangle(ASTContext &context, const FunctionDecl *decl) {
  std::unique_ptr<MangleContext> mangleContext(context.createMangleContext());
  llvm::SmallString<256> buffer;
  llvm::raw_svector_ostream stream(buffer);
  if (mangleContext->shouldMangleDeclName(decl)) {
    mangleContext->mangleName(GlobalDecl(decl), stream);
  } else {
    stream << decl->getName();
  }
  return stream.str().str();
}

std::string usrFor(const FunctionDecl *decl) {
  llvm::SmallString<128> buffer;
  if (clang::index::generateUSRForDecl(decl, buffer))
    return "";
  return buffer.str().str();
}

std::string functionQualifiedName(const FunctionDecl *decl) {
  return decl->getQualifiedNameAsString();
}

std::string locationFile(const SourceManager &sm, SourceLocation location) {
  location = sm.getSpellingLoc(location);
  return sm.getFilename(location).str();
}

bool isProjectFunction(const ASTContext &context, const std::string &root,
                       const FunctionDecl *decl) {
  const SourceManager &sm = context.getSourceManager();
  SourceLocation location = decl->getLocation();
  if (location.isInvalid() || sm.isInSystemHeader(location))
    return false;
  std::string file = locationFile(sm, location);
  return !file.empty() && isInside(root, file);
}

void appendUnique(std::vector<std::string> &values, const std::string &value) {
  if (value.empty())
    return;
  if (std::find(values.begin(), values.end(), value) == values.end())
    values.push_back(value);
}

void sortUnique(std::vector<std::string> &values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
}

class BodyVisitor : public RecursiveASTVisitor<BodyVisitor> {
public:
  BodyVisitor(ASTContext &context, std::string root, std::map<std::string, bool> packed)
      : context_(context), sm_(context.getSourceManager()), root_(std::move(root)),
        packed_(std::move(packed)) {}

  bool VisitCallExpr(CallExpr *expr) {
    if (const FunctionDecl *callee = expr->getDirectCallee()) {
      CallFact fact;
      fact.name = callee->getNameAsString();
      fact.qualified = callee->getQualifiedNameAsString();
      fact.symbol = mangle(context_, callee);
      fact.source = relativeLocation(expr->getExprLoc());
      fact.line = sm_.getSpellingLineNumber(expr->getExprLoc());
      fact.direct = true;
      calls_.push_back(fact);
      addCallFlags(callee->getNameAsString());
    } else {
      indirect_.push_back(expr->getCallee()->getType().getAsString());
      addFlag("INDIRECT_UNKNOWN");
    }
    checkType(expr->getType());
    return true;
  }

  bool VisitCXXConstructExpr(CXXConstructExpr *expr) {
    if (const CXXConstructorDecl *ctor = expr->getConstructor()) {
      CallFact fact;
      fact.name = ctor->getQualifiedNameAsString();
      fact.symbol = "";
      fact.source = relativeLocation(expr->getExprLoc());
      fact.line = sm_.getSpellingLineNumber(expr->getExprLoc());
      fact.direct = true;
      calls_.push_back(fact);
    }
    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *expr) {
    if (auto *var = dyn_cast<VarDecl>(expr->getDecl())) {
      if (var->hasGlobalStorage() && !var->isLocalVarDecl()) {
        appendUnique(reads_, var->getQualifiedNameAsString());
      }
    }
    checkType(expr->getType());
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *op) {
    if (op->getOpcode() == BO_Assign || op->isCompoundAssignmentOp()) {
      std::set<std::string> names;
      collectGlobals(op->getLHS(), names);
      for (const auto &name : names) {
        appendUnique(writes_, name);
        if (op->isCompoundAssignmentOp())
          appendUnique(reads_, name);
      }
    }
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *op) {
    if (op->isIncrementDecrementOp()) {
      std::set<std::string> names;
      collectGlobals(op->getSubExpr(), names);
      for (const auto &name : names)
        appendUnique(writes_, name);
    }
    if (op->getOpcode() == UO_Deref && op->getType().isVolatileQualified()) {
      addFlag("MMIO_DIRECT");
      evidence_.push_back("volatile_access:" + relativeLocation(op->getExprLoc()));
    }
    return true;
  }

  bool VisitCStyleCastExpr(CStyleCastExpr *expr) {
    if (expr->getCastKind() == CK_IntegralToPointer ||
        expr->getCastKind() == CK_PointerToIntegral) {
      addFlag("MMIO_DIRECT");
      evidence_.push_back("integer_pointer_cast:" + relativeLocation(expr->getExprLoc()));
    }
    return true;
  }

  bool VisitCXXReinterpretCastExpr(CXXReinterpretCastExpr *expr) {
    if (expr->getCastKind() == CK_IntegralToPointer ||
        expr->getCastKind() == CK_PointerToIntegral) {
      addFlag("MMIO_DIRECT");
    }
    return true;
  }

  bool VisitGCCAsmStmt(GCCAsmStmt *stmt) {
    addFlag("ARCH_ASM");
    evidence_.push_back("inline_asm:" + relativeLocation(stmt->getBeginLoc()));
    return true;
  }

  bool VisitMSAsmStmt(MSAsmStmt *stmt) {
    addFlag("ARCH_ASM");
    evidence_.push_back("inline_asm:" + relativeLocation(stmt->getBeginLoc()));
    return true;
  }

  bool VisitAtomicExpr(AtomicExpr *expr) {
    addFlag("RTOS_CONTEXT");
    return true;
  }

  const std::vector<CallFact> &calls() const { return calls_; }
  const std::vector<std::string> &indirect() const { return indirect_; }
  const std::vector<std::string> &reads() const { return reads_; }
  const std::vector<std::string> &writes() const { return writes_; }
  const std::vector<std::string> &flags() const { return flags_; }
  const std::vector<std::string> &evidence() const { return evidence_; }

private:
  std::string relativeLocation(SourceLocation location) const {
    std::string file = locationFile(sm_, location);
    if (file.empty())
      return "";
    return absoluteRelative(root_, file) + ":" +
           std::to_string(sm_.getSpellingLineNumber(location));
  }

  void collectGlobals(Expr *expr, std::set<std::string> &names) {
    if (auto *ref = dyn_cast<DeclRefExpr>(expr)) {
      if (auto *var = dyn_cast<VarDecl>(ref->getDecl())) {
        if (var->hasGlobalStorage() && !var->isLocalVarDecl())
          names.insert(var->getQualifiedNameAsString());
      }
      return;
    }
    if (auto *index = dyn_cast<ArraySubscriptExpr>(expr)) {
      collectGlobals(index->getBase(), names);
      return;
    }
    if (auto *member = dyn_cast<MemberExpr>(expr)) {
      collectGlobals(member->getBase(), names);
      return;
    }
    if (auto *cast = dyn_cast<CastExpr>(expr)) {
      collectGlobals(cast->getSubExpr(), names);
      return;
    }
    if (auto *unary = dyn_cast<UnaryOperator>(expr)) {
      collectGlobals(unary->getSubExpr(), names);
      return;
    }
  }

  void checkType(QualType type) {
    if (type.isVolatileQualified()) {
      addFlag("MMIO_DIRECT");
      evidence_.push_back("volatile_type:" + type.getAsString());
    }
    std::string text = type.getAsString();
    for (const auto &entry : packed_) {
      if (entry.second && text.find(entry.first) != std::string::npos) {
        addFlag("ABI_LAYOUT");
        evidence_.push_back("packed_type:" + entry.first);
      }
    }
  }

  void addCallFlags(const std::string &name) {
    std::string upper = name;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    if (upper.rfind("HAL_", 0) == 0 || upper.rfind("LL_", 0) == 0) {
      addFlag("HAL_EXTERNAL");
      evidence_.push_back("hal_call:" + name);
    }
    if (name.find("DMA") != std::string::npos || name.find("dma") != std::string::npos) {
      addFlag("DMA_ASYNC");
    }
    if (upper.find("IRQ") != std::string::npos || upper.find("ISR") != std::string::npos) {
      addFlag("ISR_ENTRY");
    }
    if (upper.rfind("XTASK", 0) == 0 || upper.rfind("VTASK", 0) == 0 ||
        upper.rfind("OSTHREAD", 0) == 0 || upper.rfind("PTHREAD_", 0) == 0 ||
        name.rfind("k_", 0) == 0 || name.rfind("NVIC_", 0) == 0) {
      addFlag("RTOS_CONTEXT");
    }
  }

  void addFlag(const std::string &flag) {
    if (std::find(flags_.begin(), flags_.end(), flag) == flags_.end())
      flags_.push_back(flag);
  }

  ASTContext &context_;
  const SourceManager &sm_;
  std::string root_;
  std::map<std::string, bool> packed_;
  std::vector<CallFact> calls_;
  std::vector<std::string> indirect_;
  std::vector<std::string> reads_;
  std::vector<std::string> writes_;
  std::vector<std::string> flags_;
  std::vector<std::string> evidence_;
};

class AnalyzerVisitor : public RecursiveASTVisitor<AnalyzerVisitor> {
public:
  AnalyzerVisitor(ASTContext &context, std::string root, std::string language,
                  std::string variant, std::string tu)
      : context_(context), sm_(context.getSourceManager()), root_(std::move(root)),
        language_(std::move(language)), variant_(std::move(variant)), tu_(std::move(tu)) {}

  bool VisitRecordDecl(RecordDecl *decl) {
    if (decl->hasAttr<PackedAttr>() && !decl->getQualifiedNameAsString().empty()) {
      packed_[decl->getQualifiedNameAsString()] = true;
    }
    return true;
  }

  bool VisitFunctionDecl(FunctionDecl *decl) {
    if (decl->isImplicit() || !isProjectFunction(context_, root_, decl))
      return true;
    if (decl->getQualifiedNameAsString() == "main")
      return true;
    FunctionFact fact;
    fact.language = language_;
    fact.name = decl->getNameAsString();
    fact.qualified = functionQualifiedName(decl);
    fact.mangled = mangle(context_, decl);
    fact.usr = usrFor(decl);
    fact.signature = decl->getType().getAsString();
    fact.return_type = decl->getReturnType().getAsString();
    fact.source = absoluteRelative(root_, locationFile(sm_, decl->getLocation()));
    fact.line = sm_.getSpellingLineNumber(decl->getLocation());
    fact.column = sm_.getSpellingColumnNumber(decl->getLocation());
    fact.definition = decl->doesThisDeclarationHaveABody();
    fact.variadic = decl->isVariadic();
    if (auto *method = dyn_cast<CXXMethodDecl>(decl)) {
      fact.is_method = true;
      fact.is_static_method = method->isStatic();
    }
    if (decl->getStorageClass() == SC_Static && !fact.is_method)
      fact.internal_linkage = true;
    for (unsigned i = 0; i < decl->getNumParams(); ++i) {
      const ParmVarDecl *param = decl->getParamDecl(i);
      QualType type = param->getType();
      ParamFact p;
      p.index = static_cast<int>(i);
      p.name = param->getNameAsString();
      p.type = type.getAsString();
      p.canonical = type.getCanonicalType().getAsString();
      p.is_pointer = type->isPointerType();
      p.is_const = type.getCanonicalType().isConstQualified() ||
                   (p.is_pointer && type->getPointeeType().isConstQualified());
      p.is_volatile = type.isVolatileQualified() ||
                      (p.is_pointer && type->getPointeeType().isVolatileQualified());
      p.is_integer = type->isIntegerType();
      p.is_signed = type->isSignedIntegerType();
      p.is_void_pointer = p.is_pointer && type->getPointeeType()->isVoidType();
      if (p.is_integer)
        p.bits = static_cast<int>(context_.getTypeSize(type));
      fact.params.push_back(std::move(p));
    }
    if (fact.definition) {
      BodyVisitor body(context_, root_, packed_);
      body.TraverseStmt(decl->getBody());
      fact.calls = body.calls();
      fact.indirect = body.indirect();
      fact.global_reads = body.reads();
      fact.global_writes = body.writes();
      fact.hardware_flags = body.flags();
      fact.evidence = body.evidence();
      if (!fact.global_writes.empty()) {
        appendUnique(fact.hardware_flags, "INIT_REQUIRED");
      }
      for (const auto &call : fact.calls) {
        if (call.symbol.empty())
          appendUnique(fact.unresolved, call.name);
      }
      functions_.push_back(std::move(fact));
    } else {
      DeclarationFact declaration;
      declaration.name = fact.name;
      declaration.qualified = fact.qualified;
      declaration.mangled = fact.mangled;
      declaration.signature = fact.signature;
      declaration.source = fact.source;
      declaration.line = fact.line;
      declaration.language = language_;
      declarations_.push_back(std::move(declaration));
    }
    return true;
  }

  const std::vector<FunctionFact> &functions() const { return functions_; }
  const std::vector<DeclarationFact> &declarations() const { return declarations_; }

private:
  ASTContext &context_;
  const SourceManager &sm_;
  std::string root_;
  std::string language_;
  std::string variant_;
  std::string tu_;
  std::map<std::string, bool> packed_;
  std::vector<FunctionFact> functions_;
  std::vector<DeclarationFact> declarations_;
};

class AnalyzerConsumer : public ASTConsumer {
public:
  AnalyzerConsumer(std::string root, std::string language, std::string variant,
                   std::string tu, std::vector<FunctionFact> &functions,
                   std::vector<DeclarationFact> &declarations)
      : root_(std::move(root)), language_(std::move(language)),
        variant_(std::move(variant)), tu_(std::move(tu)),
        functions_(functions), declarations_(declarations) {}

  void HandleTranslationUnit(ASTContext &context) override {
    AnalyzerVisitor visitor(context, root_, language_, variant_, tu_);
    visitor.TraverseDecl(context.getTranslationUnitDecl());
    functions_ = visitor.functions();
    declarations_ = visitor.declarations();
  }

private:
  std::string root_;
  std::string language_;
  std::string variant_;
  std::string tu_;
  std::vector<FunctionFact> &functions_;
  std::vector<DeclarationFact> &declarations_;
};

class AnalyzerAction : public ASTFrontendAction {
public:
  AnalyzerAction(std::string root, std::string language, std::string variant,
                 std::string tu, std::vector<FunctionFact> &functions,
                 std::vector<DeclarationFact> &declarations)
      : root_(std::move(root)), language_(std::move(language)),
        variant_(std::move(variant)), tu_(std::move(tu)),
        functions_(functions), declarations_(declarations) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &,
                                                 StringRef) override {
    return std::make_unique<AnalyzerConsumer>(root_, language_, variant_, tu_,
                                              functions_, declarations_);
  }

private:
  std::string root_;
  std::string language_;
  std::string variant_;
  std::string tu_;
  std::vector<FunctionFact> &functions_;
  std::vector<DeclarationFact> &declarations_;
};

class AnalyzerFactory : public FrontendActionFactory {
public:
  AnalyzerFactory(std::string root, std::string language, std::string variant,
                  std::string tu, std::vector<FunctionFact> &functions,
                  std::vector<DeclarationFact> &declarations)
      : root_(std::move(root)), language_(std::move(language)),
        variant_(std::move(variant)), tu_(std::move(tu)),
        functions_(functions), declarations_(declarations) {}

  std::unique_ptr<FrontendAction> create() override {
    return std::make_unique<AnalyzerAction>(root_, language_, variant_, tu_,
                                            functions_, declarations_);
  }

private:
  std::string root_;
  std::string language_;
  std::string variant_;
  std::string tu_;
  std::vector<FunctionFact> &functions_;
  std::vector<DeclarationFact> &declarations_;
};

llvm::json::Object callJSON(const CallFact &call) {
  llvm::json::Object object;
  object["name"] = call.name;
  if (!call.symbol.empty())
    object["symbol"] = call.symbol;
  if (!call.source.empty())
    object["source"] = call.source;
  if (call.line > 0)
    object["line"] = call.line;
  object["direct"] = call.direct;
  return object;
}

llvm::json::Object functionJSON(const FunctionFact &fact) {
  llvm::json::Object object;
  object["language"] = fact.language;
  object["name"] = fact.name;
  object["qualified_name"] = fact.qualified;
  if (!fact.mangled.empty())
    object["mangled_name"] = fact.mangled;
  if (!fact.usr.empty())
    object["usr"] = fact.usr;
  object["signature"] = fact.signature;
  object["return_type"] = fact.return_type;
  object["source"] = fact.source;
  object["line"] = fact.line;
  object["column"] = fact.column;
  object["definition"] = fact.definition;
  object["internal_linkage"] = fact.internal_linkage;
  object["is_method"] = fact.is_method;
  if (fact.is_static_method)
    object["is_static_method"] = true;
  if (fact.variadic)
    object["variadic"] = true;
  llvm::json::Array params;
  for (const auto &param : fact.params) {
    llvm::json::Object p;
    p["index"] = param.index;
    if (!param.name.empty())
      p["name"] = param.name;
    p["type"] = param.type;
    p["canonical_type"] = param.canonical;
    p["is_const"] = param.is_const;
    p["is_pointer"] = param.is_pointer;
    p["is_integer"] = param.is_integer;
    p["is_signed"] = param.is_signed;
    p["is_volatile"] = param.is_volatile;
    p["is_void_pointer"] = param.is_void_pointer;
    if (param.bits > 0)
      p["bits"] = param.bits;
    params.push_back(std::move(p));
  }
  object["params"] = std::move(params);
  llvm::json::Array calls;
  for (const auto &call : fact.calls)
    calls.push_back(callJSON(call));
  if (!calls.empty())
    object["direct_callees"] = std::move(calls);
  llvm::json::Array unresolved;
  for (const auto &name : fact.unresolved)
    unresolved.push_back(name);
  if (!unresolved.empty())
    object["unresolved_calls"] = std::move(unresolved);
  llvm::json::Array indirect;
  for (const auto &name : fact.indirect)
    indirect.push_back(name);
  if (!indirect.empty())
    object["indirect_calls"] = std::move(indirect);
  auto addArray = [&](const char *key, const std::vector<std::string> &values) {
    if (values.empty())
      return;
    llvm::json::Array array;
    for (const auto &value : values)
      array.push_back(value);
    object[key] = std::move(array);
  };
  addArray("global_reads", fact.global_reads);
  addArray("global_writes", fact.global_writes);
  addArray("hardware_flags", fact.hardware_flags);
  llvm::json::Array evidence;
  for (const auto &item : fact.evidence) {
    llvm::json::Object e;
    e["kind"] = "ast_observation";
    e["detail"] = item;
    e["confidence"] = "observed";
    evidence.push_back(std::move(e));
  }
  if (!evidence.empty())
    object["evidence"] = std::move(evidence);
  return object;
}

llvm::json::Object declarationJSON(const DeclarationFact &fact) {
  llvm::json::Object object;
  object["name"] = fact.name;
  object["qualified_name"] = fact.qualified;
  if (!fact.mangled.empty())
    object["mangled_name"] = fact.mangled;
  object["signature"] = fact.signature;
  object["source"] = fact.source;
  if (fact.line > 0)
    object["line"] = fact.line;
  object["language"] = fact.language;
  return object;
}

int run(const Invocation &invocation, const std::string &output) {
  std::vector<std::string> commandLine;
  for (std::size_t i = 1; i < invocation.arguments.size(); ++i) {
    const std::string &arg = invocation.arguments[i];
    if (arg == "-o" || arg == "-MF" || arg == "-MT" || arg == "-MQ" || arg == "-MJ") {
      ++i;
      continue;
    }
    if (arg == "-c" || arg == "-S" || arg == "-E" || arg == "-fsyntax-only" ||
        arg == "-MD" || arg == "-MMD" || arg == "-MP" || arg == "-MG")
      continue;
    if (arg == invocation.file)
      continue;
    commandLine.push_back(arg);
  }
  FixedCompilationDatabase database(invocation.directory, commandLine);
  ClangTool tool(database, {invocation.file});
  std::vector<FunctionFact> functions;
  std::vector<DeclarationFact> declarations;
  AnalyzerFactory factory(invocation.root, invocation.language, invocation.variant,
                          absoluteRelative(invocation.root, invocation.file),
                          functions, declarations);
  int result = tool.run(&factory);
  if (result != 0) {
    llvm::errs() << "fuzzfw-analyze: ClangTool failed with exit " << result << "\n";
    return result;
  }
  llvm::json::Object document;
  document["schema_version"] = 1;
  document["generator"] = "fuzzfw-analyze/0.1";
  llvm::json::Array functionArray;
  for (const auto &fact : functions)
    functionArray.push_back(functionJSON(fact));
  document["functions"] = std::move(functionArray);
  llvm::json::Array declarationArray;
  for (const auto &fact : declarations)
    declarationArray.push_back(declarationJSON(fact));
  document["declarations"] = std::move(declarationArray);
  std::ofstream stream(output, std::ios::binary | std::ios::trunc);
  if (!stream) {
    llvm::errs() << "fuzzfw-analyze: cannot write " << output << "\n";
    return 2;
  }
  llvm::json::Value value(std::move(document));
  stream << llvm::formatv("{0:2}", value).str() << "\n";
  return stream ? 0 : 2;
}

} // namespace

int main(int argc, char **argv) {
  std::string inputPath;
  std::string outputPath;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--input" && i + 1 < argc) {
      inputPath = argv[++i];
    } else if (arg == "--output" && i + 1 < argc) {
      outputPath = argv[++i];
    } else if (arg == "--version") {
      llvm::outs() << "fuzzfw-analyze 0.1 (Clang LibTooling)\n";
      return 0;
    } else {
      llvm::errs() << "fuzzfw-analyze: unknown argument " << arg << "\n";
      return 2;
    }
  }
  if (inputPath.empty() || outputPath.empty()) {
    llvm::errs() << "usage: fuzzfw-analyze --input INVOCATION.json --output FRAGMENT.json\n";
    return 2;
  }
  auto buffer = llvm::MemoryBuffer::getFile(inputPath);
  if (!buffer) {
    llvm::errs() << "fuzzfw-analyze: cannot read " << inputPath << "\n";
    return 2;
  }
  auto parsed = llvm::json::parse((*buffer)->getBuffer());
  if (!parsed) {
    llvm::errs() << "fuzzfw-analyze: invalid JSON\n";
    return 2;
  }
  Invocation invocation;
  invocation.root = jsonString(*parsed, "root");
  invocation.directory = jsonString(*parsed, "directory");
  invocation.file = jsonString(*parsed, "file");
  invocation.language = jsonString(*parsed, "language", "c");
  invocation.variant = jsonString(*parsed, "variant_id");
  if (const auto *object = parsed->getAsObject()) {
    if (const auto *args = object->getArray("arguments")) {
      for (const auto &arg : *args) {
        if (auto value = arg.getAsString())
          invocation.arguments.push_back(value->str());
      }
    }
  }
  if (invocation.root.empty() || invocation.directory.empty() ||
      invocation.file.empty() || invocation.arguments.empty()) {
    llvm::errs() << "fuzzfw-analyze: invocation is missing root/directory/file/arguments\n";
    return 2;
  }
  return run(invocation, outputPath);
}
