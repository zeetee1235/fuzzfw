// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/proc"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

const irFactsSchemaVersion = 1

var (
	symbolPattern = regexp.MustCompile(`@(?:"([^"]+)"|([A-Za-z$._][A-Za-z$._0-9]*))`)
	valuePattern  = regexp.MustCompile(`%[-A-Za-z$._0-9]+`)
	targetPattern = regexp.MustCompile(`target\s+triple\s*=\s*"([^"]+)"`)
)

type irInstruction struct {
	result string
	kind   string
	rhs    string
	ops    []string
	line   int
}

type irFunction struct {
	symbol        string
	argValues     []string
	argTypes      []string
	instructions  []irInstruction
	labels        map[string]int
	indirectCalls int
}

type irModule struct {
	targetTriple string
	functions    map[string]*irFunction
	defined      map[string]bool
	declared     map[string]bool
	globals      map[string]bool
}

// analyzeIR emits textual LLVM IR and computes read-only argument-use facts.
// This is deliberately the bootstrap implementation: it never transforms user
// code and never claims alias or initialization proofs.
func analyzeIR(
	ctx context.Context,
	cfg *config.Config,
	command compdb.Command,
	functions []Function,
	variant Variant,
	hostTriple string,
	tools *toolchain.Report,
) ([]IRFunctionFact, string, []diag.Diagnostic) {
	if cfg.File.Analysis.ASTOnly || !cfg.File.Analysis.EmitIR {
		return nil, "disabled", nil
	}
	compiler, _, err := astCompiler(cfg, command)
	if err != nil {
		return nil, "unavailable", []diag.Diagnostic{
			diag.Newf(diag.EIRUnavailable, "cannot resolve compiler for IR analysis of %s: %v", variant.File, err).Warning().WithTarget(variant.File),
		}
	}
	args := irArguments(cfg, command, compiler)
	result, runErr := (proc.Runner{Timeout: time.Duration(cfg.File.Analysis.TimeoutSeconds) * time.Second}).
		Run(ctx, command.Directory, args...)
	if runErr != nil || result == nil {
		message := "failed to start IR generation"
		if runErr != nil {
			message += ": " + runErr.Error()
		}
		return nil, "unavailable", []diag.Diagnostic{
			diag.Newf(diag.EIRUnavailable, "%s for %s", message, variant.File).Warning().WithTarget(variant.File),
		}
	}
	if result.TimedOut {
		return nil, "unavailable", []diag.Diagnostic{
			diag.Newf(diag.EIRUnavailable, "IR generation timed out for %s", variant.File).Warning().WithTarget(variant.File),
		}
	}
	if result.ExitCode != 0 || strings.TrimSpace(result.Stdout) == "" {
		return nil, "unavailable", []diag.Diagnostic{
			diag.Newf(diag.EIRUnavailable, "IR generation failed for %s (exit %d): %s",
				variant.File, result.ExitCode, firstLines(result.Stderr, 5),
			).Warning().WithTarget(variant.File).WithEvidence(result.Stderr),
		}
	}
	if int64(len(result.Stdout)) > int64(cfg.File.Analysis.MaxIRBytes) {
		return nil, "unavailable", []diag.Diagnostic{
			diag.Newf(diag.EIRUnavailable, "IR text for %s exceeds analysis.max_ir_bytes", variant.File).Warning().WithTarget(variant.File),
		}
	}
	if nativeFacts, ok := analyzeIRNative(ctx, cfg, tools, functions, result.Stdout, variant, hostTriple); ok {
		return nativeFacts, "native_llvm_ir", nil
	}
	module := parseIR(result.Stdout)
	if module == nil || len(module.functions) == 0 {
		return nil, "unavailable", []diag.Diagnostic{
			diag.Newf(diag.EIRUnavailable, "no functions found in generated IR for %s", variant.File).Warning().WithTarget(variant.File),
		}
	}
	bySymbol := map[string]Function{}
	for _, fn := range functions {
		symbol := fn.MangledName
		if symbol == "" {
			symbol = fn.Name
		}
		bySymbol[symbol] = fn
		bySymbol[fn.Name] = fn
	}
	var facts []IRFunctionFact
	var diagnostics []diag.Diagnostic
	for symbol, irFn := range module.functions {
		fn, ok := bySymbol[symbol]
		if !ok {
			// Some emitted symbols are compiler-generated thunks or aliases.
			// Do not attach them to a similar name.
			continue
		}
		fact := summarizeIR(irFn, module, variant, hostTriple)
		fact.SchemaVersion = irFactsSchemaVersion
		fact.FunctionID = fn.ID
		fact.TargetTriple = firstNonEmpty(variant.TargetTriple, module.targetTriple)
		fact.HostTriple = hostTriple
		fact.IRMapping = "resolved"
		facts = append(facts, fact)
	}
	for _, fn := range functions {
		symbol := fn.MangledName
		if symbol == "" {
			symbol = fn.Name
		}
		if _, ok := module.functions[symbol]; !ok {
			diagnostics = append(diagnostics, diag.Newf(diag.WIRFallback,
				"AST function %s could not be joined to IR symbol %s", fn.QualifiedName, symbol,
			).Warning().WithTarget(fn.Name))
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].LinkSymbol < facts[j].LinkSymbol })
	return facts, "textual_llvm_ir", diagnostics
}

func irArguments(cfg *config.Config, command compdb.Command, compiler string) []string {
	args := []string{compiler}
	for i := 1; i < len(command.Arguments); i++ {
		arg := command.Arguments[i]
		if arg == "-o" || arg == "-MF" || arg == "-MT" || arg == "-MQ" || arg == "-MJ" {
			i++
			continue
		}
		if arg == "-c" || arg == "-S" || arg == "-E" || arg == "-fsyntax-only" ||
			arg == "-MD" || arg == "-MMD" || arg == "-MP" || arg == "-MG" {
			continue
		}
		if strings.HasPrefix(arg, "-O") || strings.HasPrefix(arg, "-g") || arg == "-flto" || strings.HasPrefix(arg, "-flto=") {
			continue
		}
		if isSourceArgument(arg, command.File, command.Directory) {
			continue
		}
		args = append(args, arg)
	}
	args = append(args,
		command.File,
		"-S", "-emit-llvm",
		"-g", cfg.File.Analysis.IROptLevel,
		"-fno-discard-value-names",
		"-fno-lto",
		"-Wno-error",
		"-Wno-unused-command-line-argument",
		"-o", "-",
	)
	args = append(args, cfg.File.Analysis.ExtraArgs...)
	return args
}

func parseIR(text string) *irModule {
	module := &irModule{
		functions: map[string]*irFunction{},
		defined:   map[string]bool{},
		declared:  map[string]bool{},
		globals:   map[string]bool{},
	}
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if match := targetPattern.FindStringSubmatch(line); match != nil {
			module.targetTriple = match[1]
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "@") && strings.Contains(trimmed, "=") {
			if symbol := firstSymbol(trimmed); symbol != "" {
				module.globals[symbol] = true
			}
		}
		if strings.HasPrefix(trimmed, "declare ") {
			if symbol := firstSymbol(trimmed); symbol != "" {
				module.declared[symbol] = true
			}
		}
	}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !strings.HasPrefix(strings.TrimSpace(line), "define ") {
			continue
		}
		fn, _ := parseDefine(line)
		if fn == nil {
			continue
		}
		fn.labels = map[string]int{}
		j := i + 1
		for ; j < len(lines); j++ {
			bodyLine := lines[j]
			trimmed := strings.TrimSpace(bodyLine)
			if trimmed == "}" {
				break
			}
			if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, ";") {
				label := strings.TrimSuffix(trimmed, ":")
				fn.labels[label] = j + 1
				continue
			}
			if inst, ok := parseInstruction(bodyLine); ok {
				inst.line = j + 1
				fn.instructions = append(fn.instructions, inst)
			}
		}
		module.functions[fn.symbol] = fn
		module.defined[fn.symbol] = true
		i = j
	}
	return module
}

func parseDefine(line string) (*irFunction, int) {
	match := symbolPattern.FindStringSubmatchIndex(line)
	if match == nil {
		return nil, 0
	}
	symbol := symbolFromMatch(line, match)
	open := strings.Index(line[match[1]:], "(")
	if open < 0 {
		return &irFunction{symbol: symbol}, 0
	}
	open += match[1]
	depth := 0
	close := -1
	for i := open; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				close = i
			}
		}
		if close >= 0 {
			break
		}
	}
	if close < 0 {
		return &irFunction{symbol: symbol}, 0
	}
	params := splitTopLevel(line[open+1 : close])
	fn := &irFunction{symbol: symbol}
	for index, param := range params {
		param = strings.TrimSpace(param)
		if param == "" || param == "..." {
			continue
		}
		if values := valuePattern.FindAllString(param, 1); len(values) == 1 {
			fn.argValues = append(fn.argValues, values[0])
		} else {
			fn.argValues = append(fn.argValues, fmt.Sprintf("%%arg%d", index))
		}
		fn.argTypes = append(fn.argTypes, param)
	}
	return fn, 0
}

func parseInstruction(line string) (irInstruction, bool) {
	text := line
	if idx := strings.Index(text, ";"); idx >= 0 {
		text = text[:idx]
	}
	text = strings.TrimSpace(text)
	if text == "" || strings.HasPrefix(text, "!") || strings.HasPrefix(text, "#") ||
		strings.HasSuffix(text, ":") || strings.HasPrefix(text, "}") {
		return irInstruction{}, false
	}
	inst := irInstruction{}
	if left, right, ok := strings.Cut(text, " = "); ok {
		inst.result = strings.TrimSpace(left)
		text = strings.TrimSpace(right)
	}
	for _, prefix := range []string{"tail ", "musttail ", "notail "} {
		text = strings.TrimPrefix(text, prefix)
	}
	inst.rhs = text
	if fields := strings.Fields(text); len(fields) > 0 {
		inst.kind = fields[0]
	}
	inst.ops = valuePattern.FindAllString(text, -1)
	return inst, true
}

func summarizeIR(fn *irFunction, module *irModule, variant Variant, hostTriple string) IRFunctionFact {
	fact := IRFunctionFact{
		SchemaVersion: irFactsSchemaVersion,
		LinkSymbol:    fn.symbol,
		TargetTriple:  variant.TargetTriple,
		HostTriple:    hostTriple,
	}
	if fact.TargetTriple == "" {
		fact.TargetTriple = module.targetTriple
	}
	argCount := len(fn.argValues)
	if argCount > 63 {
		argCount = 63
	}
	uses := make([]map[string]bool, argCount)
	argFacts := make([]IRArgument, argCount)
	for i := range uses {
		uses[i] = map[string]bool{}
		argFacts[i] = IRArgument{Index: i}
	}
	taint := map[string]uint64{}
	memTaint := map[string]uint64{}
	for i, name := range fn.argValues {
		if i < 63 {
			taint[name] = 1 << uint(i)
		}
	}
	globalEffects := map[string]bool{}
	flags := map[string]bool{}
	var unknowns []string
	for pass := 0; pass < 5; pass++ {
		changed := false
		for _, inst := range fn.instructions {
			switch inst.kind {
			case "alloca":
				if inst.result != "" {
					if _, ok := memTaint[inst.result]; !ok {
						memTaint[inst.result] = 0
						changed = true
					}
				}
			case "store":
				ptrName, valMask := parseStore(inst.rhs, taint, memTaint)
				if ptrName != "" {
					if _, ok := memTaint[ptrName]; ok {
						newValue := memTaint[ptrName] | valMask
						if newValue != memTaint[ptrName] {
							memTaint[ptrName] = newValue
							changed = true
						}
					}
					if ptrMask := taint[ptrName]; ptrMask != 0 {
						markUses(uses, ptrMask, "memory_write")
					}
				}
				if strings.Contains(inst.rhs, "volatile") {
					flags["MMIO_DIRECT"] = true
				}
				markGlobalEffects(inst.rhs, module.globals, globalEffects, "write")
			case "load":
				ptrName := lastValue(inst.rhs)
				mask := taint[ptrName] | memTaint[ptrName]
				if mask != 0 {
					markUses(uses, mask, "memory_read")
				}
				if inst.result != "" {
					if taint[inst.result] != mask {
						taint[inst.result] = mask
						changed = true
					}
				}
				if strings.Contains(inst.rhs, "volatile") {
					flags["MMIO_DIRECT"] = true
				}
				markGlobalEffects(inst.rhs, module.globals, globalEffects, "read")
			case "getelementptr":
				mask := operandMask(inst.ops, taint)
				if mask != 0 {
					markUses(uses, mask, "indexed")
				}
				if inst.result != "" && taint[inst.result] != mask {
					taint[inst.result] = mask
					changed = true
				}
			case "icmp", "fcmp":
				mask := operandMask(inst.ops, taint)
				if mask != 0 {
					markUses(uses, mask, "compare")
					if constant := compareConstant(inst.rhs); constant != "" {
						for i := range uses {
							if mask&(1<<uint(i)) != 0 {
								uses[i]["compare_constant:"+constant] = true
							}
						}
					}
				}
				if inst.result != "" && taint[inst.result] != mask {
					taint[inst.result] = mask
					changed = true
				}
			case "br", "switch", "indirectbr":
				mask := operandMask(inst.ops, taint)
				if mask != 0 {
					markUses(uses, mask, "branch")
				}
				if mask != 0 && hasBackwardTarget(inst, fn.labels) {
					markUses(uses, mask, "loop_bound")
				}
			case "phi", "select", "zext", "sext", "trunc", "bitcast", "ptrtoint", "addrspacecast", "freeze":
				mask := operandMask(inst.ops, taint)
				if inst.result != "" && taint[inst.result] != mask {
					taint[inst.result] = mask
					changed = true
				}
			case "inttoptr":
				flags["MMIO_DIRECT"] = true
				mask := operandMask(inst.ops, taint)
				if inst.result != "" && taint[inst.result] != mask {
					taint[inst.result] = mask
					changed = true
				}
			case "call", "invoke":
				symbol := callSymbol(inst.rhs)
				mask := operandMask(inst.ops, taint)
				if symbol == "" {
					fn.indirectCalls++
					flags["INDIRECT_UNKNOWN"] = true
				} else if !strings.HasPrefix(symbol, "llvm.") {
					if mask != 0 {
						markUses(uses, mask, "passed_to_call")
						if !isMemoryCallee(symbol) {
							argFactsMayEscape(uses, mask, argFacts)
						}
						if isAllocationCallee(symbol) {
							markUses(uses, mask, "allocation_size")
						}
					}
					if !module.defined[symbol] && !allowedExternalCalls[symbol] {
						unknowns = append(unknowns, "external_call:"+symbol)
					}
				}
				if inst.result != "" && taint[inst.result] != mask {
					taint[inst.result] = mask
					changed = true
				}
			case "ret":
				mask := operandMask(inst.ops, taint)
				if mask != 0 {
					markUses(uses, mask, "may_escape")
					argFactsMayEscape(uses, mask, argFacts)
				}
			case "atomicrmw", "cmpxchg", "fence":
				flags["RTOS_CONTEXT"] = true
			case "asm", "callbr":
				flags["ARCH_ASM"] = true
			}
		}
		if !changed {
			break
		}
	}
	for i := range argFacts {
		argFacts[i].ObservedUse = sortedKeys(uses[i])
		argFacts[i].MayEscape = uses[i]["may_escape"]
	}
	fact.Arguments = trimEmptyArguments(argFacts)
	for _, use := range uses {
		if use["memory_read"] {
			fact.LoadCount++
		}
		if use["memory_write"] {
			fact.StoreCount++
		}
		if use["branch"] {
			fact.BranchCount++
		}
	}
	fact.IndirectCalls = fn.indirectCalls
	for _, use := range uses {
		if use["branch"] || use["compare"] || use["indexed"] || use["memory_read"] || use["loop_bound"] {
			fact.DataDependent = true
		}
	}
	fact.GlobalEffects = sortedKeys(globalEffects)
	fact.HardwareFlags = sortedKeys(flags)
	fact.Unknowns = uniqueStrings(unknowns)
	sort.Strings(fact.Unknowns)
	if len(fact.HardwareFlags) > 0 {
		fact.Evidence = append(fact.Evidence, Evidence{
			Kind: "ir_hardware", Symbol: fn.symbol, Detail: strings.Join(fact.HardwareFlags, ","),
			Confidence: "observed",
		})
	}
	for _, arg := range fact.Arguments {
		if len(arg.ObservedUse) > 0 {
			fact.Evidence = append(fact.Evidence, Evidence{
				Kind: "ir_argument_use", Symbol: fn.symbol,
				Detail:     fmt.Sprintf("arg%d:%s", arg.Index, strings.Join(arg.ObservedUse, ",")),
				Confidence: "observed",
			})
		}
	}
	return fact
}

func parseStore(rhs string, taint, memTaint map[string]uint64) (string, uint64) {
	parts := splitTopLevel(strings.TrimPrefix(rhs, "store"))
	if len(parts) < 2 {
		return "", 0
	}
	valPart := parts[0]
	ptrPart := parts[1]
	ptrOps := valuePattern.FindAllString(ptrPart, -1)
	ptrName := ""
	if len(ptrOps) > 0 {
		ptrName = ptrOps[0]
	}
	var mask uint64
	for _, value := range valuePattern.FindAllString(valPart, -1) {
		mask |= taint[value] | memTaint[value]
	}
	return ptrName, mask
}

func lastValue(text string) string {
	values := valuePattern.FindAllString(text, -1)
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func operandMask(ops []string, taint map[string]uint64) uint64 {
	var mask uint64
	for _, op := range ops {
		mask |= taint[op]
	}
	return mask
}

func markUses(uses []map[string]bool, mask uint64, use string) {
	for i := range uses {
		if mask&(1<<uint(i)) != 0 {
			uses[i][use] = true
		}
	}
}

func argFactsMayEscape(uses []map[string]bool, mask uint64, facts []IRArgument) {
	for i := range uses {
		if mask&(1<<uint(i)) != 0 {
			facts[i].MayEscape = true
		}
	}
}

func callSymbol(rhs string) string {
	match := symbolPattern.FindStringSubmatch(rhs)
	if match == nil {
		return ""
	}
	return firstNonEmpty(match[1], match[2])
}

func markGlobalEffects(text string, globalDefs, effects map[string]bool, mode string) {
	for _, match := range symbolPattern.FindAllStringSubmatch(text, -1) {
		name := firstNonEmpty(match[1], match[2])
		if globalDefs[name] {
			effects[mode+":"+name] = true
		}
	}
}

func trimEmptyArguments(args []IRArgument) []IRArgument {
	out := args[:0]
	for _, arg := range args {
		if len(arg.ObservedUse) > 0 || arg.MayEscape {
			out = append(out, arg)
		}
	}
	return out
}

func firstSymbol(text string) string {
	match := symbolPattern.FindStringSubmatch(text)
	if match == nil {
		return ""
	}
	return strings.ReplaceAll(firstNonEmpty(match[1], match[2]), "\\01", "")
}

func symbolFromMatch(text string, match []int) string {
	var symbol string
	if match[2] >= 0 && match[3] >= 0 {
		symbol = text[match[2]:match[3]]
	} else if match[4] >= 0 && match[5] >= 0 {
		symbol = text[match[4]:match[5]]
	}
	return strings.ReplaceAll(symbol, "\\01", "")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func compareConstant(rhs string) string {
	fields := strings.Fields(rhs)
	for i := len(fields) - 1; i >= 0; i-- {
		value := strings.Trim(fields[i], ",")
		if value == "" {
			continue
		}
		if value[0] == '-' || (value[0] >= '0' && value[0] <= '9') {
			return value
		}
	}
	return ""
}

func hasBackwardTarget(inst irInstruction, labels map[string]int) bool {
	for _, field := range strings.Fields(inst.rhs) {
		field = strings.Trim(field, ",")
		if !strings.HasPrefix(field, "%") {
			continue
		}
		if target, ok := labels[field[1:]]; ok && target <= inst.line {
			return true
		}
	}
	return false
}

func isMemoryCallee(symbol string) bool {
	switch symbol {
	case "memcpy", "memmove", "memset", "memcmp", "strlen", "strnlen",
		"strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat",
		"__builtin_memcpy", "__builtin_memset", "__builtin_strlen":
		return true
	default:
		return false
	}
}

func isAllocationCallee(symbol string) bool {
	switch symbol {
	case "malloc", "calloc", "realloc", "aligned_alloc", "memalign":
		return true
	default:
		return false
	}
}
