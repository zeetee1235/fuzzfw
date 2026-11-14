// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package analyzer

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/proc"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
	"github.com/fuzzfw/fuzzfw/internal/version"
)

// Analyze runs the deterministic Clang AST front end over every translation
// unit in the compilation database. It returns a partial analysis with explicit
// diagnostics rather than silently dropping failed units.
func Analyze(ctx context.Context, cfg *config.Config, db *compdb.Database, tools *toolchain.Report, revision string) (*Analysis, error) {
	analysis := &Analysis{
		SchemaVersion: AnalysisSchemaVersion,
		AnalysisMode:  ModeASTJSON,
		Generator:     "clang-ast-json/" + version.Version,
		Project: Project{
			Name:              cfg.File.Project.Name,
			Root:              cfg.Root,
			SourceRevision:    revision,
			ConfigFingerprint: cfg.Fingerprint,
		},
	}
	bag := &diag.Bag{}
	bag.Extend(db.Diagnostics)
	hostTriple := ""
	if tools != nil {
		hostTriple = tools.ClangTarget
	}

	commands := append([]compdb.Command(nil), db.Commands...)
	sort.Slice(commands, func(i, j int) bool {
		if commands[i].File != commands[j].File {
			return commands[i].File < commands[j].File
		}
		return commands[i].VariantID < commands[j].VariantID
	})

	totalFunctions := 0
	for _, command := range commands {
		if totalFunctions >= cfg.File.Analysis.MaxFunctions {
			bag.Add(diag.Newf(diag.EAnalysisBudget,
				"analysis function budget (%d) exhausted; remaining translation units were not analyzed",
				cfg.File.Analysis.MaxFunctions,
			))
			break
		}
		functions, declarations, irFacts, variant, diagnostics, irStatus := analyzeCommand(ctx, cfg, command, hostTriple, tools)
		variant.IRStatus = irStatus
		analysis.Variants = append(analysis.Variants, variant)
		analysis.Functions = append(analysis.Functions, functions...)
		analysis.ExternalDeclarations = append(analysis.ExternalDeclarations, declarations...)
		analysis.IRFacts = append(analysis.IRFacts, irFacts...)
		bag.Extend(diagnostics)
		totalFunctions += len(functions)
	}

	mapHeaders(analysis)
	resolveCalls(analysis)
	analysis.Diagnostics = bag.Items()
	analysis.Sort()

	nativeVariants := 0
	for _, variant := range analysis.Variants {
		if variant.AnalysisStatus == "native" {
			nativeVariants++
		}
	}
	if nativeVariants == len(analysis.Variants) && nativeVariants > 0 {
		analysis.AnalysisMode = ModeNativeAST
		analysis.Generator = "fuzzfw-analyze/0.1"
	} else if nativeVariants > 0 {
		analysis.AnalysisMode = ModeMixed
		analysis.Generator = "fuzzfw-analyze/0.1 + clang-ast-json"
	}
	// If IR was unavailable for every TU, be explicit about the reduced mode.
	if len(analysis.IRFacts) == 0 && nativeVariants == 0 {
		analysis.AnalysisMode = ModeASTOnly
	}
	return analysis, nil
}

func analyzeCommand(
	ctx context.Context,
	cfg *config.Config,
	command compdb.Command,
	hostTriple string,
	tools *toolchain.Report,
) ([]Function, []Declaration, []IRFunctionFact, Variant, []diag.Diagnostic, string) {
	variant := Variant{
		ID:             command.VariantID,
		File:           fsutil.Rel(cfg.Root, command.File),
		Language:       command.Language,
		Compiler:       command.Compiler,
		TargetTriple:   command.TargetTriple,
		HostTriple:     hostTriple,
		Arguments:      append([]string(nil), command.Arguments...),
		IncludeDirs:    append([]string(nil), command.IncludeDirs...),
		Defines:        append([]string(nil), command.Defines...),
		Standard:       command.Standard,
		AnalysisStatus: "ok",
		IRStatus:       "not_requested",
	}
	var diagnostics []diag.Diagnostic
	var functions []Function
	var declarations []Declaration

	if nativeFunctions, nativeDeclarations, nativeDiagnostics, ok := analyzeCommandNative(ctx, cfg, command, tools); ok {
		variant.AnalysisStatus = "native"
		variant.CompilerUsed = "fuzzfw-analyze"
		functions = nativeFunctions
		declarations = nativeDeclarations
		diagnostics = append(diagnostics, nativeDiagnostics...)
		irFacts, irStatus, irDiagnostics := analyzeIR(ctx, cfg, command, functions, variant, hostTriple, tools)
		diagnostics = append(diagnostics, irDiagnostics...)
		return functions, declarations, irFacts, variant, diagnostics, irStatus
	} else {
		diagnostics = append(diagnostics, nativeDiagnostics...)
	}

	compiler, substituted, err := astCompiler(cfg, command)
	if err != nil {
		diagnostics = append(diagnostics, diag.Newf(diag.EASTParse,
			"cannot resolve a Clang compiler for %s: %v", variant.File, err,
		).WithTarget(variant.File).WithRemediation(
			"Set host.clang and host.clangxx to Clang binaries that can parse the original flags.",
		))
		variant.AnalysisStatus = "failed"
		return nil, nil, nil, variant, diagnostics, "unavailable"
	}
	variant.CompilerUsed = compiler
	if substituted {
		diagnostics = append(diagnostics, diag.Newf(diag.EASTParse,
			"original compiler %q was replaced by %q for AST analysis; original flags were preserved",
			command.Compiler, compiler,
		).WithTarget(variant.File).Warning())
	}

	args := astArguments(cfg, command, compiler)
	timeout := time.Duration(cfg.File.Analysis.TimeoutSeconds) * time.Second
	result, runErr := (proc.Runner{Timeout: timeout}).Run(ctx, command.Directory, args...)
	if runErr != nil {
		diagnostics = append(diagnostics, diag.Wrap(diag.EASTParse,
			fmt.Sprintf("failed to start Clang AST analysis for %s", variant.File), runErr,
		).Diagnostic().WithTarget(variant.File))
		variant.AnalysisStatus = "failed"
		return nil, nil, nil, variant, diagnostics, "unavailable"
	}
	if result.TimedOut {
		diagnostics = append(diagnostics, diag.Newf(diag.EASTParse,
			"Clang AST analysis timed out after %s for %s", timeout, variant.File,
		).WithTarget(variant.File))
		variant.AnalysisStatus = "failed"
		return nil, nil, nil, variant, diagnostics, "unavailable"
	}
	if result.ExitCode != 0 {
		diagnostics = append(diagnostics, diag.Newf(diag.EASTParse,
			"Clang AST analysis failed for %s (exit %d): %s",
			variant.File, result.ExitCode, firstLines(result.Stderr, 6),
		).WithTarget(variant.File).WithEvidence(result.Stderr))
		variant.AnalysisStatus = "failed"
		return nil, nil, nil, variant, diagnostics, "unavailable"
	}
	doc, err := decodeAST([]byte(result.Stdout))
	if err != nil {
		diagnostics = append(diagnostics, diag.Newf(diag.EASTParse,
			"cannot decode Clang AST JSON for %s: %v", variant.File, err,
		).WithTarget(variant.File))
		variant.AnalysisStatus = "failed"
		return nil, nil, nil, variant, diagnostics, "unavailable"
	}

	index := newASTIndex(cfg.Root, command.Directory)
	index.build(doc, variant.File)
	functions, declarations = index.collect(doc, variant, cfg)
	irFacts, irStatus, irDiagnostics := analyzeIR(ctx, cfg, command, functions, variant, hostTriple, tools)
	diagnostics = append(diagnostics, irDiagnostics...)
	return functions, declarations, irFacts, variant, diagnostics, irStatus
}

func astCompiler(cfg *config.Config, command compdb.Command) (string, bool, error) {
	original := filepath.Base(command.Compiler)
	if strings.Contains(original, "clang") {
		if resolved, err := proc.LookPath(command.Compiler); err == nil {
			return resolved, false, nil
		}
	}
	wanted := cfg.File.Host.Clang
	if command.Language == "c++" || command.Language == "objective-c++" {
		wanted = cfg.File.Host.ClangXX
	}
	resolved, err := proc.LookPath(wanted)
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", wanted, err)
	}
	return resolved, true, nil
}

func astArguments(cfg *config.Config, command compdb.Command, compiler string) []string {
	args := []string{compiler}
	raw := command.Arguments
	for i := 1; i < len(raw); i++ {
		arg := raw[i]
		if arg == "-o" || arg == "-MF" || arg == "-MT" || arg == "-MQ" || arg == "-MJ" {
			i++
			continue
		}
		if arg == "-c" || arg == "-S" || arg == "-E" || arg == "-fsyntax-only" ||
			arg == "-MD" || arg == "-MMD" || arg == "-MP" || arg == "-MG" {
			continue
		}
		if isSourceArgument(arg, command.File, command.Directory) {
			continue
		}
		args = append(args, arg)
	}
	args = append(args,
		command.File,
		"-Xclang", "-ast-dump=json",
		"-fsyntax-only",
		"-fno-color-diagnostics",
		"-Wno-error",
		"-Wno-unused-command-line-argument",
	)
	args = append(args, cfg.File.Analysis.ExtraArgs...)
	return args
}

func isSourceArgument(arg, sourceFile, directory string) bool {
	if arg == sourceFile || arg == filepath.Base(sourceFile) {
		return true
	}
	if strings.HasPrefix(arg, "-") {
		return false
	}
	if !filepath.IsAbs(arg) {
		arg = filepath.Join(directory, arg)
	}
	return filepath.Clean(arg) == sourceFile
}

func firstLines(text string, limit int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > limit {
		lines = lines[:limit]
	}
	return strings.Join(lines, " | ")
}

// mapHeaders joins definitions to a unique source header declaration.
func mapHeaders(analysis *Analysis) {
	byKey := map[string][]Declaration{}
	for _, declaration := range analysis.ExternalDeclarations {
		key := declaration.Name + "\x00" + declaration.Signature
		byKey[key] = append(byKey[key], declaration)
	}
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if fn.Header != "" {
			continue
		}
		if isHeaderFile(fn.Source) {
			fn.Header = fn.Source
			continue
		}
		candidates := byKey[fn.Name+"\x00"+fn.Signature]
		sources := map[string]bool{}
		for _, candidate := range candidates {
			if isHeaderFile(candidate.Source) {
				sources[candidate.Source] = true
			}
		}
		if len(sources) == 1 {
			for source := range sources {
				fn.Header = source
			}
		}
	}
}

var allowedExternalCalls = map[string]bool{
	"memcpy": true, "memmove": true, "memset": true, "memcmp": true,
	"strlen": true, "strnlen": true, "strcmp": true, "strncmp": true,
	"strcpy": true, "strncpy": true, "strcat": true, "strncat": true,
	"strchr": true, "strrchr": true, "strstr": true, "strdup": true,
	"malloc": true, "calloc": true, "realloc": true, "free": true,
	"abort": true, "exit": true, "assert": true, "__assert_fail": true,
	"printf": true, "fprintf": true, "sprintf": true, "snprintf": true,
	"vprintf": true, "vfprintf": true, "vsnprintf": true, "puts": true,
	"putchar": true, "qsort": true, "bsearch": true, "abs": true,
	"labs": true, "llabs": true, "isdigit": true, "isalpha": true,
	"isalnum": true, "isspace": true, "tolower": true, "toupper": true,
	"sqrt": true, "pow": true, "sin": true, "cos": true, "fabs": true,
	"__builtin_memcpy": true, "__builtin_memset": true, "__builtin_strlen": true,
}

// AllowedExternalCall reports whether a symbol is a standard C runtime call
// that the host build may resolve without a project definition or adapter.
func AllowedExternalCall(name string) bool {
	return allowedExternalCalls[name] || strings.HasPrefix(name, "__builtin_") || strings.HasPrefix(name, "__cxa_")
}

// resolveCalls computes unresolved external calls conservatively, respecting
// internal linkage per translation unit.
func resolveCalls(analysis *Analysis) {
	type definition struct {
		function Function
	}
	bySymbolEverywhere := map[string][]definition{}
	byTU := map[string]map[string]bool{}
	for _, fn := range analysis.Functions {
		if !fn.Definition {
			continue
		}
		symbol := fn.MangledName
		if symbol == "" {
			symbol = fn.Name
		}
		bySymbolEverywhere[symbol] = append(bySymbolEverywhere[symbol], definition{fn})
		if byTU[fn.TranslationUnit] == nil {
			byTU[fn.TranslationUnit] = map[string]bool{}
		}
		byTU[fn.TranslationUnit][symbol] = true
	}
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		var unresolved []string
		for _, call := range fn.DirectCallees {
			symbol := call.Symbol
			if symbol == "" {
				symbol = call.Name
			}
			if allowedExternalCalls[symbol] || allowedExternalCalls[call.Name] ||
				strings.HasPrefix(call.Name, "__builtin_") || strings.HasPrefix(call.Name, "__cxa_") {
				continue
			}
			if byTU[fn.TranslationUnit][symbol] {
				continue
			}
			resolved := false
			for _, candidate := range bySymbolEverywhere[symbol] {
				if !candidate.function.InternalLinkage {
					resolved = true
					break
				}
			}
			if !resolved {
				unresolved = append(unresolved, symbol)
			}
		}
		fn.UnresolvedCalls = uniqueStrings(append(fn.UnresolvedCalls, unresolved...))
	}
}
