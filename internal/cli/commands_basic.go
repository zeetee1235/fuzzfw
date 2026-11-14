// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

func runDoctor(ctx context.Context, global globalOptions, args []string) (int, error) {
	flags := newFlagSet("doctor")
	jsonOutput := flags.Bool("json", false, "print machine-readable JSON")
	strict := flags.Bool("strict", false, "fail when required tools are missing")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	cfg, err := loadConfigOrError(global, ".", false)
	if err != nil {
		return exitcode.Usage, err
	}
	report := toolchain.Detect(ctx, cfg)
	if *jsonOutput {
		if err := writeJSONTo("", report); err != nil {
			return exitcode.Incomplete, err
		}
	} else {
		fmt.Printf("fuzzfw doctor\n")
		fmt.Printf("platform: %s\n", report.Platform)
		fmt.Printf("clang target: %s\n", report.ClangTarget)
		fmt.Printf("sanitizers: %t\n", report.SanitizersOK)
		fmt.Printf("libFuzzer: %t\n\n", report.LibFuzzerOK)
		names := make([]string, 0, len(report.Tools))
		for name := range report.Tools {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Printf("%-20s %-8s %s\n", "TOOL", "FOUND", "VERSION/PATH")
		for _, name := range names {
			tool := report.Tools[name]
			value := tool.Version
			if value == "" {
				value = tool.Path
			}
			if value == "" {
				value = tool.Detail
			}
			fmt.Printf("%-20s %-8t %s\n", name, tool.Found, value)
		}
		fmt.Println()
		for _, check := range report.Checks {
			state := "ok"
			if !check.OK {
				state = "missing/optional"
			}
			fmt.Printf("[%s] %s: %s\n", state, check.Name, check.Message)
		}
	}
	if !*strict {
		return exitcode.OK, nil
	}
	if !report.Tools["clang"].Found {
		return exitcode.Incomplete, diag.NewError(diag.EUsage, "clang is required")
	}
	if !report.SanitizersOK {
		return exitcode.Incomplete, diag.NewError(diag.EUsage, "ASan/UBSan support is required")
	}
	if cfg.File.CI.Engine != "replay" {
		if ok, message := report.EngineAvailable(cfg.File.CI.Engine); !ok {
			return exitcode.Incomplete, diag.NewError(diag.EEngineUnavailable, message)
		}
	}
	return exitcode.OK, nil
}

func runScan(ctx context.Context, global globalOptions, args []string) (int, error) {
	flags := newFlagSet("scan")
	compdbPath := flags.String("compdb", "", "path to compile_commands.json")
	artifactDir := flags.String("artifact-dir", "", "artifact directory (default .fuzzfw)")
	jsonOutput := flags.Bool("json", false, "print analysis JSON")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	start := "."
	if flags.NArg() > 1 {
		return exitcode.Usage, fmt.Errorf("scan accepts at most one project path")
	}
	if flags.NArg() == 1 {
		start = flags.Arg(0)
	}
	cfg, err := loadConfigOrError(global, start, false)
	if err != nil {
		return exitcode.Usage, err
	}
	if *compdbPath != "" {
		cfg.CompDB = fsutil.Resolve(cfg.Root, *compdbPath)
	}
	if *artifactDir != "" {
		cfg.ArtifactDir = fsutil.Resolve(cfg.Root, *artifactDir)
	}
	tools := toolchain.Detect(ctx, cfg)
	if !tools.Tools["clang"].Found {
		return exitcode.Incomplete, diag.NewError(diag.EASTParse, "clang was not found; install Clang or set host.clang")
	}
	db, err := loadDatabase(ctx, cfg)
	if err != nil {
		return exitcode.Usage, err
	}
	analysis, buildManifest, duration, err := analyzeProject(ctx, cfg, db, tools)
	if err != nil {
		return exitcode.Incomplete, err
	}
	ws := artifacts.NewWorkspace(cfg)
	analysisHash, manifestHash, err := writeAnalysisArtifacts(ws, analysis, buildManifest)
	if err != nil {
		return exitcode.Incomplete, err
	}
	for _, diagnostic := range analysis.Diagnostics {
		printDiagnostic(diagnostic)
	}
	if len(analysis.Functions) == 0 {
		fmt.Fprintf(os.Stderr, "error: no analyzable functions found (analysis mode %s)\n", analysis.AnalysisMode)
		return exitcode.Incomplete, nil
	}
	if *jsonOutput {
		if err := writeJSONTo("", analysis); err != nil {
			return exitcode.Incomplete, err
		}
		return exitcode.OK, nil
	}
	fmt.Printf("analyzed %d translation unit variant(s), %d function definition(s) in %.2fs\n",
		len(analysis.Variants), len(analysis.Functions), duration.Seconds())
	fmt.Printf("analysis: %s (mode %s)\n", ws.Analysis, analysis.AnalysisMode)
	fmt.Printf("manifest: %s\n", ws.BuildManifest)
	fmt.Printf("analysis sha256: %s\nmanifest sha256: %s\n\n", analysisHash, manifestHash)
	fmt.Printf("%-28s %-9s %-7s %s\n", "FUNCTION", "LANG", "LINE", "SOURCE")
	for _, fn := range analysis.Functions {
		fmt.Printf("%-28s %-9s %-7d %s\n", fn.QualifiedName, fn.Language, fn.Line, fn.Source)
	}
	return exitcode.OK, nil
}

func printDiagnostic(d diag.Diagnostic) {
	target := ""
	if d.Target != "" {
		target = " [" + d.Target + "]"
	}
	fmt.Fprintf(os.Stderr, "%s [%s]%s %s\n", strings.ToUpper(string(d.Severity)), d.Code, target, d.Message)
}

func runPlan(ctx context.Context, global globalOptions, args []string) (int, error) {
	flags := newFlagSet("plan")
	var selected stringList
	flags.Var(&selected, "target", "target name or symbol (repeatable)")
	refresh := flags.Bool("refresh", false, "re-run analysis before planning")
	jsonOutput := flags.Bool("json", false, "print plan JSON")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	cfg, err := loadConfigOrError(global, ".", false)
	if err != nil {
		return exitcode.Usage, err
	}
	tools := toolchain.Detect(ctx, cfg)
	ws := artifacts.NewWorkspace(cfg)
	analysis, analysisHash, _, _, err := prepareAnalysis(ctx, cfg, tools, *refresh)
	if err != nil {
		return exitcode.Incomplete, err
	}
	plan, err := planner.Build(cfg, analysis, analysisHash, selected)
	if err != nil {
		return exitcode.Incomplete, err
	}
	if err := writePlan(ws, plan); err != nil {
		return exitcode.Incomplete, err
	}
	for _, diagnostic := range plan.Diagnostics {
		printDiagnostic(diagnostic)
	}
	if len(plan.Targets) == 0 {
		return exitcode.Usage, diag.NewError(diag.EConfigInvalid, "no targets selected")
	}
	if *jsonOutput {
		if err := writeJSONTo("", plan); err != nil {
			return exitcode.Incomplete, err
		}
		return exitcode.OK, nil
	}
	fmt.Printf("plan %s: %d target(s)\n\n", plan.PlanID, len(plan.Targets))
	fmt.Printf("%-24s %-16s %-10s %s\n", "TARGET", "CLASSIFICATION", "REQUIRED", "REASON")
	for _, target := range plan.Targets {
		reason := ""
		if len(target.Reasons) > 0 {
			reason = target.Reasons[0]
		}
		fmt.Printf("%-24s %-16s %-10t %s\n", target.Name, target.Classification, target.Required, reason)
		for _, diagnostic := range target.Diagnostics {
			printDiagnostic(diagnostic)
		}
	}
	return exitcode.OK, nil
}

func runInspect(ctx context.Context, global globalOptions, args []string) (int, error) {
	flags := newFlagSet("inspect")
	targetName := flags.String("target", "", "target name or symbol")
	jsonOutput := flags.Bool("json", false, "print machine-readable evidence")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	if *targetName == "" {
		return exitcode.Usage, fmt.Errorf("inspect requires --target")
	}
	cfg, err := loadConfigOrError(global, ".", false)
	if err != nil {
		return exitcode.Usage, err
	}
	ws := artifacts.NewWorkspace(cfg)
	plan, err := loadPlan(ws)
	if err != nil {
		return exitcode.Incomplete, err
	}
	target, ok := plan.Target(*targetName)
	if !ok {
		return exitcode.Usage, fmt.Errorf("target %q not found in plan", *targetName)
	}
	analysis, _ := loadAnalysis(cfg, ws)
	var function *analyzer.Function
	if analysis != nil {
		for i := range analysis.Functions {
			if analysis.Functions[i].ID == target.FunctionID {
				function = &analysis.Functions[i]
				break
			}
		}
	}
	payload := map[string]any{"target": target, "function": function, "plan_id": plan.PlanID}
	if *jsonOutput {
		if err := writeJSONTo("", payload); err != nil {
			return exitcode.Incomplete, err
		}
		return exitcode.OK, nil
	}
	fmt.Printf("target: %s (%s)\n", target.Name, target.Symbol)
	fmt.Printf("classification: %s\n", target.Classification)
	fmt.Printf("function: %s\n", target.Signature)
	fmt.Printf("source: %s\n", target.Source)
	fmt.Printf("header: %s\n", target.Header)
	fmt.Printf("input model: %+v\n", target.InputModel)
	fmt.Printf("required translation units: %s\n", strings.Join(target.Dependencies, ", "))
	fmt.Printf("constraints:\n")
	for _, constraint := range target.Constraints {
		fmt.Printf("  - %s (%s)\n", constraint.Expr, constraint.Basis)
	}
	fmt.Printf("roles:\n")
	for _, role := range target.Roles {
		fmt.Printf("  - arg %d: %s <- %s [%s]\n", role.Argument, role.Role, role.Source, strings.Join(role.Evidence, ", "))
	}
	fmt.Printf("reasons:\n")
	for _, reason := range target.Reasons {
		fmt.Printf("  - %s\n", reason)
	}
	fmt.Printf("diagnostics:\n")
	for _, diagnostic := range target.Diagnostics {
		printDiagnostic(diagnostic)
	}
	return exitcode.OK, nil
}
