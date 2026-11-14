// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

func runBuild(ctx context.Context, global globalOptions, args []string) (int, error) {
	flags := newFlagSet("build")
	var selected stringList
	flags.Var(&selected, "target", "target name or symbol (repeatable)")
	engineFlag := flags.String("engine", "", "engine adapter: honggfuzz, libfuzzer, replay")
	refresh := flags.Bool("refresh", false, "re-run analysis and planning")
	jsonOutput := flags.Bool("json", false, "print build state JSON")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	cfg, err := loadConfigOrError(global, ".", false)
	if err != nil {
		return exitcode.Usage, err
	}
	tools := toolchain.Detect(ctx, cfg)
	ws := artifacts.NewWorkspace(cfg)
	analysis, analysisHash, manifestHash, _, err := prepareAnalysis(ctx, cfg, tools, *refresh)
	if err != nil {
		return exitcode.Incomplete, err
	}
	var plan *planner.Plan
	if !*refresh && fsutil.Exists(ws.Plan) {
		plan, err = loadPlan(ws)
		if err != nil {
			return exitcode.Incomplete, err
		}
	} else {
		plan, err = planner.Build(cfg, analysis, analysisHash, selected)
		if err != nil {
			return exitcode.Incomplete, err
		}
		if err := writePlan(ws, plan); err != nil {
			return exitcode.Incomplete, err
		}
	}
	names, err := targetNames(plan, selected)
	if err != nil {
		return exitcode.Usage, err
	}
	names = nonBlockedNames(plan, names)
	if len(names) == 0 {
		return exitcode.Usage, diag.NewError(diag.EConfigInvalid, "no buildable targets selected; all targets are blocked")
	}
	engineName := cfg.File.CI.Engine
	if *engineFlag != "" {
		engineName = *engineFlag
	}
	if ok, message := tools.EngineAvailable(engineName); !ok {
		fmt.Fprintf(stderr(), "warning [%s]: %s\n", diag.EEngineUnavailable, message)
	}
	db, err := loadDatabase(ctx, cfg)
	if err != nil {
		return exitcode.Incomplete, err
	}
	results, diagnostics, err := buildTargets(ctx, cfg, ws, db, tools, plan, names, engineName)
	if err != nil {
		return exitcode.Incomplete, err
	}
	for _, diagnostic := range diagnostics {
		printDiagnostic(diagnostic)
	}
	state, err := saveBuildResults(cfg, ws, plan, analysisHash, manifestHash, tools.Hash(), results)
	if err != nil {
		return exitcode.Incomplete, err
	}
	if *jsonOutput {
		if err := writeJSONTo("", state); err != nil {
			return exitcode.Incomplete, err
		}
		return exitCodeFromBuilds(results, engineName), nil
	}
	fmt.Printf("%-24s %-18s %-10s %-10s %s\n", "TARGET", "STATUS", "ENTRY", "INPUT", "BINARY")
	for _, result := range results {
		binary := result.Result.SelftestBinary
		if result.Result.FuzzBinary != "" {
			binary = result.Result.FuzzBinary
		}
		fmt.Printf("%-24s %-18s %-10t %-10s %s\n", result.Name, result.Result.Status,
			result.Result.Selftest.EntryHit, result.Result.Selftest.InputUse, binary)
	}
	return exitCodeFromBuilds(results, engineName), nil
}

func nonBlockedNames(plan *planner.Plan, names []string) []string {
	var out []string
	for _, name := range names {
		if target, ok := plan.Target(name); ok && target.Classification != planner.Blocked {
			out = append(out, name)
		}
	}
	return out
}

func exitCodeFromBuilds(results []targetBuild, engineName string) int {
	code := exitcode.OK
	for _, result := range results {
		switch result.Result.Status {
		case "fuzzable":
			continue
		case "selftest_passed":
			if engineName == "replay" {
				continue
			}
			code = exitcode.Incomplete
		default:
			code = exitcode.Incomplete
		}
	}
	return code
}

func stderr() *os.File { return os.Stderr }
