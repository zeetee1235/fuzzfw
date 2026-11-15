// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/engine"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/report"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
	"github.com/fuzzfw/fuzzfw/internal/triage"
)

func runFuzz(ctx context.Context, global globalOptions, args []string) (int, error) {
	flags := newFlagSet("fuzz")
	timeFlag := flags.String("time", "", "total fuzzing budget (30s, 10m, 1h)")
	jobsFlag := flags.Int("jobs", 0, "engine workers")
	engineFlag := flags.String("engine", "", "engine: honggfuzz, libfuzzer, replay")
	outputFlag := flags.String("output", "", "output directory")
	baselineFlag := flags.String("baseline", "", "finding baseline JSON")
	noMinimize := flags.Bool("no-minimize", false, "disable input minimization")
	jsonOutput := flags.Bool("json", false, "print summary JSON")
	var selected stringList
	flags.Var(&selected, "target", "target name (repeatable)")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	started := time.Now()
	cfg, err := loadConfigOrError(global, ".", false)
	if err != nil {
		return exitcode.Usage, err
	}
	if *noMinimize {
		cfg.File.Harness.Minimize = false
	}
	tools := toolchain.Detect(ctx, cfg)
	ws := artifacts.NewWorkspace(cfg)
	plan, err := loadPlan(ws)
	if err != nil {
		return exitcode.Incomplete, err
	}
	state, err := loadBuildState(ws)
	if err != nil {
		return exitcode.Incomplete, err
	}
	engineName := cfg.File.CI.Engine
	if *engineFlag != "" {
		engineName = *engineFlag
	}
	fuzzEngine, err := engine.New(engineName, cfg, tools)
	if err != nil {
		return exitcode.Usage, err
	}
	if ok, message := fuzzEngine.Available(); !ok {
		return exitcode.Incomplete, diag.NewError(diag.EEngineUnavailable, message)
	}
	names, err := targetNames(plan, selected)
	if err != nil {
		return exitcode.Usage, err
	}
	var builtNames []string
	for _, name := range names {
		if built, ok := state.target(name); ok && built.Result.SelftestBinary != "" {
			builtNames = append(builtNames, name)
		}
	}
	if len(builtNames) == 0 {
		return exitcode.Usage, diag.NewError(diag.EArtifactInvalid,
			"no built targets selected; run fuzzfw build first")
	}
	outputDir := "fuzzfw-out"
	if cfg.File.CI.OutputDir != "" {
		outputDir = cfg.File.CI.OutputDir
	}
	if *outputFlag != "" {
		outputDir = fsutil.Resolve(cfg.Root, *outputFlag)
	}
	baselinePath := cfg.File.CI.Baseline
	if *baselineFlag != "" {
		baselinePath = fsutil.Resolve(cfg.Root, *baselineFlag)
	}
	baseline, err := triage.LoadBaseline(baselinePath)
	if err != nil {
		return exitcode.Incomplete, err
	}
	out := artifacts.NewOutput(outputDir, baselinePath)
	if err := out.Ensure(); err != nil {
		return exitcode.Incomplete, err
	}
	budget, err := parseDurations(*timeFlag, cfg.File.CI.TimeSeconds)
	if err != nil {
		return exitcode.Usage, err
	}
	jobs := cfg.File.CI.Jobs
	if *jobsFlag > 0 {
		jobs = *jobsFlag
	}
	perTarget := budget / time.Duration(len(builtNames))
	if cfg.File.CI.PerTargetSeconds > 0 {
		perTarget = time.Duration(cfg.File.CI.PerTargetSeconds) * time.Second
	}
	if perTarget < time.Second {
		perTarget = time.Second
	}
	var allFindings []triage.Finding
	var allDiagnostics []diag.Diagnostic
	var summaries []report.TargetSummary
	casesReplayed := 0
	casesFuzzed := 0
	selftestSeconds := 0.0
	fuzzStarted := time.Now()
	triageStarted := time.Now()
	runs := make([]fuzzTargetRun, len(builtNames))
	if err := parallelIndexes(len(builtNames), cfg.File.CI.TargetJobs, func(index int) error {
		runs[index] = runFuzzTarget(ctx, cfg, plan, state, out, fuzzEngine, engineName, builtNames[index], perTarget, jobs)
		return runs[index].err
	}); err != nil {
		return exitcode.Incomplete, err
	}
	for _, run := range runs {
		allFindings = append(allFindings, run.findings...)
		allDiagnostics = append(allDiagnostics, run.diagnostics...)
		summaries = append(summaries, run.summary)
		casesReplayed += run.casesReplayed
		casesFuzzed += run.casesFuzzed
		selftestSeconds += run.selftestSeconds
	}
	fuzzSeconds := time.Since(fuzzStarted).Seconds()
	triageSeconds := time.Since(triageStarted).Seconds()
	project := report.ProjectInfo{Name: plan.Project.Name, Root: plan.Project.Root, SourceRevision: plan.Project.SourceRevision}
	summary := report.New(report.Input{
		Command: "fuzz", Config: cfg, Project: project, StartedAt: started, FinishedAt: time.Now(),
		SelftestSeconds: selftestSeconds, FuzzSeconds: fuzzSeconds, TriageSeconds: triageSeconds,
		Targets: summaries, Findings: allFindings, Baseline: baseline,
		Diagnostics: allDiagnostics, CasesReplayed: casesReplayed, CasesFuzzed: casesFuzzed,
		Artifacts: report.ArtifactPaths{
			Summary: out.Summary, JUnit: out.JUnit, BuildInfo: out.BuildInfo,
			Diagnostics: out.Diagnostics, Corpus: out.CorpusDir, Findings: out.FindingsDir,
		},
	})
	info := newBuildInfoDocument(state, tools, plan)
	if err := fsutil.WriteJSON(out.BuildInfo, info, true); err != nil {
		return exitcode.Incomplete, err
	}
	if err := report.Write(summary, out); err != nil {
		return exitcode.Incomplete, err
	}
	if *jsonOutput {
		if err := writeJSONTo("", summary); err != nil {
			return exitcode.Incomplete, err
		}
	} else {
		fmt.Printf("fuzz completed: status=%s exit=%d findings=%d\n", summary.Status, summary.ExitCode, len(summary.Findings))
		for _, target := range summary.Targets {
			fmt.Printf("  %-24s %-18s entry=%t input=%s findings=%d\n",
				target.Name, target.Status, target.EntryHit, target.InputUse, len(target.FindingIDs))
		}
	}
	return summary.ExitCode, nil
}

type fuzzTargetRun struct {
	summary         report.TargetSummary
	findings        []triage.Finding
	diagnostics     []diag.Diagnostic
	casesReplayed   int
	casesFuzzed     int
	selftestSeconds float64
	err             error
}

func runFuzzTarget(
	ctx context.Context,
	cfg *config.Config,
	plan *planner.Plan,
	state *buildState,
	out *artifacts.Output,
	fuzzEngine engine.Engine,
	engineName, name string,
	perTarget time.Duration,
	jobs int,
) fuzzTargetRun {
	run := fuzzTargetRun{}
	target, ok := plan.Target(name)
	if !ok {
		run.err = fmt.Errorf("target %q not found in plan", name)
		return run
	}
	built, _ := state.target(name)
	run.selftestSeconds = built.Result.Selftest.DurationSeconds
	corpusDir, _, err := prepareCorpus(cfg, out, target)
	if err != nil {
		run.err = err
		return run
	}
	raw, quality, replayDiags := replayCorpus(ctx, cfg, out, target, &built.Result)
	run.casesReplayed = quality.Inputs
	run.diagnostics = append(run.diagnostics, replayDiags...)
	for _, selftestCase := range built.Result.Selftest.Cases {
		if selftestCase.Crash && (selftestCase.Origin == "target_crash" || selftestCase.Origin == "target_invariant") && selftestCase.InputPath != "" {
			raw = append(raw, engine.RawFinding{
				Path: absJoinPath(cfg.Root, selftestCase.InputPath), Kind: selftestCase.Sanitizer,
				Target: target.Name, Engine: "selftest",
			})
		}
	}
	if engineName != "replay" {
		if built.Result.FuzzBinary == "" {
			run.diagnostics = append(run.diagnostics, diag.Newf(diag.EEngineUnavailable,
				"target %s has no fuzz binary for engine %s", name, engineName).WithTarget(name))
		} else {
			runResult, err := fuzzEngine.Run(ctx, name, &built.Result, corpusDir, out.TargetEngine(name), perTarget, jobs, target.MaxInputBytes, built.Result.DictionaryPath)
			if err != nil {
				run.diagnostics = append(run.diagnostics, diag.Newf(diag.EEngineFailed,
					"engine %s failed for %s: %v", engineName, name, err).WithTarget(name))
			} else {
				run.casesFuzzed = runResult.Executions
				raw = append(raw, runResult.RawFindings...)
			}
		}
	}
	ctxInfo := triage.Context{
		BuildManifestSHA256:   state.BuildManifestSHA256,
		AdapterManifestSHA256: adapterFingerprint(target),
		BuildProfile:          plan.PlanID,
	}
	findings, triageDiags, err := triage.Process(ctx, cfg, out, target, &built.Result, raw, ctxInfo)
	if err != nil {
		run.err = err
		return run
	}
	run.findings = findings
	run.diagnostics = append(run.diagnostics, triageDiags...)
	sum := summarizeTarget(target, &built.Result, findings)
	sum.CorpusInputs = quality.Inputs
	sum.CorpusSelected = quality.Selected
	sum.CorpusRemoved = quality.Removed
	sum.InputsWithData = quality.InputsWithData
	sum.CorpusFrames = quality.Frames
	sum.DistinctStates = len(quality.StateHashes)
	sum.StateHashes = quality.StateHashes
	sum.DistinctTransitions = len(quality.Transitions)
	sum.Transitions = quality.Transitions
	sum.CommandConstants = quality.CommandConstants
	sum.CommandsCovered = quality.CommandsCovered
	if built.Result.Status == "smoke_crashed" && hasTargetCrash(findings) {
		if built.Result.FuzzBinary != "" {
			sum.Status = "fuzzable"
		} else {
			sum.Status = "selftest_passed"
		}
	}
	run.summary = sum
	return run
}
