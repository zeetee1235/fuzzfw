// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/engine"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/report"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
	"github.com/fuzzfw/fuzzfw/internal/triage"
)

func runCheck(ctx context.Context, global globalOptions, args []string) (int, error) {
	flags := newFlagSet("check")
	timeFlag := flags.String("time", "", "fuzzing budget (30s, 10m, 1h)")
	jobsFlag := flags.Int("jobs", 0, "engine workers")
	engineFlag := flags.String("engine", "", "engine: honggfuzz, libfuzzer, replay")
	outputFlag := flags.String("output", "", "output directory")
	baselineFlag := flags.String("baseline", "", "baseline JSON path")
	bootstrap := flags.Bool("bootstrap-baseline", false, "approve current findings as the baseline")
	noMinimize := flags.Bool("no-minimize", false, "disable input minimization")
	jsonOutput := flags.Bool("json", false, "print summary JSON")
	var selected stringList
	flags.Var(&selected, "target", "required target name (repeatable)")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	started := time.Now()
	cfg, err := loadConfigOrError(global, ".", true)
	if err != nil {
		return exitcode.Usage, err
	}
	if *noMinimize {
		cfg.File.Harness.Minimize = false
	}
	if len(selected) == 0 && len(cfg.RequiredTargets()) == 0 {
		return exitcode.Usage, diag.NewError(diag.ETargetRequiredNone,
			"no required targets: set required=true on [[targets]] or pass --target")
	}
	for _, name := range selected {
		if _, ok := cfg.Target(name); !ok {
			return exitcode.Usage, diag.NewError(diag.ETargetNotFound,
				fmt.Sprintf("selected target %q is not declared in fuzzfw.toml", name))
		}
	}
	tools := toolchain.Detect(ctx, cfg)
	if !tools.Tools["clang"].Found {
		return exitcode.Incomplete, diag.NewError(diag.EASTParse, "clang was not found; install Clang or set host.clang")
	}
	engineName := cfg.File.CI.Engine
	if *engineFlag != "" {
		engineName = *engineFlag
	}
	fuzzEngine, err := engine.New(engineName, cfg, tools)
	if err != nil {
		return exitcode.Usage, err
	}
	engineOK, engineMessage := fuzzEngine.Available()
	var allDiagnostics []diag.Diagnostic
	if !engineOK {
		allDiagnostics = append(allDiagnostics, diag.New(diag.EEngineUnavailable, engineMessage).WithTarget(""))
	}

	// check is self-contained: always re-analyze from the current source tree.
	db, err := loadDatabase(ctx, cfg)
	if err != nil {
		return exitcode.Usage, err
	}
	analysis, buildManifest, analysisDuration, err := analyzeProject(ctx, cfg, db, tools)
	if err != nil {
		return exitcode.Incomplete, err
	}
	ws := artifacts.NewWorkspace(cfg)
	analysisHash, manifestHash, err := writeAnalysisArtifacts(ws, analysis, buildManifest)
	if err != nil {
		return exitcode.Incomplete, err
	}
	allDiagnostics = append(allDiagnostics, analysis.Diagnostics...)
	plan, err := planner.Build(cfg, analysis, analysisHash, selected)
	if err != nil {
		return exitcode.Incomplete, err
	}
	if err := writePlan(ws, plan); err != nil {
		return exitcode.Incomplete, err
	}
	allDiagnostics = append(allDiagnostics, plan.Diagnostics...)
	required := requiredNames(cfg, plan, selected)
	if len(required) == 0 {
		return exitcode.Usage, diag.NewError(diag.ETargetRequiredNone,
			"plan contains no required target; set required=true or pass --target")
	}
	requiredSet := map[string]bool{}
	for _, name := range required {
		requiredSet[name] = true
	}

	buildStarted := time.Now()
	results, buildDiags, err := buildTargets(ctx, cfg, ws, db, tools, plan, required, engineName)
	if err != nil {
		return exitcode.Incomplete, err
	}
	buildDuration := time.Since(buildStarted)
	allDiagnostics = append(allDiagnostics, buildDiags...)
	state, err := saveBuildResults(cfg, ws, plan, analysisHash, manifestHash, tools.Hash(), results)
	if err != nil {
		return exitcode.Incomplete, err
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
	if len(results) == 0 {
		return exitcode.Incomplete, diag.NewError(diag.ERequiredNotRun,
			"required targets were planned but no build result was produced")
	}
	perTarget := budget / time.Duration(len(results))
	if cfg.File.CI.PerTargetSeconds > 0 {
		perTarget = time.Duration(cfg.File.CI.PerTargetSeconds) * time.Second
	}
	if perTarget < time.Second {
		perTarget = time.Second
	}
	fuzzDeadline := time.Now().Add(budget)

	var allFindings []triage.Finding
	findingsByTarget := map[string][]triage.Finding{}
	summaries := map[string]report.TargetSummary{}
	casesReplayed := 0
	casesFuzzed := 0
	selftestSeconds := 0.0
	fuzzStarted := time.Now()
	triageStarted := time.Now()
	engineFailed := map[string]bool{}
	fuzzTimedOut := map[string]bool{}
	for _, result := range results {
		target, ok := plan.Target(result.Name)
		if !ok {
			continue
		}
		built := result
		selftestSeconds += built.Result.Selftest.DurationSeconds
		summary := summarizeTarget(target, &built.Result, nil)
		summary.Required = requiredSet[target.Name] || summary.Required
		summaries[target.Name] = summary
		if built.Result.SelftestBinary == "" {
			allDiagnostics = append(allDiagnostics, diag.Newf(diag.EHarnessBuild,
				"target %s has no self-test binary", target.Name).WithTarget(target.Name))
			continue
		}
		corpusDir, _, err := prepareCorpus(cfg, out, target)
		if err != nil {
			return exitcode.Incomplete, err
		}
		raw, quality, replayDiags := replayCorpus(ctx, cfg, out, target, &built.Result)
		casesReplayed += quality.Inputs
		allDiagnostics = append(allDiagnostics, replayDiags...)
		if summary, ok := summaries[target.Name]; ok {
			summary.CorpusInputs = quality.Inputs
			summary.InputsWithData = quality.InputsWithData
			summary.CorpusFrames = quality.Frames
			summary.DistinctStates = len(quality.StateHashes)
			summary.StateHashes = quality.StateHashes
			summary.DistinctTransitions = len(quality.Transitions)
			summary.Transitions = quality.Transitions
			summary.CommandConstants = quality.CommandConstants
			summary.CommandsCovered = quality.CommandsCovered
			summaries[target.Name] = summary
		}
		for _, selftestCase := range built.Result.Selftest.Cases {
			if selftestCase.Crash && (selftestCase.Origin == "target_crash" || selftestCase.Origin == "target_invariant") && selftestCase.InputPath != "" {
				raw = append(raw, engine.RawFinding{
					Path: absJoinPath(cfg.Root, selftestCase.InputPath), Kind: selftestCase.Sanitizer,
					Target: target.Name, Engine: "selftest",
				})
			}
		}
		if engineName != "replay" && built.Result.FuzzBinary != "" {
			remaining := time.Until(fuzzDeadline)
			if remaining < time.Second {
				fuzzTimedOut[target.Name] = true
				allDiagnostics = append(allDiagnostics, diag.New(diag.ETimeoutInfra,
					"global fuzz budget exhausted before target "+target.Name).WithTarget(target.Name))
			} else {
				targetBudget := perTarget
				if targetBudget > remaining {
					targetBudget = remaining
				}
				runResult, runErr := fuzzEngine.Run(ctx, target.Name, &built.Result, corpusDir, out.TargetEngine(target.Name), targetBudget, jobs, target.MaxInputBytes, built.Result.DictionaryPath)
				if runErr != nil {
					engineFailed[target.Name] = true
					allDiagnostics = append(allDiagnostics, diag.Newf(diag.EEngineFailed,
						"engine %s failed for %s: %v", engineName, target.Name, runErr).WithTarget(target.Name))
				} else {
					casesFuzzed += runResult.Executions
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
			return exitcode.Incomplete, err
		}
		allDiagnostics = append(allDiagnostics, triageDiags...)
		allFindings = append(allFindings, findings...)
		findingsByTarget[target.Name] = findings
		if built.Result.Status == "smoke_crashed" && hasTargetCrash(findings) {
			// A seed that already crashes the target is a product finding, not
			// a harness failure. The build command still fails closed; check
			// reports the reproduced target finding through the finding path.
			summary := summaries[target.Name]
			if built.Result.FuzzBinary != "" {
				summary.Status = "fuzzable"
			} else {
				summary.Status = "selftest_passed"
			}
			summaries[target.Name] = summary
		}
	}
	triageDuration := time.Since(triageStarted)

	baseline, err := triage.LoadBaseline(baselinePath)
	if err != nil {
		return exitcode.Incomplete, err
	}
	if baseline == nil && *bootstrap {
		if baselinePath == "" {
			baselinePath = filepath.Join(cfg.Root, "fuzzfw-baseline.json")
		}
		if err := triage.WriteBaseline(baselinePath, allFindings); err != nil {
			return exitcode.Incomplete, err
		}
		if loaded, err := triage.LoadBaseline(baselinePath); err == nil {
			baseline = loaded
		}
		allDiagnostics = append(allDiagnostics, diag.Diagnostic{
			Code: diag.InfoRecovery, Severity: diag.SeverityInfo,
			Message: "baseline bootstrapped at " + baselinePath,
		})
	} else if baseline == nil {
		allDiagnostics = append(allDiagnostics, diag.New(diag.EBaselineMissing,
			"no baseline configured; all reproduced findings are treated as new",
		).Warning())
	}

	var targetSummaries []report.TargetSummary
	for _, target := range plan.Targets {
		summary, ok := summaries[target.Name]
		if !ok {
			summary = summarizeTarget(target, nil, nil)
			summary.Required = requiredSet[target.Name] || summary.Required
			if target.Classification == planner.Blocked {
				summary.Status = "blocked"
			}
		}
		findings := findingsByTarget[target.Name]
		for _, finding := range findings {
			summary.FindingIDs = append(summary.FindingIDs, finding.ID)
		}
		if engineFailed[target.Name] {
			summary.Status = "engine_failed"
		}
		if fuzzTimedOut[target.Name] {
			summary.Status = "not_fuzzable"
		}
		targetSummaries = append(targetSummaries, summary)
	}

	fuzzSeconds := time.Since(fuzzStarted).Seconds()
	project := report.ProjectInfo{Name: plan.Project.Name, Root: plan.Project.Root, SourceRevision: plan.Project.SourceRevision}
	summary := report.New(report.Input{
		Command: "check", Config: cfg, Project: project, StartedAt: started, FinishedAt: time.Now(),
		AnalysisSeconds: analysisDuration.Seconds(), BuildSeconds: buildDuration.Seconds(),
		SelftestSeconds: selftestSeconds, FuzzSeconds: fuzzSeconds, TriageSeconds: triageDuration.Seconds(),
		Targets: targetSummaries, Findings: allFindings, Baseline: baseline,
		Diagnostics: allDiagnostics, CasesReplayed: casesReplayed, CasesFuzzed: casesFuzzed,
		Artifacts: report.ArtifactPaths{
			Summary: out.Summary, JUnit: out.JUnit, BuildInfo: out.BuildInfo,
			Diagnostics: out.Diagnostics, Corpus: out.CorpusDir, Findings: out.FindingsDir,
			Baseline: baselinePath,
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
		fmt.Printf("check: %s (exit %d)\n", summary.Status, summary.ExitCode)
		fmt.Printf("reason: %s\n", summary.Reason)
		for _, target := range summary.Targets {
			fmt.Printf("  %-24s %-18s entry=%t input=%s findings=%d\n",
				target.Name, target.Status, target.EntryHit, target.InputUse, len(target.FindingIDs))
		}
		if len(summary.Findings) > 0 {
			fmt.Printf("findings: %d (new reproduced: %d)\n", len(summary.Findings), summary.Metrics.NewFindingsReproduced)
		}
		fmt.Printf("artifacts: %s\n", out.Root)
	}
	return summary.ExitCode, nil
}

func hasTargetCrash(findings []triage.Finding) bool {
	for _, finding := range findings {
		if (finding.Origin == "target_crash" || finding.Origin == "target_invariant") &&
			finding.Reproduction.Level == "R1_HOST_REPRODUCED" && !finding.Reproduction.NonReproducing {
			return true
		}
	}
	return false
}

func absJoinPath(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}
