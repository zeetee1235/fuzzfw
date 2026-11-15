// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/engine"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/harness"
	"github.com/fuzzfw/fuzzfw/internal/hostbuild"
	"github.com/fuzzfw/fuzzfw/internal/manifest"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/report"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
	"github.com/fuzzfw/fuzzfw/internal/triage"
)

func prepareAnalysis(ctx context.Context, cfg *config.Config, tools *toolchain.Report, refresh bool) (*analyzer.Analysis, string, string, time.Duration, error) {
	ws := artifacts.NewWorkspace(cfg)
	if !refresh && fsutil.Exists(ws.Analysis) && fsutil.Exists(ws.BuildManifest) {
		analysis, err := loadAnalysis(cfg, ws)
		if err != nil {
			return nil, "", "", 0, err
		}
		var buildManifest manifest.Manifest
		if err := fsutil.ReadJSON(ws.BuildManifest, &buildManifest); err != nil {
			return nil, "", "", 0, err
		}
		analysisHash, err := fsutil.HashJSON(analysis)
		if err != nil {
			return nil, "", "", 0, err
		}
		manifestHash, err := fsutil.HashJSON(buildManifest)
		if err != nil {
			return nil, "", "", 0, err
		}
		return analysis, analysisHash, manifestHash, 0, nil
	}
	db, err := loadDatabase(ctx, cfg)
	if err != nil {
		return nil, "", "", 0, err
	}
	analysis, buildManifest, duration, err := analyzeProject(ctx, cfg, db, tools)
	if err != nil {
		return nil, "", "", 0, err
	}
	analysisHash, manifestHash, err := writeAnalysisArtifacts(ws, analysis, buildManifest)
	if err != nil {
		return nil, "", "", 0, err
	}
	return analysis, analysisHash, manifestHash, duration, nil
}

type irFactsFile struct {
	SchemaVersion int                       `json:"schema_version"`
	Facts         []analyzer.IRFunctionFact `json:"facts"`
}

func collectRevision(ctx context.Context, cfg *config.Config) string {
	if cfg.File.Project.SourceRevision != "auto" && cfg.File.Project.SourceRevision != "" {
		return cfg.File.Project.SourceRevision
	}
	return fsutil.CollectGit(ctx, cfg.Root).RevisionString()
}

func loadDatabase(ctx context.Context, cfg *config.Config) (*compdb.Database, error) {
	return compdb.Load(ctx, cfg.CompDB, cfg.Root)
}

func analyzeProject(ctx context.Context, cfg *config.Config, db *compdb.Database, tools *toolchain.Report) (*analyzer.Analysis, *manifest.Manifest, time.Duration, error) {
	started := time.Now()
	revision := collectRevision(ctx, cfg)
	analysis, err := analyzer.Analyze(ctx, cfg, db, tools, revision)
	if err != nil {
		return nil, nil, time.Since(started), err
	}
	buildManifest, err := manifest.Collect(ctx, cfg, db, tools)
	if err != nil {
		return nil, nil, time.Since(started), err
	}
	return analysis, buildManifest, time.Since(started), nil
}

func writeAnalysisArtifacts(ws *artifacts.Workspace, analysis *analyzer.Analysis, buildManifest *manifest.Manifest) (string, string, error) {
	if err := ws.Ensure(); err != nil {
		return "", "", err
	}
	if err := fsutil.WriteJSON(ws.BuildManifest, buildManifest, true); err != nil {
		return "", "", err
	}
	if err := fsutil.WriteJSON(ws.Analysis, analysis, true); err != nil {
		return "", "", err
	}
	irFile := irFactsFile{SchemaVersion: 1, Facts: analysis.IRFacts}
	if err := fsutil.WriteJSON(ws.IRFacts, irFile, true); err != nil {
		return "", "", err
	}
	analysisHash, err := fsutil.HashJSON(analysis)
	if err != nil {
		return "", "", err
	}
	manifestHash, err := fsutil.HashJSON(buildManifest)
	if err != nil {
		return "", "", err
	}
	return analysisHash, manifestHash, nil
}

func loadAnalysis(cfg *config.Config, ws *artifacts.Workspace) (*analyzer.Analysis, error) {
	var analysis analyzer.Analysis
	if err := fsutil.ReadJSON(ws.Analysis, &analysis); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no analysis at %s; run fuzzfw scan --refresh first", ws.Analysis)
		}
		return nil, err
	}
	if analysis.SchemaVersion != analyzer.AnalysisSchemaVersion {
		return nil, fmt.Errorf("unsupported analysis schema %d", analysis.SchemaVersion)
	}
	return &analysis, nil
}

func loadPlan(ws *artifacts.Workspace) (*planner.Plan, error) {
	var plan planner.Plan
	if err := fsutil.ReadJSON(ws.Plan, &plan); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no plan at %s; run fuzzfw plan first", ws.Plan)
		}
		return nil, err
	}
	if plan.SchemaVersion != planner.PlanSchemaVersion {
		return nil, fmt.Errorf("unsupported plan schema %d", plan.SchemaVersion)
	}
	return &plan, nil
}

func writePlan(ws *artifacts.Workspace, plan *planner.Plan) error {
	if err := ws.Ensure(); err != nil {
		return err
	}
	return fsutil.WriteJSON(ws.Plan, plan, true)
}

func targetNames(plan *planner.Plan, selected []string) ([]string, error) {
	if len(selected) == 0 {
		var names []string
		for _, target := range plan.Targets {
			names = append(names, target.Name)
		}
		return names, nil
	}
	var names []string
	for _, name := range selected {
		if _, ok := plan.Target(name); ok {
			names = append(names, name)
			continue
		}
		return nil, fmt.Errorf("target %q not found in plan", name)
	}
	return names, nil
}

func requiredNames(cfg *config.Config, plan *planner.Plan, selected []string) []string {
	if len(selected) > 0 {
		return selected
	}
	var names []string
	for _, target := range plan.Targets {
		if target.Required {
			names = append(names, target.Name)
		}
	}
	if len(names) == 0 {
		for _, target := range cfg.RequiredTargets() {
			names = append(names, target.Name)
		}
	}
	return names
}

func buildTargets(
	ctx context.Context,
	cfg *config.Config,
	ws *artifacts.Workspace,
	db *compdb.Database,
	tools *toolchain.Report,
	plan *planner.Plan,
	names []string,
	engineName string,
) ([]targetBuild, []diag.Diagnostic, error) {
	var results []targetBuild
	var diagnostics []diag.Diagnostic
	for _, name := range names {
		target, ok := plan.Target(name)
		if !ok {
			diagnostics = append(diagnostics, diag.Newf(diag.ETargetNotFound, "target %s not found in plan", name))
			continue
		}
		hp, err := harness.BuildPlan(target, cfg)
		if err != nil {
			result := hostbuild.Result{
				Target: target.Name, Status: hostbuild.StatusHarnessBuildFailed,
				Classification: target.Classification,
				Diagnostics: []diag.Diagnostic{diag.Newf(diag.EHarnessBuild,
					"cannot create harness plan: %v", err).WithTarget(target.Name)},
			}
			results = append(results, targetBuild{Name: target.Name, Result: result})
			diagnostics = append(diagnostics, result.Diagnostics...)
			continue
		}
		builder := hostbuild.Builder{
			Ctx: ctx, Cfg: cfg, DB: db, Workspace: ws, Tools: tools, Engine: engineName,
		}
		result, err := builder.Build(target, hp)
		if err != nil {
			return results, diagnostics, err
		}
		results = append(results, targetBuild{Name: target.Name, Result: *result})
		diagnostics = append(diagnostics, result.Diagnostics...)
	}
	return results, diagnostics, nil
}

func saveBuildResults(cfg *config.Config, ws *artifacts.Workspace, plan *planner.Plan, analysisHash, manifestHash, toolchainHash string, results []targetBuild) (*buildState, error) {
	state := &buildState{
		SchemaVersion:       buildStateSchemaVersion,
		CreatedAt:           fsutil.NowUTC(),
		BuildManifestSHA256: manifestHash,
		AnalysisSHA256:      analysisHash,
		ConfigFingerprint:   cfg.Fingerprint,
		PlanID:              plan.PlanID,
		ToolchainHash:       toolchainHash,
		Targets:             results,
	}
	return state, saveBuildState(ws, state, plan)
}

func prepareCorpus(cfg *config.Config, out *artifacts.Output, target planner.TargetPlan) (string, int, error) {
	corpusDir := out.TargetCorpus(target.Name)
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		return "", 0, err
	}
	if cfg.File.CI.CorpusDir != "" {
		if err := copyCorpusFiles(cfg.File.CI.CorpusDir, corpusDir); err != nil {
			return "", 0, err
		}
	}
	for index, seed := range target.Seeds {
		source := seed
		if !filepath.IsAbs(source) {
			source = filepath.Join(cfg.Root, source)
		}
		info, err := os.Stat(source)
		if err != nil {
			continue
		}
		if info.IsDir() {
			if err := copyCorpusFiles(source, corpusDir); err != nil {
				return "", 0, err
			}
			continue
		}
		dest := filepath.Join(corpusDir, fmt.Sprintf("seed-%03d", index))
		if err := fsutil.CopyFile(source, dest); err != nil {
			return "", 0, err
		}
	}
	files, err := corpusFiles(corpusDir)
	if err != nil {
		return "", 0, err
	}
	if len(files) == 0 {
		if err := fsutil.WriteFileAtomic(filepath.Join(corpusDir, "empty"), nil, 0o644); err != nil {
			return "", 0, err
		}
		files = []string{filepath.Join(corpusDir, "empty")}
	}
	return corpusDir, len(files), nil
}

func copyCorpusFiles(source, dest string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		target := filepath.Join(dest, fsutil.SafeName(name, "seed"))
		if fsutil.Exists(target) {
			continue
		}
		if err := fsutil.CopyFile(filepath.Join(source, name), target); err != nil {
			return err
		}
	}
	return nil
}

func corpusFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

type corpusQuality struct {
	Inputs         int
	InputsWithData int
	Frames         uint64
	StateHashes    []string
}

func replayCorpus(
	ctx context.Context,
	cfg *config.Config,
	out *artifacts.Output,
	target planner.TargetPlan,
	build *hostbuild.Result,
) ([]engine.RawFinding, corpusQuality, []diag.Diagnostic) {
	var raw []engine.RawFinding
	var diagnostics []diag.Diagnostic
	quality := corpusQuality{}
	states := map[string]bool{}
	dir := out.TargetCorpus(target.Name)
	files, err := corpusFiles(dir)
	if err != nil {
		return raw, quality, []diag.Diagnostic{diag.Newf(diag.EArtifactInvalid,
			"cannot enumerate corpus for %s: %v", target.Name, err).WithTarget(target.Name)}
	}
	quality.Inputs = len(files)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			diagnostics = append(diagnostics, diag.Newf(diag.EArtifactInvalid,
				"cannot read corpus file %s: %v", file, err).WithTarget(target.Name))
			continue
		}
		outcome := triage.RunOnce(ctx, cfg, build, data, target.Name, "", 20*time.Second)
		if outcome.Report != nil {
			if outcome.Report.Frames > 0 {
				quality.InputsWithData++
				if outcome.Report.StateHash != "" {
					states[outcome.Report.StateHash] = true
				}
			}
			if outcome.Report.Frames > quality.Frames {
				quality.Frames = outcome.Report.Frames
			}
		}
		if outcome.Crashed {
			raw = append(raw, engine.RawFinding{
				Path: file, Kind: outcome.Kind, Target: target.Name, Engine: "corpus",
			})
		}
	}
	for hash := range states {
		quality.StateHashes = append(quality.StateHashes, hash)
	}
	sort.Strings(quality.StateHashes)
	return raw, quality, diagnostics
}

func summarizeTarget(target planner.TargetPlan, build *hostbuild.Result, findings []triage.Finding) report.TargetSummary {
	summary := report.TargetSummary{
		Name:           target.Name,
		Required:       target.Required,
		Classification: target.Classification,
		Status:         "planned",
		EntryHit:       false,
		InputUse:       "unknown",
		Dependencies:   append([]string(nil), target.Dependencies...),
	}
	if build != nil {
		summary.Status = build.Status
		summary.Engine = build.Engine
		summary.HarnessID = build.HarnessID
		summary.SelftestBinary = build.SelftestBinary
		summary.FuzzBinary = build.FuzzBinary
		summary.EntryHit = build.Selftest.EntryHit
		summary.InputUse = build.Selftest.InputUse
		if summary.InputUse == "" {
			summary.InputUse = "unknown"
		}
		summary.Stability = "stable"
		if !build.Selftest.Stable {
			summary.Stability = "unstable"
		}
		summary.Diagnostics = append(summary.Diagnostics, build.Diagnostics...)
	}
	if target.Classification == planner.Blocked {
		summary.Status = "blocked"
	}
	for _, adapter := range target.Adapters {
		summary.Adapters = append(summary.Adapters, report.AdapterSummary{
			OriginalSymbol: adapter.OriginalSymbol,
			Source:         adapter.ReplacementSource,
			Model:          adapter.Model,
			Limitations:    adapter.Limitations,
		})
	}
	for _, finding := range findings {
		summary.FindingIDs = append(summary.FindingIDs, finding.ID)
	}
	summary.Diagnostics = append(summary.Diagnostics, target.Diagnostics...)
	return summary
}

func adapterFingerprint(target planner.TargetPlan) string {
	hash, _ := fsutil.HashJSON(target.Adapters)
	return hash
}

func targetByBuildName(plan *planner.Plan, name string) (planner.TargetPlan, bool) {
	return plan.Target(name)
}

type buildInfoDocument struct {
	SchemaVersion       int           `json:"schema_version"`
	CreatedAt           string        `json:"created_at"`
	BuildManifestSHA256 string        `json:"build_manifest_sha256"`
	AnalysisSHA256      string        `json:"analysis_sha256"`
	ConfigFingerprint   string        `json:"config_fingerprint,omitempty"`
	PlanID              string        `json:"plan_id"`
	ToolchainHash       string        `json:"toolchain_hash,omitempty"`
	Targets             []targetBuild `json:"targets"`
	GeneratedAt         string        `json:"generated_at"`
	Toolchain           any           `json:"toolchain,omitempty"`
	Plan                *planner.Plan `json:"plan,omitempty"`
}

func newBuildInfoDocument(state *buildState, tools any, plan *planner.Plan) buildInfoDocument {
	return buildInfoDocument{
		SchemaVersion:       state.SchemaVersion,
		CreatedAt:           state.CreatedAt,
		BuildManifestSHA256: state.BuildManifestSHA256,
		AnalysisSHA256:      state.AnalysisSHA256,
		ConfigFingerprint:   state.ConfigFingerprint,
		PlanID:              state.PlanID,
		ToolchainHash:       state.ToolchainHash,
		Targets:             state.Targets,
		GeneratedAt:         fsutil.NowUTC(),
		Toolchain:           tools,
		Plan:                plan,
	}
}
