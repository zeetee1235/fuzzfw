// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package artifacts defines the on-disk fuzzfw workspace and output layout.
package artifacts

import (
	"path/filepath"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
)

// Workspace is the local analysis/build state under .fuzzfw/.
type Workspace struct {
	Root             string
	BuildManifest    string
	Analysis         string
	IRFacts          string
	Plan             string
	Lock             string
	GeneratedDir     string
	BuildDir         string
	AnalyzerInputDir string
}

// NewWorkspace creates a workspace layout for cfg.
func NewWorkspace(cfg *config.Config) *Workspace {
	root := cfg.ArtifactDir
	return &Workspace{
		Root:             root,
		BuildManifest:    filepath.Join(root, "build_manifest.json"),
		Analysis:         filepath.Join(root, "analysis.json"),
		IRFacts:          filepath.Join(root, "ir_facts.json"),
		Plan:             filepath.Join(root, "plan.json"),
		Lock:             filepath.Join(root, "lock.json"),
		GeneratedDir:     filepath.Join(root, "generated"),
		BuildDir:         filepath.Join(root, "build"),
		AnalyzerInputDir: filepath.Join(root, "analyzer-input"),
	}
}

// Ensure creates the workspace directories.
func (w *Workspace) Ensure() error {
	for _, dir := range []string{w.Root, w.GeneratedDir, w.BuildDir, w.AnalyzerInputDir} {
		if err := fsutil.EnsureDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// TargetGenerated returns the generated-source directory for a target.
func (w *Workspace) TargetGenerated(target string) string {
	return filepath.Join(w.GeneratedDir, fsutil.SafeName(target, "target"))
}

// TargetBuild returns the build directory for a target.
func (w *Workspace) TargetBuild(target string) string {
	return filepath.Join(w.BuildDir, fsutil.SafeName(target, "target"))
}

// AnalyzerInput returns a per-variant analyzer input file path.
func (w *Workspace) AnalyzerInput(variantID string) string {
	return filepath.Join(w.AnalyzerInputDir, fsutil.SafeName(variantID, "variant")+".json")
}

// Output is the CI-facing fuzzfw-out/ tree.
type Output struct {
	Root        string
	Summary     string
	JUnit       string
	BuildInfo   string
	Diagnostics string
	CorpusDir   string
	FindingsDir string
	EngineDir   string
	LogsDir     string
	Baseline    string
}

// NewOutput creates the output layout.
func NewOutput(root, baseline string) *Output {
	return &Output{
		Root:        root,
		Summary:     filepath.Join(root, "summary.json"),
		JUnit:       filepath.Join(root, "junit.xml"),
		BuildInfo:   filepath.Join(root, "build-info.json"),
		Diagnostics: filepath.Join(root, "diagnostics.json"),
		CorpusDir:   filepath.Join(root, "corpus"),
		FindingsDir: filepath.Join(root, "findings"),
		EngineDir:   filepath.Join(root, "engine"),
		LogsDir:     filepath.Join(root, "logs"),
		Baseline:    baseline,
	}
}

// Ensure creates the output directories.
func (o *Output) Ensure() error {
	for _, dir := range []string{o.Root, o.CorpusDir, o.FindingsDir, o.EngineDir, o.LogsDir} {
		if err := fsutil.EnsureDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// TargetCorpus returns the corpus directory for a target.
func (o *Output) TargetCorpus(target string) string {
	return filepath.Join(o.CorpusDir, fsutil.SafeName(target, "target"))
}

// TargetEngine returns the engine artifact directory for a target.
func (o *Output) TargetEngine(target string) string {
	return filepath.Join(o.EngineDir, fsutil.SafeName(target, "target"))
}

// FindingDir returns the finding artifact directory.
func (o *Output) FindingDir(id string) string {
	return filepath.Join(o.FindingsDir, fsutil.SafeName(id, "finding"))
}

// TargetLog returns the log path for a target.
func (o *Output) TargetLog(target string) string {
	return filepath.Join(o.LogsDir, fsutil.SafeName(target, "target")+".log")
}
