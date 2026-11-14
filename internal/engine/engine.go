// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package engine runs external fuzzing engines. Engine-specific coverage
// numbers are never converted into a common synthetic metric.
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/hostbuild"
	"github.com/fuzzfw/fuzzfw/internal/proc"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

// RawFinding is an engine artifact before replay and classification.
type RawFinding struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Engine string `json:"engine"`
	Log    string `json:"log,omitempty"`
}

// RunResult records one engine invocation.
type RunResult struct {
	Engine      string        `json:"engine"`
	Target      string        `json:"target"`
	Argv        []string      `json:"argv"`
	ExitCode    int           `json:"exit_code"`
	TimedOut    bool          `json:"timed_out"`
	Duration    time.Duration `json:"duration_ns"`
	LogPath     string        `json:"log_path"`
	ArtifactDir string        `json:"artifact_dir"`
	Executions  int           `json:"executions,omitempty"`
	RawFindings []RawFinding  `json:"raw_findings,omitempty"`
}

// Engine is the thin adapter contract from the specification.
type Engine interface {
	Name() string
	Available() (bool, string)
	Run(ctx context.Context, target string, build *hostbuild.Result, corpusDir, artifactDir string, budget time.Duration, jobs int, maxInput int) (*RunResult, error)
}

// New selects an engine by name.
func New(name string, cfg *config.Config, tools *toolchain.Report) (Engine, error) {
	switch name {
	case "replay":
		return &ReplayEngine{}, nil
	case "libfuzzer":
		return &LibFuzzerEngine{Config: cfg, Tools: tools}, nil
	case "honggfuzz":
		return &HonggfuzzEngine{Config: cfg, Tools: tools}, nil
	default:
		return nil, fmt.Errorf("unknown engine %q", name)
	}
}

// ReplayEngine is the validation-only mode used for local corpus checks.
type ReplayEngine struct{}

func (e *ReplayEngine) Name() string { return "replay" }
func (e *ReplayEngine) Available() (bool, string) {
	return true, "validates corpus and self-test binaries only"
}
func (e *ReplayEngine) Run(context.Context, string, *hostbuild.Result, string, string, time.Duration, int, int) (*RunResult, error) {
	return &RunResult{Engine: "replay"}, nil
}

// LibFuzzerEngine runs Clang's libFuzzer adapter.
type LibFuzzerEngine struct {
	Config *config.Config
	Tools  *toolchain.Report
}

func (e *LibFuzzerEngine) Name() string { return "libfuzzer" }
func (e *LibFuzzerEngine) Available() (bool, string) {
	if e.Tools == nil || !e.Tools.LibFuzzerOK {
		return false, "clang -fsanitize=fuzzer is not available"
	}
	return true, ""
}

func (e *LibFuzzerEngine) Run(ctx context.Context, target string, build *hostbuild.Result, corpusDir, artifactDir string, budget time.Duration, jobs, maxInput int) (*RunResult, error) {
	if build == nil || build.FuzzBinary == "" {
		return nil, fmt.Errorf("no libFuzzer binary for target %s", target)
	}
	if ok, message := e.Available(); !ok {
		return nil, fmt.Errorf("%s", message)
	}
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return nil, err
	}
	if emptyDir(corpusDir) {
		_ = fsutil.WriteFileAtomic(filepath.Join(corpusDir, "empty"), nil, 0o644)
	}
	if jobs < 1 {
		jobs = 1
	}
	seconds := int(budget.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	argv := []string{
		build.FuzzBinary,
		fmt.Sprintf("-max_total_time=%d", seconds),
		fmt.Sprintf("-jobs=%d", jobs),
		fmt.Sprintf("-workers=%d", jobs),
		fmt.Sprintf("-artifact_prefix=%s%s", artifactDir, string(os.PathSeparator)),
		fmt.Sprintf("-max_len=%d", maxInput),
		"-timeout=10",
		"-rss_limit_mb=2048",
		"-print_final_stats=1",
		corpusDir,
	}
	logPath := filepath.Join(artifactDir, "engine.log")
	started := time.Now()
	run, err := (proc.Runner{Timeout: budget + 2*time.Minute}).Run(ctx, e.Config.Root, argv...)
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(logPath, []byte(run.Stdout+"\n"+run.Stderr), 0o644); err != nil {
		return nil, err
	}
	result := &RunResult{
		Engine:      e.Name(),
		Target:      target,
		Argv:        argv,
		ExitCode:    run.ExitCode,
		TimedOut:    run.TimedOut,
		Duration:    time.Since(started),
		LogPath:     logPath,
		ArtifactDir: artifactDir,
		Executions:  parseLibFuzzerExecutions(run.Stdout + run.Stderr),
	}
	result.RawFindings, _ = collectLibFuzzerArtifacts(artifactDir, target, logPath)
	return result, nil
}

var libfuzzerExecPattern = regexp.MustCompile(`stat::number_of_executed_units:\s*(\d+)`)

func parseLibFuzzerExecutions(text string) int {
	if match := libfuzzerExecPattern.FindStringSubmatch(text); match != nil {
		value, _ := strconv.Atoi(match[1])
		return value
	}
	return 0
}

// HonggfuzzEngine runs the P0 default engine.
type HonggfuzzEngine struct {
	Config *config.Config
	Tools  *toolchain.Report
}

func (e *HonggfuzzEngine) Name() string { return "honggfuzz" }
func (e *HonggfuzzEngine) Available() (bool, string) {
	if e.Tools == nil {
		return false, "toolchain report unavailable"
	}
	if !e.Tools.Tools["honggfuzz"].Found {
		return false, "honggfuzz executable not found"
	}
	if !e.Tools.Tools["hfuzz-clang"].Found {
		return false, "hfuzz-clang wrapper not found"
	}
	return true, ""
}

func (e *HonggfuzzEngine) Run(ctx context.Context, target string, build *hostbuild.Result, corpusDir, artifactDir string, budget time.Duration, jobs, maxInput int) (*RunResult, error) {
	if build == nil || build.FuzzBinary == "" {
		return nil, fmt.Errorf("no honggfuzz binary for target %s", target)
	}
	if ok, message := e.Available(); !ok {
		return nil, fmt.Errorf("%s", message)
	}
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return nil, err
	}
	if emptyDir(corpusDir) {
		_ = fsutil.WriteFileAtomic(filepath.Join(corpusDir, "empty"), nil, 0o644)
	}
	if jobs < 1 {
		jobs = 1
	}
	seconds := int(budget.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	argv := []string{
		e.Tools.Tools["honggfuzz"].Path,
		"-P",
		"--run_time", strconv.Itoa(seconds),
		"--threads", strconv.Itoa(jobs),
		"--input", corpusDir,
		"--workspace", artifactDir,
		"--max_file_size", strconv.Itoa(maxInput),
		"--exit_upon_crash",
		"--", build.FuzzBinary,
	}
	logPath := filepath.Join(artifactDir, "engine.log")
	started := time.Now()
	run, err := (proc.Runner{Timeout: budget + 2*time.Minute}).Run(ctx, e.Config.Root, argv...)
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(logPath, []byte(run.Stdout+"\n"+run.Stderr), 0o644); err != nil {
		return nil, err
	}
	result := &RunResult{
		Engine:      e.Name(),
		Target:      target,
		Argv:        argv,
		ExitCode:    run.ExitCode,
		TimedOut:    run.TimedOut,
		Duration:    time.Since(started),
		LogPath:     logPath,
		ArtifactDir: artifactDir,
	}
	result.RawFindings, _ = collectHonggfuzzArtifacts(artifactDir, target, logPath)
	return result, nil
}

var libfuzzerArtifactPrefixes = []string{"crash-", "timeout-", "leak-", "oom-", "slow-unit-", "artifact-"}

func collectLibFuzzerArtifacts(dir, target, logPath string) ([]RawFinding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var findings []RawFinding
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		kind := ""
		for _, prefix := range libfuzzerArtifactPrefixes {
			if strings.HasPrefix(entry.Name(), prefix) {
				kind = strings.TrimSuffix(prefix, "-")
				break
			}
		}
		if kind == "" {
			continue
		}
		findings = append(findings, RawFinding{
			Path: filepath.Join(dir, entry.Name()), Kind: kind, Target: target, Engine: "libfuzzer", Log: logPath,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings, nil
}

func collectHonggfuzzArtifacts(dir, target, logPath string) ([]RawFinding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var findings []RawFinding
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "engine.log" || strings.HasSuffix(entry.Name(), ".report.json") {
			continue
		}
		kind := ""
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, "SIG"), strings.Contains(name, "crash"):
			kind = "crash"
		case strings.Contains(name, "timeout") || strings.Contains(name, "hang"):
			kind = "timeout"
		case strings.Contains(name, "leak"):
			kind = "leak"
		}
		if kind == "" {
			continue
		}
		findings = append(findings, RawFinding{
			Path: filepath.Join(dir, name), Kind: kind, Target: target, Engine: "honggfuzz", Log: logPath,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings, nil
}

func emptyDir(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) == 0
}
