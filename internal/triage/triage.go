// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package triage replays raw engine artifacts in isolated processes, classifies
// origin, minimizes inputs, and writes reproducible finding artifacts.
package triage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/engine"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/hostbuild"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/proc"
)

// FindingSchemaVersion is finding.json schema version 1.
const FindingSchemaVersion = 1

// Finding is the normalized artifact contract.
type Finding struct {
	SchemaVersion         int          `json:"schema_version"`
	ID                    string       `json:"id"`
	Fingerprint           string       `json:"fingerprint"`
	Target                string       `json:"target"`
	Kind                  string       `json:"kind"`
	Origin                string       `json:"origin"`
	Reproduction          Reproduction `json:"reproduction"`
	Source                SourceLoc    `json:"source,omitempty"`
	BuildManifestSHA256   string       `json:"build_manifest_sha256,omitempty"`
	AdapterManifestSHA256 string       `json:"adapter_manifest_sha256,omitempty"`
	InputSHA256           string       `json:"input_sha256"`
	InputPath             string       `json:"input_path"`
	LogPath               string       `json:"log_path,omitempty"`
	ScopeNote             string       `json:"scope_note"`
}

// Reproduction records the R-level and attempt counts.
type Reproduction struct {
	Level          string `json:"level"`
	Success        int    `json:"success"`
	Attempts       int    `json:"attempts"`
	Flaky          bool   `json:"flaky"`
	NonReproducing bool   `json:"non_reproducing"`
}

// SourceLoc is the first target frame location.
type SourceLoc struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Func string `json:"func,omitempty"`
}

// Context carries reproducibility identifiers into findings.
type Context struct {
	BuildManifestSHA256   string
	AdapterManifestSHA256 string
	BuildProfile          string
}

// ReplayOutcome is one isolated execution result.
type ReplayOutcome struct {
	Command   []string                `json:"command"`
	ExitCode  int                     `json:"exit_code"`
	Signal    int                     `json:"signal,omitempty"`
	TimedOut  bool                    `json:"timed_out"`
	Log       string                  `json:"-"`
	Report    *hostbuild.ReplayReport `json:"report,omitempty"`
	Crashed   bool                    `json:"crashed"`
	Kind      string                  `json:"kind,omitempty"`
	Signature string                  `json:"signature,omitempty"`
	Frames    []string                `json:"frames,omitempty"`
	Origin    string                  `json:"origin,omitempty"`
	Source    SourceLoc               `json:"source,omitempty"`
}

var (
	asanLine      = regexp.MustCompile(`AddressSanitizer:\s*([A-Za-z0-9_-]+)`)
	lsanLine      = regexp.MustCompile(`LeakSanitizer:\s*([A-Za-z0-9_-]+)`)
	ubsanLine     = regexp.MustCompile(`runtime error:\s*([^\n]+)`)
	frameLine     = regexp.MustCompile(`^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+([^\s]+)\s+([^\s:]+):(\d+)`)
	invariantLine = regexp.MustCompile(`fuzzfw invariant violated:\s*([^\n]+)`)
)

// Process triages raw engine findings for one target.
func Process(
	ctx context.Context,
	cfg *config.Config,
	out *artifacts.Output,
	target planner.TargetPlan,
	build *hostbuild.Result,
	raw []engine.RawFinding,
	ctxInfo Context,
) ([]Finding, []diag.Diagnostic, error) {
	if build == nil || build.SelftestBinary == "" {
		return nil, []diag.Diagnostic{diag.New(diag.EArtifactInvalid,
			"cannot triage without a self-test binary").WithTarget(target.Name)}, nil
	}
	if err := out.Ensure(); err != nil {
		return nil, nil, err
	}
	var diagnostics []diag.Diagnostic
	byFingerprint := map[string]Finding{}
	for _, artifact := range raw {
		inputData, err := os.ReadFile(artifact.Path)
		if err != nil {
			diagnostics = append(diagnostics, diag.Newf(diag.EArtifactInvalid,
				"cannot read engine artifact %s: %v", artifact.Path, err))
			continue
		}
		replay := RunOnce(ctx, cfg, build, inputData, target.Name, artifact.Log, 30*time.Second)
		if !replay.Crashed {
			// Keep the observation but do not promote it to a product finding.
			finding := Finding{
				SchemaVersion: FindingSchemaVersion,
				Target:        target.Name,
				Kind:          firstNonEmpty(replay.Kind, artifact.Kind),
				Origin:        "unknown",
				Reproduction:  Reproduction{Level: "R0_OBSERVED", Attempts: 1, NonReproducing: true},
				InputSHA256:   fsutil.HashBytes(inputData),
				ScopeNote:     "raw engine observation did not reproduce in self-test",
			}
			finding.Fingerprint = fingerprint(finding, replay.Frames, ctxInfo.BuildProfile)
			finding.ID = findingID(finding.Fingerprint)
			if _, exists := byFingerprint[finding.Fingerprint]; !exists {
				rawLog := replay.Log
				if rawLog == "" {
					rawLog = readLog(artifact.Log)
				}
				if err := writeFindingArtifacts(ctx, cfg, out, build, target, &finding, inputData, rawLog); err != nil {
					return nil, diagnostics, err
				}
				byFingerprint[finding.Fingerprint] = finding
			}
			continue
		}

		kind := replay.Kind
		origin := replay.Origin
		attempts := cfg.File.Harness.ReproductionAttempts
		success := 0
		var firstLog string
		var lastOutcome ReplayOutcome
		for attempt := 0; attempt < attempts; attempt++ {
			outcome := RunOnce(ctx, cfg, build, inputData, target.Name, "", 30*time.Second)
			if sameFailure(replay, outcome) {
				success++
				if firstLog == "" {
					firstLog = outcome.Log
				}
			}
			lastOutcome = outcome
		}
		level := "R0_OBSERVED"
		flaky := false
		nonReproducing := false
		switch {
		case success == attempts && attempts > 0:
			level = "R1_HOST_REPRODUCED"
		case success > 0:
			level = "R1_HOST_REPRODUCED"
			flaky = true
		default:
			nonReproducing = true
			firstLog = lastOutcome.Log
		}

		minimized := inputData
		if success > 0 && cfg.File.Harness.Minimize {
			minimized, _, diagnostics = minimize(ctx, cfg, build, target.Name, inputData, replay, diagnostics)
			// Re-verify the minimized input with fresh attempts.
			success = 0
			for attempt := 0; attempt < attempts; attempt++ {
				outcome := RunOnce(ctx, cfg, build, minimized, target.Name, "", 30*time.Second)
				if sameFailure(replay, outcome) {
					success++
					if firstLog == "" {
						firstLog = outcome.Log
					}
				}
			}
			flaky = success > 0 && success < attempts
			nonReproducing = success == 0
			if success == attempts && attempts > 0 {
				level = "R1_HOST_REPRODUCED"
			}
		}

		finding := Finding{
			SchemaVersion:         FindingSchemaVersion,
			Target:                target.Name,
			Kind:                  kind,
			Origin:                origin,
			Reproduction:          Reproduction{Level: level, Success: success, Attempts: attempts, Flaky: flaky, NonReproducing: nonReproducing},
			Source:                replay.Source,
			BuildManifestSHA256:   ctxInfo.BuildManifestSHA256,
			AdapterManifestSHA256: ctxInfo.AdapterManifestSHA256,
			InputSHA256:           fsutil.HashBytes(minimized),
			ScopeNote:             "host recompiled code; MCU behavior is not confirmed (HOST_ONLY)",
		}
		finding.Fingerprint = fingerprint(finding, replay.Frames, ctxInfo.BuildProfile)
		finding.ID = findingID(finding.Fingerprint)
		if existing, exists := byFingerprint[finding.Fingerprint]; exists {
			if finding.Reproduction.Success > existing.Reproduction.Success {
				byFingerprint[finding.Fingerprint] = finding
			}
			continue
		}
		byFingerprint[finding.Fingerprint] = finding
		if firstLog != "" {
			finding.LogPath = ""
		}
		// Persist immediately with the final minimized bytes and first log.
		if err := writeFindingArtifacts(ctx, cfg, out, build, target, &finding, minimized, firstLog); err != nil {
			return nil, diagnostics, err
		}
		byFingerprint[finding.Fingerprint] = finding
	}

	findings := make([]Finding, 0, len(byFingerprint))
	for _, finding := range byFingerprint {
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return findings, diagnostics, nil
}

// RunOnce executes one input in a fresh self-test process.
func RunOnce(ctx context.Context, cfg *config.Config, build *hostbuild.Result, data []byte, target, logPath string, timeout time.Duration) ReplayOutcome {
	outcome := ReplayOutcome{}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dir, err := os.MkdirTemp("", "fuzzfw-replay-*")
	if err != nil {
		outcome.Log = err.Error()
		return outcome
	}
	defer os.RemoveAll(dir)
	inputPath := filepath.Join(dir, "input.bin")
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(inputPath, data, 0o644); err != nil {
		outcome.Log = err.Error()
		return outcome
	}
	symbol := build.EntrySymbol
	argv := []string{build.SelftestBinary, "--input", inputPath, "--report", reportPath}
	if symbol != "" {
		argv = append(argv, "--entry-symbol", symbol)
	}
	outcome.Command = argv
	run, err := (proc.Runner{Timeout: timeout}).Run(ctx, cfg.Root, argv...)
	if err != nil {
		outcome.Log = err.Error()
		return outcome
	}
	outcome.ExitCode = run.ExitCode
	outcome.Signal = run.Signal
	outcome.TimedOut = run.TimedOut
	outcome.Log = run.Stderr
	var report hostbuild.ReplayReport
	if err := fsutil.ReadJSON(reportPath, &report); err == nil {
		outcome.Report = &report
	}
	outcome.Kind = crashKind(run.Stderr, run.ExitCode, run.Signal, run.TimedOut)
	outcome.Crashed = outcome.Kind != ""
	outcome.Frames, outcome.Source = normalizeFrames(run.Stderr)
	outcome.Signature = outcome.Kind + "|" + strings.Join(outcome.Frames, ";")
	outcome.Origin = classifyOrigin(run.Stderr, outcome.Frames, build)
	return outcome
}

func crashKind(log string, exitCode, signal int, timedOut bool) string {
	if match := invariantLine.FindStringSubmatch(log); match != nil {
		return "invariant:" + strings.TrimSpace(match[1])
	}
	if match := asanLine.FindStringSubmatch(log); match != nil {
		return "address:" + match[1]
	}
	if match := lsanLine.FindStringSubmatch(log); match != nil {
		return "leak:" + match[1]
	}
	if match := ubsanLine.FindStringSubmatch(log); match != nil {
		message := strings.TrimSpace(match[1])
		if idx := strings.Index(message, ":"); idx > 0 {
			message = message[:idx]
		}
		return "undefined:" + message
	}
	if timedOut {
		return "timeout"
	}
	if signal != 0 {
		return fmt.Sprintf("signal:%d", signal)
	}
	if exitCode != 0 {
		return fmt.Sprintf("exit:%d", exitCode)
	}
	return ""
}

func normalizeFrames(log string) ([]string, SourceLoc) {
	var frames []string
	var source SourceLoc
	for _, line := range strings.Split(log, "\n") {
		match := frameLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		fn := match[2]
		file := filepath.Base(match[3])
		lineNo := match[4]
		frames = append(frames, fn+"@"+file+":"+lineNo)
		if source.Func == "" {
			source = SourceLoc{File: file, Line: atoi(lineNo), Func: fn}
		}
		if len(frames) >= 8 {
			break
		}
	}
	return frames, source
}

func classifyOrigin(log string, frames []string, build *hostbuild.Result) string {
	if invariantLine.MatchString(log) {
		return "target_invariant"
	}
	if build.Target != "" && strings.Contains(log, build.Target) {
		return "target_crash"
	}
	adapterNames := map[string]bool{}
	for _, adapter := range build.Adapters {
		adapterNames[filepath.Base(adapter.ReplacementSource)] = true
	}
	targetNames := map[string]bool{}
	for _, dependency := range build.Dependencies {
		targetNames[filepath.Base(dependency)] = true
	}
	for _, frame := range frames {
		file := frame
		if idx := strings.LastIndex(frame, "@"); idx >= 0 {
			file = frame[idx+1:]
		}
		if idx := strings.Index(file, ":"); idx >= 0 {
			file = file[:idx]
		}
		switch {
		case strings.Contains(file, "replay_driver") || strings.HasPrefix(file, "__asan"):
			continue
		case strings.Contains(file, "harness."):
			return "harness_failure"
		case adapterNames[file]:
			return "adapter_failure"
		case targetNames[file]:
			return "target_crash"
		case strings.HasSuffix(file, ".c") || strings.HasSuffix(file, ".cpp") || strings.HasSuffix(file, ".cc"):
			return "target_crash"
		}
	}
	if asanLine.MatchString(log) || ubsanLine.MatchString(log) || lsanLine.MatchString(log) {
		return "unknown"
	}
	return "unknown"
}

func fingerprint(finding Finding, frames []string, profile string) string {
	return fsutil.HashString(strings.Join([]string{
		finding.Kind, finding.Origin, finding.Target, profile, strings.Join(frames, ";"),
	}, "\x00"))
}

func sameFailure(a, b ReplayOutcome) bool {
	if !b.Crashed || a.Kind != b.Kind {
		return false
	}
	if len(a.Frames) == 0 || len(b.Frames) == 0 {
		return true
	}
	return topFunction(a.Frames[0]) == topFunction(b.Frames[0])
}

func topFunction(frame string) string {
	if idx := strings.IndexByte(frame, '@'); idx >= 0 {
		return frame[:idx]
	}
	return frame
}

func minimize(ctx context.Context, cfg *config.Config, build *hostbuild.Result, target string, data []byte, reference ReplayOutcome, diagnostics []diag.Diagnostic) ([]byte, bool, []diag.Diagnostic) {
	if len(data) <= cfg.File.Harness.MinInputBytes+1 {
		return data, false, diagnostics
	}
	current := append([]byte(nil), data...)
	attempts := 0
	const maxAttempts = 300
	for chunk := len(current) / 2; chunk >= 1 && attempts < maxAttempts; chunk /= 2 {
		changed := false
		for start := 0; start+chunk <= len(current) && attempts < maxAttempts; {
			candidate := append([]byte(nil), current[:start]...)
			candidate = append(candidate, current[start+chunk:]...)
			attempts++
			outcome := RunOnce(ctx, cfg, build, candidate, target, "", 20*time.Second)
			if sameFailure(reference, outcome) && len(candidate) >= cfg.File.Harness.MinInputBytes {
				current = candidate
				changed = true
				continue
			}
			start += chunk
		}
		if !changed && chunk == 1 {
			break
		}
	}
	return current, len(current) != len(data), diagnostics
}

func writeFindingArtifacts(ctx context.Context, cfg *config.Config, out *artifacts.Output, build *hostbuild.Result, target planner.TargetPlan, finding *Finding, data []byte, log string) error {
	_ = ctx
	dir := out.FindingDir(finding.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	inputPath := filepath.Join(dir, "input.bin")
	if err := fsutil.WriteFileAtomic(inputPath, data, 0o644); err != nil {
		return err
	}
	logPath := filepath.Join(dir, "sanitizer.log")
	if err := fsutil.WriteFileAtomic(logPath, []byte(log), 0o644); err != nil {
		return err
	}
	finding.InputPath = fsutil.Rel(out.Root, inputPath)
	finding.LogPath = fsutil.Rel(out.Root, logPath)
	finding.InputSHA256 = fsutil.HashBytes(data)
	repro := struct {
		SchemaVersion int          `json:"schema_version"`
		FindingID     string       `json:"finding_id"`
		Reproduction  Reproduction `json:"reproduction"`
		InputSHA256   string       `json:"input_sha256"`
		BuildSHA256   string       `json:"build_manifest_sha256,omitempty"`
		ScopeNote     string       `json:"scope_note"`
	}{
		SchemaVersion: 1,
		FindingID:     finding.ID,
		Reproduction:  finding.Reproduction,
		InputSHA256:   finding.InputSHA256,
		BuildSHA256:   finding.BuildManifestSHA256,
		ScopeNote:     finding.ScopeNote,
	}
	if err := fsutil.WriteJSON(filepath.Join(dir, "repro.json"), repro, true); err != nil {
		return err
	}
	script := replayScript(build, finding, dir)
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "replay.sh"), []byte(script), 0o755); err != nil {
		return err
	}
	return fsutil.WriteJSON(filepath.Join(dir, "finding.json"), finding, true)
}

func replayScript(build *hostbuild.Result, finding *Finding, dir string) string {
	return fmt.Sprintf(`#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")"
expected_input=%s
expected_build=%s
actual_input=$(sha256sum input.bin | awk '{print $1}')
actual_build=$(sha256sum %s | awk '{print $1}')
if [ "$expected_input" != "$actual_input" ]; then
    echo "fuzzfw: input hash mismatch" >&2
    exit 2
fi
if [ -n "$expected_build" ] && [ "$expected_build" != "$actual_build" ]; then
    echo "fuzzfw: self-test binary hash mismatch; rebuild the target" >&2
    exit 2
fi
exec %s --input input.bin --report replay-report.json --entry-symbol %s
`, shQuote(finding.InputSHA256), shQuote(build.SelftestSHA256), shQuote(build.SelftestBinary), shQuote(build.SelftestBinary), shQuote(build.EntrySymbol))
}

func atoi(value string) int {
	result := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			break
		}
		result = result*10 + int(r-'0')
	}
	return result
}

// Baseline records approved finding fingerprints.
type Baseline struct {
	SchemaVersion int             `json:"schema_version"`
	Findings      []BaselineEntry `json:"findings"`
}

// BaselineEntry is one approved finding identity.
type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	ID          string `json:"id,omitempty"`
	Target      string `json:"target,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Origin      string `json:"origin,omitempty"`
}

// LoadBaseline reads a baseline file; nil means no baseline exists.
func LoadBaseline(path string) (*Baseline, error) {
	if path == "" {
		return nil, nil
	}
	var baseline Baseline
	if err := fsutil.ReadJSON(path, &baseline); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if baseline.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported baseline schema version %d", baseline.SchemaVersion)
	}
	return &baseline, nil
}

// WriteBaseline writes an approved baseline.
func WriteBaseline(path string, findings []Finding) error {
	baseline := Baseline{SchemaVersion: 1}
	for _, finding := range findings {
		if finding.Reproduction.Level != "R1_HOST_REPRODUCED" || finding.Reproduction.NonReproducing || finding.Reproduction.Flaky {
			continue
		}
		baseline.Findings = append(baseline.Findings, BaselineEntry{
			Fingerprint: finding.Fingerprint, ID: finding.ID, Target: finding.Target,
			Kind: finding.Kind, Origin: finding.Origin,
		})
	}
	return fsutil.WriteJSON(path, baseline, true)
}

// NewFingerprints returns findings not present in the baseline.
func NewFingerprints(findings []Finding, baseline *Baseline) []Finding {
	if baseline == nil {
		return findings
	}
	known := map[string]bool{}
	for _, entry := range baseline.Findings {
		known[entry.Fingerprint] = true
	}
	var out []Finding
	for _, finding := range findings {
		if !known[finding.Fingerprint] {
			out = append(out, finding)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func findingID(fingerprintValue string) string {
	if len(fingerprintValue) >= 8 {
		return "F" + strings.ToUpper(fingerprintValue[:8])
	}
	return "F" + strings.ToUpper(fingerprintValue)
}

func readLog(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func shQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
