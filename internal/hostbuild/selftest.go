// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package hostbuild

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/harness"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/proc"
)

var (
	asanPattern      = regexp.MustCompile(`AddressSanitizer: ([A-Za-z0-9_-]+)`)
	lsanPattern      = regexp.MustCompile(`LeakSanitizer: ([A-Za-z0-9_-]+)`)
	ubsanPattern     = regexp.MustCompile(`runtime error: ([^\n]+)`)
	invariantPattern = regexp.MustCompile(`fuzzfw invariant violated:\s*([^\n]+)`)
)

type selftestCase struct {
	name  string
	path  string
	input []byte
}

func (b *Builder) runSelftest(target planner.TargetPlan, hp *harness.Plan, binary, buildDir string) (Selftest, []diag.Diagnostic) {
	result := Selftest{Stable: true, InputUse: "unknown"}
	selftestStarted := time.Now()
	defer func() { result.DurationSeconds = time.Since(selftestStarted).Seconds() }()
	var diagnostics []diag.Diagnostic
	casesDir := filepath.Join(buildDir, "cases")
	if err := os.MkdirAll(casesDir, 0o755); err != nil {
		diagnostics = append(diagnostics, diag.Newf(diag.EInternal, "cannot create self-test case dir: %v", err).WithTarget(target.Name))
		return result, diagnostics
	}
	cases := b.selftestCases(target, casesDir)
	if len(cases) == 0 {
		diagnostics = append(diagnostics, diag.New(diag.EHarnessSmoke,
			"no self-test inputs are available").WithTarget(target.Name))
		return result, diagnostics
	}
	entrySymbol := hp.Target.LinkSymbol
	if entrySymbol == "" {
		entrySymbol = hp.Target.CallSymbol
	}
	timeout := 20 * time.Second
	if b.Cfg.File.Host.TimeoutSeconds < 20 {
		timeout = time.Duration(b.Cfg.File.Host.TimeoutSeconds) * time.Second
	}
	seenCoverage := map[string]bool{}
	for _, testCase := range cases {
		reportPath := filepath.Join(casesDir, fsutil.SafeName(testCase.name, "case")+".report.json")
		_ = os.Remove(reportPath)
		argv := []string{binary, "--input", testCase.path, "--report", reportPath, "--entry-symbol", entrySymbol}
		run, err := (proc.Runner{Timeout: timeout}).Run(b.Ctx, b.Cfg.Root, argv...)
		if err != nil {
			diagnostics = append(diagnostics, diag.Newf(diag.EHarnessSmoke,
				"cannot execute self-test binary: %v", err).WithTarget(target.Name))
			return result, diagnostics
		}
		caseResult := CaseResult{
			Name:      testCase.name,
			InputPath: fsutil.Rel(b.Cfg.Root, testCase.path),
			InputSize: len(testCase.input),
			ExitCode:  run.ExitCode,
			Signal:    run.Signal,
			TimedOut:  run.TimedOut,
			LogTail:   tail(run.Stderr, 4096),
		}
		if report, err := readReplayReport(reportPath); err == nil {
			caseResult.Report = report
			if report.EntryHit != nil && *report.EntryHit {
				result.EntryHit = true
			}
			if report.CoverageHash != "" {
				seenCoverage[report.CoverageHash] = true
			}
			if report.Frames > result.Frames {
				result.Frames = report.Frames
			}
			if report.Frames > 0 && report.StateHash != "" {
				result.StateHash = report.StateHash
			}
		}
		caseResult.Sanitizer = sanitizerKind(run.Stderr)
		caseResult.Crash = run.ExitCode != 0 || run.Signal != 0 || run.TimedOut || caseResult.Sanitizer != ""
		if caseResult.Crash {
			caseResult.Origin = classifyOrigin(run.Stderr, target)
			result.CrashCount++
		}
		result.Cases = append(result.Cases, caseResult)
	}
	result.DistinctCoverage = len(seenCoverage)
	for hash := range seenCoverage {
		result.CoverageHashes = append(result.CoverageHashes, hash)
	}
	sort.Strings(result.CoverageHashes)
	if !result.EntryHit && result.DistinctCoverage == 0 {
		result.EntryUnknown = true
	}
	if result.DistinctCoverage > 1 {
		result.InputUse = "weak_sensitivity"
	}
	if rolesObserveInput(target.Roles) {
		result.InputUse = "observed"
	}
	if result.InputUse == "unknown" {
		diagnostics = append(diagnostics, diag.New(diag.WInputSensitivity,
			"input consumption is not directly observed; coverage equality alone is not proof of non-use",
		).Warning().WithTarget(target.Name))
	}

	// Persistent reset probe: call the same input multiple times inside one
	// process and compare per-iteration coverage. This is the gate required
	// before persistent engine mode can be trusted for a target.
	if b.Cfg.File.Harness.PersistentResetCheck && b.Cfg.File.Host.Coverage {
		if probeCase, ok := persistentProbeCase(result.Cases); ok {
			reportPath := filepath.Join(casesDir, "persistent.report.json")
			_ = os.Remove(reportPath)
			argv := []string{binary, "--input", absJoin(b.Cfg.Root, probeCase.InputPath),
				"--report", reportPath, "--entry-symbol", entrySymbol, "--iterations", "3"}
			probeRun, probeErr := (proc.Runner{Timeout: timeout}).Run(b.Ctx, b.Cfg.Root, argv...)
			report, readErr := readReplayReport(reportPath)
			if probeErr != nil || readErr != nil || probeRun.ExitCode != 0 || len(report.Iterations) < 2 {
				result.Stable = false
				message := "persistent reset probe could not complete"
				if probeErr != nil {
					message += ": " + probeErr.Error()
				} else if probeRun != nil {
					message += fmt.Sprintf(" (exit %d)", probeRun.ExitCode)
				}
				diagnostics = append(diagnostics, diag.New(diag.EStateLeak, message).WithTarget(target.Name))
			} else {
				result.PersistentChecked = true
				result.PersistentStable = true
				// The first call may perform legitimate one-time C++/runtime
				// initialization. Compare the warm iterations; a per-call
				// state leak still changes the hash.
				baseline := report.Iterations[1]
				for index, iteration := range report.Iterations {
					result.PersistentHashes = append(result.PersistentHashes, iteration.CoverageHash)
					if index == 0 {
						continue
					}
					if iteration.CoverageHash != baseline.CoverageHash {
						result.PersistentStable = false
					}
					if (iteration.EntryHit == nil) != (baseline.EntryHit == nil) ||
						(iteration.EntryHit != nil && baseline.EntryHit != nil && *iteration.EntryHit != *baseline.EntryHit) {
						result.PersistentStable = false
					}
				}
				if !result.PersistentStable {
					result.Stable = false
					diagnostics = append(diagnostics, diag.New(diag.EStateLeak,
						"persistent reset probe produced different coverage across repeated calls",
					).WithTarget(target.Name))
				}
			}
		}
	}

	// Stability: repeat the first non-crashing case in a fresh process.
	for _, caseResult := range result.Cases {
		if caseResult.Crash || caseResult.Report == nil {
			continue
		}
		reportPath := filepath.Join(casesDir, fsutil.SafeName(caseResult.Name, "case")+".repeat.report.json")
		_ = os.Remove(reportPath)
		inputPath := absJoin(b.Cfg.Root, caseResult.InputPath)
		argv := []string{binary, "--input", inputPath, "--report", reportPath, "--entry-symbol", entrySymbol}
		repeat, err := (proc.Runner{Timeout: timeout}).Run(b.Ctx, b.Cfg.Root, argv...)
		if err != nil {
			break
		}
		report, readErr := readReplayReport(reportPath)
		if readErr != nil || repeat.ExitCode != caseResult.ExitCode || repeat.Signal != caseResult.Signal {
			result.Stable = false
			break
		}
		if report.CoverageHash != caseResult.Report.CoverageHash {
			result.Stable = false
			break
		}
		break
	}
	if result.CrashCount > 0 {
		diagnostics = append(diagnostics, diag.Newf(diag.EHarnessSmoke,
			"self-test observed %d crashing case(s); target/adapter/harness origin is recorded per case",
			result.CrashCount,
		).WithTarget(target.Name))
	}
	if result.EntryUnknown {
		diagnostics = append(diagnostics, diag.New(diag.EEntryUnreached,
			"entry reachability could not be measured (coverage disabled)",
		).WithTarget(target.Name))
	} else if !result.EntryHit {
		diagnostics = append(diagnostics, diag.New(diag.EEntryUnreached,
			"target entry was not reached by any self-test input",
		).WithTarget(target.Name))
	}
	if !result.Stable {
		diagnostics = append(diagnostics, diag.New(diag.EStateLeak,
			"self-test was not reproducible across isolated repeats",
		).WithTarget(target.Name))
	}
	return result, diagnostics
}

func (b *Builder) selftestCases(target planner.TargetPlan, casesDir string) []selftestCase {
	maxInput := target.MaxInputBytes
	if maxInput <= 0 {
		maxInput = b.Cfg.File.Harness.MaxInputBytes
	}
	var cases []selftestCase
	seen := map[string]bool{}
	add := func(name string, data []byte) {
		if seen[name] {
			return
		}
		seen[name] = true
		path := filepath.Join(casesDir, fsutil.SafeName(name, "case")+".bin")
		if err := fsutil.WriteFileAtomic(path, data, 0o644); err != nil {
			return
		}
		cases = append(cases, selftestCase{name: name, path: path, input: data})
	}
	add("empty", nil)
	for index, seed := range target.Seeds {
		path := absJoin(b.Cfg.Root, seed)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(data) > maxInput {
			data = data[:maxInput]
		}
		add(fmt.Sprintf("seed-%02d", index), data)
	}
	add("zero", []byte{0})
	add("ff", []byte{0xff})
	size := 64
	if maxInput < size {
		size = maxInput
	}
	if size < 1 {
		size = 1
	}
	pattern := make([]byte, size)
	for i := range pattern {
		pattern[i] = byte(i % 251)
	}
	add("pattern", pattern)
	return cases
}

func readReplayReport(path string) (*ReplayReport, error) {
	var report ReplayReport
	if err := fsutil.ReadJSON(path, &report); err != nil {
		return nil, err
	}
	if report.SchemaVersion != 1 {
		return nil, fmt.Errorf("unexpected replay report schema %d", report.SchemaVersion)
	}
	return &report, nil
}

func sanitizerKind(log string) string {
	if match := asanPattern.FindStringSubmatch(log); match != nil {
		return "address:" + match[1]
	}
	if match := lsanPattern.FindStringSubmatch(log); match != nil {
		return "leak:" + match[1]
	}
	if match := ubsanPattern.FindStringSubmatch(log); match != nil {
		message := strings.TrimSpace(match[1])
		if idx := strings.Index(message, ":"); idx > 0 {
			message = message[:idx]
		}
		return "undefined:" + message
	}
	if strings.Contains(log, "UndefinedBehaviorSanitizer") {
		return "undefined"
	}
	return ""
}

func classifyOrigin(log string, target planner.TargetPlan) string {
	if invariantPattern.MatchString(log) {
		return "target_invariant"
	}
	if strings.Contains(log, target.Name) || (target.Source != "" && strings.Contains(log, filepath.Base(target.Source))) {
		return "target_crash"
	}
	for _, adapter := range target.Adapters {
		if strings.Contains(log, filepath.Base(adapter.ReplacementSource)) {
			return "adapter_failure"
		}
	}
	if strings.Contains(log, "harness.c") || strings.Contains(log, "harness.cpp") {
		return "harness_failure"
	}
	for _, dependency := range target.Dependencies {
		if strings.Contains(log, filepath.Base(dependency)) {
			return "target_crash"
		}
	}
	if target.Source != "" && strings.Contains(log, filepath.Base(target.Source)) {
		return "target_crash"
	}
	if sanitizerKind(log) != "" {
		return "unknown"
	}
	return "unknown"
}

func rolesObserveInput(roles []planner.RoleBinding) bool {
	for _, role := range roles {
		for _, evidence := range role.Evidence {
			if evidence == "ir:memory_read" || evidence == "ir:passed_to_call" {
				return true
			}
		}
	}
	return false
}

func tail(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[len(text)-limit:]
}

func persistentProbeCase(cases []CaseResult) (CaseResult, bool) {
	for _, item := range cases {
		if !item.Crash && item.Report != nil && item.InputSize > 0 {
			return item, true
		}
	}
	for _, item := range cases {
		if !item.Crash && item.Report != nil {
			return item, true
		}
	}
	return CaseResult{}, false
}
