// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package hostbuild compiles original translation units, approved adapters, and
// generated harnesses into native host binaries. It does not copy target code.
package hostbuild

import (
	"context"
	"path/filepath"

	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

// Build status values are part of build-info.json.
const (
	StatusBlocked            = "blocked"
	StatusHarnessBuildFailed = "harness_build_failed"
	StatusSmokeCrashed       = "smoke_crashed"
	StatusEntryUnreached     = "entry_unreached"
	StatusStateLeak          = "state_leak"
	StatusSelftestPassed     = "selftest_passed"
	StatusFuzzable           = "fuzzable"
	StatusNotFuzzable        = "not_fuzzable"
)

// BuildDelta records changes between original and host compilation profiles.
type BuildDelta struct {
	RemovedFlags []string `json:"removed_flags,omitempty"`
	AddedFlags   []string `json:"added_flags,omitempty"`
	Compiler     string   `json:"compiler,omitempty"`
	Sanitizers   []string `json:"sanitizers,omitempty"`
}

// ReplayReport is the JSON emitted by the native replay driver.
type ReplayReport struct {
	SchemaVersion int    `json:"schema_version"`
	InputSize     int    `json:"input_size"`
	GuardsTotal   int    `json:"guards_total"`
	GuardsHit     int    `json:"guards_hit"`
	CoverageHash  string `json:"coverage_hash"`
	EntrySymbol   string `json:"entry_symbol"`
	EntryHit      *bool  `json:"entry_hit"`
}

// CaseResult is one self-test case.
type CaseResult struct {
	Name      string        `json:"name"`
	InputPath string        `json:"input_path"`
	InputSize int           `json:"input_size"`
	ExitCode  int           `json:"exit_code"`
	Signal    int           `json:"signal,omitempty"`
	TimedOut  bool          `json:"timed_out"`
	Report    *ReplayReport `json:"report,omitempty"`
	Sanitizer string        `json:"sanitizer,omitempty"`
	Origin    string        `json:"origin,omitempty"`
	LogTail   string        `json:"log_tail,omitempty"`
	Crash     bool          `json:"crash"`
}

// Selftest is the aggregate of all self-test cases.
type Selftest struct {
	Cases            []CaseResult `json:"cases"`
	DurationSeconds  float64      `json:"duration_seconds"`
	EntryHit         bool         `json:"entry_hit"`
	EntryUnknown     bool         `json:"entry_unknown"`
	Stable           bool         `json:"stable"`
	InputUse         string       `json:"input_use"` // observed, weak_sensitivity, unknown
	DistinctCoverage int          `json:"distinct_coverage"`
	CrashCount       int          `json:"crash_count"`
	CoverageHashes   []string     `json:"coverage_hashes,omitempty"`
}

// Result is the build artifact and self-test record for one target.
type Result struct {
	Target            string                   `json:"target"`
	Status            string                   `json:"status"`
	Classification    string                   `json:"classification"`
	Engine            string                   `json:"engine"`
	EntrySymbol       string                   `json:"entry_symbol,omitempty"`
	HarnessID         string                   `json:"harness_id"`
	HarnessPlanPath   string                   `json:"harness_plan_path"`
	HarnessSourcePath string                   `json:"harness_source_path"`
	HarnessSHA256     string                   `json:"harness_sha256"`
	SelftestBinary    string                   `json:"selftest_binary,omitempty"`
	SelftestSHA256    string                   `json:"selftest_sha256,omitempty"`
	FuzzBinary        string                   `json:"fuzz_binary,omitempty"`
	FuzzSHA256        string                   `json:"fuzz_sha256,omitempty"`
	BuildLog          string                   `json:"build_log"`
	Objects           []string                 `json:"objects,omitempty"`
	Adapters          []planner.AdapterBinding `json:"adapters,omitempty"`
	Dependencies      []string                 `json:"dependencies,omitempty"`
	Delta             BuildDelta               `json:"build_delta"`
	Selftest          Selftest                 `json:"selftest"`
	Diagnostics       []diag.Diagnostic        `json:"diagnostics,omitempty"`
}

// Succeeded reports whether compile and self-test gates passed. Engine
// availability is reported separately by Status.
func (r *Result) Succeeded() bool {
	return r.Status == StatusSelftestPassed || r.Status == StatusFuzzable
}

// Builder compiles one target at a time.
type Builder struct {
	Ctx       context.Context
	Cfg       *config.Config
	DB        *compdb.Database
	Workspace *artifacts.Workspace
	Tools     *toolchain.Report
	Engine    string
}

type buildProfile struct {
	Name         string
	CompilerC    string
	CompilerCXX  string
	CompileFlags []string
	LinkFlags    []string
	NeedReplay   bool
}

func (b *Builder) profiles(target planner.TargetPlan) (selftest buildProfile, fuzz *buildProfile, diagnostics []diag.Diagnostic) {
	sanitizers := sanitizerFlags(b.Cfg)
	base := []string{
		b.Cfg.File.Host.Optimization,
		"-g",
		"-fno-omit-frame-pointer",
		"-fno-common",
	}
	selftest = buildProfile{
		Name:         "selftest",
		CompilerC:    b.Cfg.File.Host.Clang,
		CompilerCXX:  b.Cfg.File.Host.ClangXX,
		CompileFlags: append(append([]string{}, base...), sanitizers...),
		LinkFlags:    append(append([]string{}, sanitizers...), "-Wl,--export-dynamic", "-ldl", "-lm", "-pthread"),
		NeedReplay:   true,
	}
	if b.Cfg.File.Host.Coverage && b.Cfg.File.Host.CoverageMode == "trace-pc-guard" {
		selftest.CompileFlags = append(selftest.CompileFlags, "-fsanitize-coverage=trace-pc-guard")
	}
	switch b.Engine {
	case "replay":
		return selftest, nil, nil
	case "libfuzzer":
		if b.Tools == nil || !b.Tools.LibFuzzerOK {
			diagnostics = append(diagnostics, diag.New(diag.EEngineUnavailable,
				"libFuzzer support is not available in the selected Clang").Warning().WithTarget(target.Name))
			return selftest, nil, diagnostics
		}
		fuzz = &buildProfile{
			Name:         "fuzz-libfuzzer",
			CompilerC:    b.Cfg.File.Host.Clang,
			CompilerCXX:  b.Cfg.File.Host.ClangXX,
			CompileFlags: append(append([]string{}, base...), "-fsanitize=fuzzer-no-link,address,undefined", "-fno-sanitize-recover=all"),
			LinkFlags:    []string{"-fsanitize=fuzzer,address,undefined", "-fno-sanitize-recover=all", "-g", "-fno-omit-frame-pointer", "-ldl", "-lm", "-pthread"},
			NeedReplay:   false,
		}
		return selftest, fuzz, nil
	case "honggfuzz":
		if b.Tools == nil || !b.Tools.Tools["honggfuzz"].Found || !b.Tools.Tools["hfuzz-clang"].Found {
			diagnostics = append(diagnostics, diag.New(diag.EEngineUnavailable,
				"honggfuzz or hfuzz-clang was not found").Warning().WithTarget(target.Name))
			return selftest, nil, diagnostics
		}
		if b.usesCXX(target) && !b.Tools.Tools["hfuzz-clang++"].Found {
			diagnostics = append(diagnostics, diag.New(diag.EEngineUnavailable,
				"hfuzz-clang++ was not found for a C++ target").Warning().WithTarget(target.Name))
			return selftest, nil, diagnostics
		}
		fuzz = &buildProfile{
			Name:         "fuzz-honggfuzz",
			CompilerC:    b.Tools.Tools["hfuzz-clang"].Path,
			CompilerCXX:  b.Tools.Tools["hfuzz-clang++"].Path,
			CompileFlags: append(append([]string{}, base...), sanitizers...),
			LinkFlags:    append(append([]string{}, sanitizers...), "-Wl,--export-dynamic", "-ldl", "-lm", "-pthread"),
			NeedReplay:   false,
		}
		return selftest, fuzz, nil
	default:
		diagnostics = append(diagnostics, diag.Newf(diag.EEngineUnavailable,
			"unknown engine %q", b.Engine).Warning().WithTarget(target.Name))
		return selftest, nil, diagnostics
	}
}

func sanitizerFlags(cfg *config.Config) []string {
	if len(cfg.File.Host.Sanitizers) == 0 {
		return nil
	}
	flags := []string{"-fsanitize=" + joinComma(cfg.File.Host.Sanitizers)}
	flags = append(flags, "-fno-sanitize-recover=all")
	return flags
}

func joinComma(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ","
		}
		out += value
	}
	return out
}

func compilerFor(profile buildProfile, language string) string {
	if language == "c++" {
		return profile.CompilerCXX
	}
	return profile.CompilerC
}

func absJoin(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
