// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package toolchain discovers external tools and verifies that required
// compiler features are available.
package toolchain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/proc"
)

// Tool describes one external executable.
type Tool struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Found   bool   `json:"found"`
	Detail  string `json:"detail,omitempty"`
}

// Report is the result of environment discovery.
type Report struct {
	Platform          string          `json:"platform"`
	PythonNotRequired bool            `json:"python_not_required"`
	Tools             map[string]Tool `json:"tools"`
	ClangTarget       string          `json:"clang_target,omitempty"`
	SanitizersOK      bool            `json:"sanitizers_ok"`
	LibFuzzerOK       bool            `json:"libfuzzer_ok"`
	Checks            []Check         `json:"checks"`
}

// Check is a named readiness check.
type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// Detect discovers tools and capabilities. It never fails because a tool is
// missing; callers decide which tools are required.
func Detect(ctx context.Context, cfg *config.Config) *Report {
	report := &Report{
		Platform:          runtime.GOOS + "/" + runtime.GOARCH,
		PythonNotRequired: true,
		Tools:             map[string]Tool{},
	}
	checks := []struct {
		Name    string
		Command string
	}{
		{"clang", cfg.File.Host.Clang},
		{"clang++", cfg.File.Host.ClangXX},
		{"cmake", "cmake"},
		{"ninja", "ninja"},
		{"make", "make"},
		{"git", "git"},
		{"honggfuzz", "honggfuzz"},
		{"hfuzz-clang", "hfuzz-clang"},
		{"hfuzz-clang++", "hfuzz-clang++"},
		{"fuzzfw-analyze", "fuzzfw-analyze"},
		{"fuzzfw-ir-analyze", "fuzzfw-ir-analyze"},
		{"llvm-profdata", "llvm-profdata"},
		{"llvm-cov", "llvm-cov"},
	}
	for _, check := range checks {
		report.Tools[check.Name] = discover(ctx, check.Name, check.Command)
	}
	// Allow the native analyzer to live next to the fuzzfw executable or in
	// the source tree during development.
	for _, name := range []string{"fuzzfw-analyze", "fuzzfw-ir-analyze"} {
		tool := report.Tools[name]
		if !tool.Found {
			if path := findAdjacent(name); path != "" {
				tool = Tool{Name: name, Path: path, Version: proc.Version(ctx, path, "--version"), Found: true}
				report.Tools[name] = tool
			}
		}
	}
	clang := report.Tools["clang"]
	if clang.Found {
		result, _ := proc.RunSimple(ctx, "", 10*time.Second, clang.Path, "-dumpmachine")
		if result != nil {
			report.ClangTarget = strings.TrimSpace(result.Stdout)
		}
	}
	report.SanitizersOK = probeSanitizer(ctx, clang.Path)
	report.LibFuzzerOK = probeLibFuzzer(ctx, clang.Path)
	report.Checks = []Check{
		{Name: "clang", OK: clang.Found, Message: "Clang is required for AST/IR analysis and host builds"},
		{Name: "sanitizers", OK: report.SanitizersOK, Message: "ASan/UBSan support is required for default builds"},
		{Name: "libfuzzer", OK: report.LibFuzzerOK, Message: "Optional libFuzzer adapter; default engine is honggfuzz"},
		{Name: "honggfuzz", OK: report.Tools["honggfuzz"].Found && report.Tools["hfuzz-clang"].Found, Message: "Required only when ci.engine=honggfuzz"},
		{Name: "analyzer", OK: report.Tools["fuzzfw-analyze"].Found, Message: "Native LibTooling analyzer; Go bootstrap analyzer is used when absent"},
	}
	return report
}

func discover(ctx context.Context, name, command string) Tool {
	tool := Tool{Name: name}
	if strings.TrimSpace(command) == "" {
		return tool
	}
	path, err := proc.LookPath(command)
	if err != nil {
		tool.Detail = err.Error()
		return tool
	}
	tool.Path = path
	tool.Found = true
	tool.Version = proc.Version(ctx, path, "--version")
	return tool
}

func findAdjacent(name string) string {
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		for _, candidate := range []string{
			filepath.Join(base, name),
			filepath.Join(base, "analyzer", "build", name),
			filepath.Join(base, "..", "analyzer", "build", name),
		} {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
				return candidate
			}
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		for _, candidate := range []string{
			filepath.Join(cwd, "analyzer", "build", name),
			filepath.Join(cwd, "analyzer", "build", "bin", name),
		} {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
				return candidate
			}
		}
	}
	return ""
}

func probeSanitizer(ctx context.Context, clang string) bool {
	if clang == "" {
		return false
	}
	dir, err := os.MkdirTemp("", "fuzzfw-probe-*")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	source := filepath.Join(dir, "probe.c")
	if err := os.WriteFile(source, []byte("int main(void){return 0;}\n"), 0o644); err != nil {
		return false
	}
	output := filepath.Join(dir, "probe")
	result, err := proc.RunSimple(ctx, dir, 60*time.Second,
		clang, source, "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-o", output)
	return err == nil && result != nil && result.OK()
}

func probeLibFuzzer(ctx context.Context, clang string) bool {
	if clang == "" {
		return false
	}
	dir, err := os.MkdirTemp("", "fuzzfw-libfuzzer-probe-*")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	source := filepath.Join(dir, "probe.c")
	body := "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){(void)d;(void)n;return 0;}\n"
	if err := os.WriteFile(source, []byte(body), 0o644); err != nil {
		return false
	}
	output := filepath.Join(dir, "probe")
	result, err := proc.RunSimple(ctx, dir, 60*time.Second,
		clang, source, "-fsanitize=fuzzer,address", "-o", output)
	return err == nil && result != nil && result.OK()
}

// EngineAvailable reports whether the requested engine can run on this host.
func (r *Report) EngineAvailable(name string) (bool, string) {
	switch name {
	case "replay":
		return true, "replay engine validates corpus and self-test binaries only"
	case "libfuzzer":
		if !r.LibFuzzerOK {
			return false, "clang -fsanitize=fuzzer is not available"
		}
		return true, ""
	case "honggfuzz":
		if !r.Tools["honggfuzz"].Found {
			return false, "honggfuzz executable not found"
		}
		if !r.Tools["hfuzz-clang"].Found {
			return false, "hfuzz-clang wrapper not found"
		}
		return true, ""
	default:
		return false, fmt.Sprintf("unknown engine %q", name)
	}
}

// Hash returns a stable fingerprint of discovered tool paths and versions.
func (r *Report) Hash() string {
	// JSON encoding sorts string map keys, so the map is deterministic.
	hash, _ := fsutil.HashJSON(struct {
		Platform    string          `json:"platform"`
		Tools       map[string]Tool `json:"tools"`
		ClangTarget string          `json:"clang_target,omitempty"`
		Sanitizers  bool            `json:"sanitizers"`
		LibFuzzer   bool            `json:"libfuzzer"`
	}{r.Platform, r.Tools, r.ClangTarget, r.SanitizersOK, r.LibFuzzerOK})
	return hash
}
