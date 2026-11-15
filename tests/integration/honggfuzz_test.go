// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

//go:build integration && honggfuzz

package integration

import (
	"os/exec"
	"testing"
)

func requireHonggfuzz(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"honggfuzz", "hfuzz-clang", "hfuzz-clang++"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("honggfuzz toolchain not available: %v", err)
		}
	}
}

func TestHonggfuzzEndToEnd(t *testing.T) {
	requireHonggfuzz(t)
	project := fixture("c_parser")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "honggfuzz",
		"--time", "5s", "--jobs", "1", "--output", out, "--no-minimize", "--quiet")
	if code != 1 {
		t.Fatalf("honggfuzz check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, out+"/summary.json")
	findings := summary["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("honggfuzz run produced no triaged finding")
	}
	finding := findings[0].(map[string]any)
	if finding["origin"] != "target_crash" {
		t.Fatalf("origin = %v", finding["origin"])
	}
}

func TestHonggfuzzDiscoversUnseededCrash(t *testing.T) {
	requireHonggfuzz(t)
	project := fixture("c_vuln")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "honggfuzz",
		"--time", "15s", "--jobs", "2", "--output", out, "--no-minimize", "--quiet")
	if code != 1 {
		t.Fatalf("unseeded honggfuzz check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, out+"/summary.json")
	metrics := summary["metrics"].(map[string]any)
	if metrics["cases_fuzzed"].(float64) < 1 {
		t.Fatalf("no fuzz executions recorded: %v", metrics)
	}
	findings := summary["findings"].([]any)
	if len(findings) == 0 || findings[0].(map[string]any)["origin"] != "target_crash" {
		t.Fatalf("unexpected findings: %v", findings)
	}
}

func TestHonggfuzzCommandDictionaryDiscovery(t *testing.T) {
	requireHonggfuzz(t)
	project := fixture("c_commands")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "honggfuzz",
		"--time", "10s", "--jobs", "2", "--output", out, "--no-minimize", "--quiet")
	if code != 1 {
		t.Fatalf("command discovery check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, out+"/summary.json")
	if summary["metrics"].(map[string]any)["cases_fuzzed"].(float64) < 1 {
		t.Fatalf("no command fuzz executions: %v", summary["metrics"])
	}
}
