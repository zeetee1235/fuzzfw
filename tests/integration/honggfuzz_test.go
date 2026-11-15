// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

//go:build integration && honggfuzz

package integration

import (
	"os/exec"
	"testing"
)

func TestHonggfuzzEndToEnd(t *testing.T) {
	for _, tool := range []string{"honggfuzz", "hfuzz-clang", "hfuzz-clang++"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("honggfuzz toolchain not available: %v", err)
		}
	}
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
