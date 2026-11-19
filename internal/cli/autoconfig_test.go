// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

func TestIsAutoConfig(t *testing.T) {
	if !isAutoConfig(&config.Config{}) {
		t.Fatal("empty config should be auto")
	}
	if isAutoConfig(&config.Config{Path: "fuzzfw.toml"}) {
		t.Fatal("explicit config must not be auto")
	}
	if isAutoConfig(&config.Config{Targets: []config.Target{{Name: "x"}}}) {
		t.Fatal("declared targets must not be auto")
	}
}

func TestSelectAutoEngine(t *testing.T) {
	libfuzzer := &toolchain.Report{LibFuzzerOK: true, Tools: map[string]toolchain.Tool{}}
	if got := selectAutoEngine(libfuzzer); got != "libfuzzer" {
		t.Fatalf("want libfuzzer, got %q", got)
	}

	honggfuzz := &toolchain.Report{Tools: map[string]toolchain.Tool{
		"honggfuzz":   {Found: true},
		"hfuzz-clang": {Found: true},
	}}
	if got := selectAutoEngine(honggfuzz); got != "honggfuzz" {
		t.Fatalf("want honggfuzz, got %q", got)
	}

	if got := selectAutoEngine(&toolchain.Report{Tools: map[string]toolchain.Tool{}}); got != "replay" {
		t.Fatalf("want replay, got %q", got)
	}
}

func TestAutoSeedDirsPrefersSeeds(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"seeds", "corpus"} {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "input"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := autoSeedDirs(root)
	if len(got) != 1 || got[0] != "seeds" {
		t.Fatalf("want [seeds], got %v", got)
	}
}

func TestApplyAutoTargetsMarksReadyCandidates(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "seeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "seeds", "input"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Root: root}
	plan := &planner.Plan{Targets: []planner.TargetPlan{
		{Name: "ready", Classification: planner.ReadyCandidate},
		{Name: "blocked", Classification: planner.Blocked},
	}}
	diagnostics := applyAutoTargets(cfg, plan, nil)
	if len(diagnostics) != 1 {
		t.Fatalf("want one diagnostic, got %d", len(diagnostics))
	}
	if !plan.Targets[0].Required {
		t.Fatal("ready target was not marked required")
	}
	if plan.Targets[1].Required {
		t.Fatal("blocked target must not be marked required")
	}
	if len(plan.Targets[0].Seeds) != 1 || plan.Targets[0].Seeds[0] != "seeds" {
		t.Fatalf("seeds not attached: %v", plan.Targets[0].Seeds)
	}
}
