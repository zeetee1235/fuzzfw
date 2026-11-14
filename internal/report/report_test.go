// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package report

import (
	"strings"
	"testing"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/triage"
)

func testSummary(t *testing.T, status string, findings []triage.Finding) *Summary {
	t.Helper()
	cfgFile := config.Defaults()
	cfgFile.CI.FailOnNewReproduced = true
	cfg := &config.Config{File: cfgFile}
	return New(Input{
		Command: "check", Config: cfg,
		Project:   ProjectInfo{Name: "p", Root: "/tmp", SourceRevision: "rev"},
		StartedAt: time.Unix(0, 0), FinishedAt: time.Unix(1, 0),
		Targets:  []TargetSummary{{Name: "t", Required: true, Classification: "ready_candidate", Status: status}},
		Findings: findings,
	})
}

func TestSummaryPass(t *testing.T) {
	summary := testSummary(t, "selftest_passed", nil)
	if summary.Status != "pass" || summary.ExitCode != 0 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestSummaryFindingFail(t *testing.T) {
	finding := triage.Finding{
		ID: "F00000001", Fingerprint: "abc", Target: "t", Kind: "address:heap-buffer-overflow", Origin: "target_crash",
		Reproduction: triage.Reproduction{Level: "R1_HOST_REPRODUCED", Success: 3, Attempts: 3},
	}
	summary := testSummary(t, "selftest_passed", []triage.Finding{finding})
	if summary.Status != "fail" || summary.ExitCode != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.Metrics.NewFindingsReproduced != 1 {
		t.Fatalf("metrics = %+v", summary.Metrics)
	}
	data, err := RenderJUnit(summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "reproduced finding") {
		t.Fatalf("junit = %s", data)
	}
}

func TestSummaryBlockedRequiredIncomplete(t *testing.T) {
	summary := testSummary(t, "blocked", nil)
	if summary.Status != "incomplete" || summary.ExitCode != 2 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestMarkdown(t *testing.T) {
	summary := testSummary(t, "selftest_passed", nil)
	text := RenderMarkdown(summary)
	if !strings.Contains(text, "# fuzzfw report") || !strings.Contains(text, "| t | true") {
		t.Fatalf("markdown = %s", text)
	}
}
