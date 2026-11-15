// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package report produces the stable summary.json, JUnit XML, and Markdown
// artifacts used by CI and by humans.
package report

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/triage"
	"github.com/fuzzfw/fuzzfw/internal/version"
)

// SchemaVersion is the summary.json schema.
const SchemaVersion = 1

// ToolInfo identifies the generator.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// ProjectInfo identifies the scanned project.
type ProjectInfo struct {
	Name           string `json:"name"`
	Root           string `json:"root"`
	SourceRevision string `json:"source_revision"`
}

// Metrics are the CI metrics defined by the specification.
type Metrics struct {
	TargetsTotal          int     `json:"targets_total"`
	TargetsRequired       int     `json:"targets_required"`
	TargetsBuilt          int     `json:"targets_built"`
	TargetsSelftestPassed int     `json:"targets_selftest_passed"`
	TargetsExecuted       int     `json:"targets_executed"`
	TargetsBlocked        int     `json:"targets_blocked"`
	CasesReplayed         int     `json:"cases_replayed"`
	CasesFuzzed           int     `json:"cases_fuzzed"`
	NewFindingsReproduced int     `json:"new_findings_reproduced"`
	FlakyFindings         int     `json:"flaky_findings"`
	HarnessFailures       int     `json:"harness_failures"`
	AnalysisSeconds       float64 `json:"analysis_seconds"`
	BuildSeconds          float64 `json:"build_seconds"`
	SelftestSeconds       float64 `json:"selftest_seconds"`
	FuzzSeconds           float64 `json:"fuzz_seconds"`
	TriageSeconds         float64 `json:"triage_seconds"`
}

// AdapterSummary is a compact adapter record.
type AdapterSummary struct {
	OriginalSymbol string   `json:"original_symbol"`
	Source         string   `json:"source"`
	Model          string   `json:"model"`
	Limitations    []string `json:"limitations,omitempty"`
}

// TargetSummary records one target's gate results.
type TargetSummary struct {
	Name                string            `json:"name"`
	Required            bool              `json:"required"`
	Classification      string            `json:"classification"`
	Status              string            `json:"status"`
	Engine              string            `json:"engine,omitempty"`
	HarnessID           string            `json:"harness_id,omitempty"`
	SelftestBinary      string            `json:"selftest_binary,omitempty"`
	FuzzBinary          string            `json:"fuzz_binary,omitempty"`
	EntryHit            bool              `json:"entry_hit"`
	InputUse            string            `json:"input_use,omitempty"`
	Stability           string            `json:"stability,omitempty"`
	Dependencies        []string          `json:"required_translation_units,omitempty"`
	Adapters            []AdapterSummary  `json:"adapters,omitempty"`
	CorpusInputs        int               `json:"corpus_inputs,omitempty"`
	CorpusSelected      int               `json:"corpus_selected,omitempty"`
	CorpusRemoved       int               `json:"corpus_removed,omitempty"`
	InputsWithData      int               `json:"inputs_with_frames,omitempty"`
	CorpusFrames        uint64            `json:"corpus_frames,omitempty"`
	DistinctStates      int               `json:"distinct_states,omitempty"`
	StateHashes         []string          `json:"state_hashes,omitempty"`
	DistinctTransitions int               `json:"distinct_transitions,omitempty"`
	Transitions         []string          `json:"transitions,omitempty"`
	CommandConstants    int               `json:"command_constants,omitempty"`
	CommandsCovered     int               `json:"commands_covered,omitempty"`
	FindingIDs          []string          `json:"finding_ids,omitempty"`
	Diagnostics         []diag.Diagnostic `json:"diagnostics,omitempty"`
}

// FindingRecord adds baseline status to a finding.
type FindingRecord struct {
	triage.Finding
	New bool `json:"new"`
}

// ArtifactPaths lists stable outputs.
type ArtifactPaths struct {
	Summary     string `json:"summary"`
	JUnit       string `json:"junit"`
	BuildInfo   string `json:"build_info"`
	Diagnostics string `json:"diagnostics"`
	Corpus      string `json:"corpus"`
	Findings    string `json:"findings"`
	Baseline    string `json:"baseline,omitempty"`
}

// Summary is fuzzfw-out/summary.json.
type Summary struct {
	SchemaVersion     int               `json:"schema_version"`
	Tool              ToolInfo          `json:"tool"`
	Command           string            `json:"command"`
	StartedAt         string            `json:"started_at"`
	FinishedAt        string            `json:"finished_at"`
	DurationSeconds   float64           `json:"duration_seconds"`
	Status            string            `json:"status"`
	ExitCode          int               `json:"exit_code"`
	Reason            string            `json:"reason"`
	Project           ProjectInfo       `json:"project"`
	ConfigFingerprint string            `json:"config_fingerprint"`
	Metrics           Metrics           `json:"metrics"`
	Targets           []TargetSummary   `json:"targets"`
	Findings          []FindingRecord   `json:"findings"`
	Diagnostics       []diag.Diagnostic `json:"diagnostics,omitempty"`
	Artifacts         ArtifactPaths     `json:"artifacts"`
}

// Input is the runtime data used to compose a summary.
type Input struct {
	Command         string
	Config          *config.Config
	Project         ProjectInfo
	StartedAt       time.Time
	FinishedAt      time.Time
	AnalysisSeconds float64
	BuildSeconds    float64
	SelftestSeconds float64
	FuzzSeconds     float64
	TriageSeconds   float64
	Targets         []TargetSummary
	Findings        []triage.Finding
	Baseline        *triage.Baseline
	Diagnostics     []diag.Diagnostic
	CasesReplayed   int
	CasesFuzzed     int
	Artifacts       ArtifactPaths
}

// New composes a summary and computes the CI verdict.
func New(input Input) *Summary {
	summary := &Summary{
		SchemaVersion:   SchemaVersion,
		Tool:            ToolInfo{Name: "fuzzfw", Version: version.Version, Commit: version.Commit},
		Command:         input.Command,
		StartedAt:       fsutil.FormatUTC(input.StartedAt),
		FinishedAt:      fsutil.FormatUTC(input.FinishedAt),
		DurationSeconds: input.FinishedAt.Sub(input.StartedAt).Seconds(),
		Project:         input.Project,
		Targets:         input.Targets,
		Diagnostics:     input.Diagnostics,
		Artifacts:       input.Artifacts,
		Metrics: Metrics{
			AnalysisSeconds: input.AnalysisSeconds,
			BuildSeconds:    input.BuildSeconds,
			SelftestSeconds: input.SelftestSeconds,
			FuzzSeconds:     input.FuzzSeconds,
			TriageSeconds:   input.TriageSeconds,
			CasesReplayed:   input.CasesReplayed,
			CasesFuzzed:     input.CasesFuzzed,
		},
	}
	if input.Config != nil {
		summary.ConfigFingerprint = input.Config.Fingerprint
	}
	baseline := input.Baseline
	newFindings := triage.NewFingerprints(input.Findings, baseline)
	newSet := map[string]bool{}
	for _, finding := range newFindings {
		newSet[finding.Fingerprint] = true
	}
	for _, finding := range input.Findings {
		summary.Findings = append(summary.Findings, FindingRecord{Finding: finding, New: newSet[finding.Fingerprint]})
	}
	sort.Slice(summary.Findings, func(i, j int) bool {
		return summary.Findings[i].Fingerprint < summary.Findings[j].Fingerprint
	})
	if summary.Findings == nil {
		summary.Findings = []FindingRecord{}
	}
	if summary.Targets == nil {
		summary.Targets = []TargetSummary{}
	}
	for index := range summary.Targets {
		for _, finding := range summary.Findings {
			if finding.Target != summary.Targets[index].Name {
				continue
			}
			found := false
			for _, id := range summary.Targets[index].FindingIDs {
				if id == finding.ID {
					found = true
					break
				}
			}
			if !found {
				summary.Targets[index].FindingIDs = append(summary.Targets[index].FindingIDs, finding.ID)
			}
		}
	}
	summary.Metrics.TargetsTotal = len(summary.Targets)
	for _, target := range summary.Targets {
		if target.Required {
			summary.Metrics.TargetsRequired++
		}
		switch target.Status {
		case "fuzzable", "selftest_passed":
			summary.Metrics.TargetsBuilt++
			summary.Metrics.TargetsSelftestPassed++
			summary.Metrics.TargetsExecuted++
		case "blocked":
			summary.Metrics.TargetsBlocked++
		case "harness_build_failed", "smoke_crashed", "entry_unreached", "state_leak", "not_fuzzable":
			summary.Metrics.TargetsBuilt++
		}
	}
	for _, finding := range summary.Findings {
		if finding.Reproduction.NonReproducing || finding.Reproduction.Flaky {
			summary.Metrics.FlakyFindings++
		}
		if finding.Origin == "harness_failure" || finding.Origin == "adapter_failure" {
			summary.Metrics.HarnessFailures++
		}
		if finding.New && finding.Reproduction.Level == "R1_HOST_REPRODUCED" &&
			(finding.Origin == "target_crash" || finding.Origin == "target_invariant") {
			summary.Metrics.NewFindingsReproduced++
		}
	}
	summary.Status = "pass"
	summary.ExitCode = exitcode.OK
	summary.Reason = "all required targets completed and no failing new reproduced finding"
	var incompleteReasons []string
	for _, target := range summary.Targets {
		ok := target.Status == "fuzzable" || target.Status == "selftest_passed"
		if target.Required && !ok {
			incompleteReasons = append(incompleteReasons, fmt.Sprintf("%s: %s", target.Name, target.Status))
		}
	}
	if len(incompleteReasons) > 0 {
		summary.Status = "incomplete"
		summary.ExitCode = exitcode.Incomplete
		summary.Reason = "required targets did not complete: " + strings.Join(incompleteReasons, ", ")
	}
	if summary.Metrics.NewFindingsReproduced > 0 {
		summary.Status = "fail"
		summary.ExitCode = exitcode.Findings
		summary.Reason = fmt.Sprintf("%d new host-reproduced target finding(s)", summary.Metrics.NewFindingsReproduced)
	} else if summary.Metrics.HarnessFailures > 0 {
		summary.Status = "incomplete"
		summary.ExitCode = exitcode.Incomplete
		summary.Reason = "reproduced harness/adapter failure; not promoted to a product finding"
	}
	if input.Config != nil {
		if !input.Config.File.CI.FailOnNewReproduced && summary.Metrics.NewFindingsReproduced > 0 {
			summary.Status = "pass"
			summary.ExitCode = exitcode.OK
			summary.Reason = "new reproduced findings are allowed by ci.fail_on_new_reproduced=false"
		}
		if !input.Config.File.CI.IncompleteIsFailure && summary.Status == "incomplete" && summary.Metrics.NewFindingsReproduced == 0 {
			summary.Status = "pass"
			summary.ExitCode = exitcode.OK
			summary.Reason = "incomplete checks are allowed by ci.incomplete_is_failure=false"
		}
	}
	return summary
}

// Write writes summary.json, junit.xml, summary.md, and diagnostics.json.
func Write(summary *Summary, out *artifacts.Output) error {
	if err := out.Ensure(); err != nil {
		return err
	}
	if err := fsutil.WriteJSON(out.Summary, summary, true); err != nil {
		return err
	}
	if err := fsutil.WriteJSON(out.Diagnostics, summary.Diagnostics, true); err != nil {
		return err
	}
	if err := WriteJUnit(summary, out.JUnit); err != nil {
		return err
	}
	return WriteMarkdown(summary, filepath.Join(out.Root, "summary.md"))
}

// WriteJUnit emits CI-standard JUnit XML.
func WriteJUnit(summary *Summary, path string) error {
	data, err := RenderJUnit(summary)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0o644)
}

// RenderJUnit returns the JUnit XML bytes.
func RenderJUnit(summary *Summary) ([]byte, error) {
	suite := testsuite{
		Name:     "fuzzfw",
		Tests:    len(summary.Targets),
		Failures: 0,
		Errors:   0,
		Skipped:  0,
		Time:     fmt.Sprintf("%.3f", summary.DurationSeconds),
	}
	for _, target := range summary.Targets {
		testCase := testcase{
			ClassName: "fuzzfw.target",
			Name:      target.Name,
			Time:      "0",
			SystemOut: targetSystemOut(target),
		}
		switch {
		case target.Status == "fuzzable" || target.Status == "selftest_passed":
			if len(target.FindingIDs) > 0 {
				testCase.Failure = &failure{
					Message: "reproduced finding(s): " + strings.Join(target.FindingIDs, ", "),
					Body:    targetSystemOut(target),
				}
				suite.Failures++
			}
		case target.Status == "blocked" && !target.Required:
			testCase.Skipped = &skipped{Message: "blocked (optional target)"}
			suite.Skipped++
		case !target.Required && target.Status == "planned":
			testCase.Skipped = &skipped{Message: "optional target not built by this check"}
			suite.Skipped++
		case target.Status == "blocked":
			testCase.Error = &junitError{Message: "required target blocked", Body: targetSystemOut(target)}
			suite.Errors++
		default:
			testCase.Error = &junitError{Message: "target did not complete: " + target.Status, Body: targetSystemOut(target)}
			suite.Errors++
		}
		suite.Cases = append(suite.Cases, testCase)
	}
	suites := testsuites{
		XMLName:  xml.Name{Local: "testsuites"},
		Name:     "fuzzfw",
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Errors:   suite.Errors,
		Skipped:  suite.Skipped,
		Suites:   []testsuite{suite},
	}
	data, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append([]byte(xml.Header), data...)
	return append(data, '\n'), nil
}

// WriteMarkdown emits a concise human report.
func WriteMarkdown(summary *Summary, path string) error {
	return fsutil.WriteFileAtomic(path, []byte(RenderMarkdown(summary)), 0o644)
}

// RenderMarkdown returns the human report.
func RenderMarkdown(summary *Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# fuzzfw report\n\n")
	fmt.Fprintf(&b, "- Status: **%s** (exit %d)\n", summary.Status, summary.ExitCode)
	fmt.Fprintf(&b, "- Project: `%s` revision `%s`\n", summary.Project.Name, summary.Project.SourceRevision)
	fmt.Fprintf(&b, "- Duration: %.2fs; analysis %.2fs; build %.2fs; fuzz %.2fs; triage %.2fs\n",
		summary.DurationSeconds, summary.Metrics.AnalysisSeconds, summary.Metrics.BuildSeconds,
		summary.Metrics.FuzzSeconds, summary.Metrics.TriageSeconds)
	fmt.Fprintf(&b, "- Reason: %s\n\n", summary.Reason)
	fmt.Fprintf(&b, "## Targets\n\n| Target | Required | Classification | Status | Entry | Input use | Findings |\n")
	fmt.Fprintf(&b, "|---|---:|---|---|---:|---|---|\n")
	for _, target := range summary.Targets {
		fmt.Fprintf(&b, "| %s | %t | %s | %s | %t | %s | %s |\n",
			target.Name, target.Required, target.Classification, target.Status,
			target.EntryHit, target.InputUse, strings.Join(target.FindingIDs, ", "))
	}
	fmt.Fprintf(&b, "\n## Findings\n\n")
	if len(summary.Findings) == 0 {
		fmt.Fprintf(&b, "No findings.\n")
	} else {
		fmt.Fprintf(&b, "| ID | Target | Kind | Origin | Repro | New |\n|---|---|---|---|---|---:|\n")
		for _, finding := range summary.Findings {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s (%d/%d) | %t |\n",
				finding.ID, finding.Target, finding.Kind, finding.Origin,
				finding.Reproduction.Level, finding.Reproduction.Success,
				finding.Reproduction.Attempts, finding.New)
		}
	}
	fmt.Fprintf(&b, "\n## Diagnostics\n\n")
	if len(summary.Diagnostics) == 0 {
		fmt.Fprintf(&b, "None.\n")
	} else {
		for _, diagnostic := range summary.Diagnostics {
			fmt.Fprintf(&b, "- `%s` %s\n", diagnostic.Code, diagnostic.Message)
		}
	}
	return b.String()
}

type testsuites struct {
	XMLName  xml.Name    `xml:"testsuites"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Suites   []testsuite `xml:"testsuite"`
}

type testsuite struct {
	Name     string     `xml:"name,attr"`
	Tests    int        `xml:"tests,attr"`
	Failures int        `xml:"failures,attr"`
	Errors   int        `xml:"errors,attr"`
	Skipped  int        `xml:"skipped,attr"`
	Time     string     `xml:"time,attr"`
	Cases    []testcase `xml:"testcase"`
}

type testcase struct {
	ClassName string      `xml:"classname,attr"`
	Name      string      `xml:"name,attr"`
	Time      string      `xml:"time,attr"`
	Failure   *failure    `xml:"failure,omitempty"`
	Error     *junitError `xml:"error,omitempty"`
	Skipped   *skipped    `xml:"skipped,omitempty"`
	SystemOut string      `xml:"system-out,omitempty"`
}

type failure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type junitError struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type skipped struct {
	Message string `xml:"message,attr"`
}

func targetSystemOut(target TargetSummary) string {
	var parts []string
	parts = append(parts, "classification="+target.Classification, "status="+target.Status,
		fmt.Sprintf("entry_hit=%t", target.EntryHit), "input_use="+target.InputUse)
	for _, diagnostic := range target.Diagnostics {
		parts = append(parts, diagnostic.Code+": "+diagnostic.Message)
	}
	return strings.Join(parts, "\n")
}

// Load reads summary.json.
func Load(path string) (*Summary, error) {
	var summary Summary
	if err := fsutil.ReadJSON(path, &summary); err != nil {
		return nil, err
	}
	if summary.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported summary schema version %d", summary.SchemaVersion)
	}
	return &summary, nil
}
