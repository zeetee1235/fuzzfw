// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package diag provides structured, stable diagnostics and diagnostic codes.
package diag

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Severity is the user-facing importance of a diagnostic.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Diagnostic codes are part of the public contract. Adding a code is
// backwards compatible; changing the meaning of an existing code requires a
// schema version bump.
const (
	EConfigInvalid      = "E_CONFIG_INVALID"
	EConfigNotFound     = "E_CONFIG_NOT_FOUND"
	EUsage              = "E_USAGE"
	ETargetNotFound     = "E_TARGET_NOT_FOUND"
	ETargetRequiredNone = "E_TARGET_REQUIRED_NONE"
	ECompDBMissing      = "E_COMPDB_MISSING"
	ECompDBInvalid      = "E_COMPDB_INVALID"
	ESourceMissing      = "E_SOURCE_MISSING"
	EASTParse           = "E_AST_PARSE"
	EIRUnavailable      = "E_IR_UNAVAILABLE"
	EIRMapAmbiguous     = "E_IR_MAP_AMBIGUOUS"
	EAnalysisIncomplete = "E_ANALYSIS_INCOMPLETE"
	EAnalysisBudget     = "E_ANALYSIS_BUDGET"
	ERoleAmbiguous      = "E_HARNESS_ROLE_AMBIGUOUS"
	EContextUnknown     = "E_HARNESS_CONTEXT_UNKNOWN"
	EHarnessBuild       = "E_HARNESS_BUILD"
	EHarnessSmoke       = "E_HARNESS_SMOKE"
	EHarnessSource      = "E_HARNESS_SOURCE_MISSING"
	EContextInvalid     = "E_CONTEXT_INVALID"
	EDMAUnmodeled       = "E_DMA_UNMODELED"
	EStateLeak          = "E_STATE_LEAK"
	EEntryUnreached     = "E_ENTRY_UNREACHED"
	EInputNotObserved   = "E_INPUT_NOT_OBSERVED"
	ELinkGraphUnknown   = "E_LINK_GRAPH_UNKNOWN"
	EHALUnmodeled       = "E_HAL_UNMODELED"
	EMMIODirect         = "E_MMIO_DIRECT"
	EABIMismatch        = "E_ABI_MISMATCH"
	EAdapterInvalid     = "E_ADAPTER_INVALID"
	EAdapterTrivial     = "E_ADAPTER_TRIVIAL"
	EEngineUnavailable  = "E_ENGINE_UNAVAILABLE"
	EEngineFailed       = "E_ENGINE_FAILED"
	ETimeoutInfra       = "E_TIMEOUT_INFRA"
	ERequiredNotRun     = "E_REQUIRED_NOT_RUN"
	EBaselineMissing    = "E_BASELINE_MISSING"
	EArtifactInvalid    = "E_ARTIFACT_INVALID"
	EInternal           = "E_INTERNAL"
	WIRFallback         = "W_IR_FALLBACK"
	WABIHostOnly        = "W_ABI_HOST_ONLY"
	WInputSensitivity   = "W_INPUT_SENSITIVITY_UNKNOWN"
	WBuildDelta         = "W_BUILD_DELTA"
	WConfigUnknownKey   = "W_CONFIG_UNKNOWN_KEY"
	ITargetBlocked      = "I_TARGET_BLOCKED"
	WAutoconfig         = "W_AUTOCONFIG"
	InfoRecovery        = "I_BASELINE_BOOTSTRAPPED"
	WARNativeAnalyzer   = "W_NATIVE_ANALYZER_FALLBACK"
)

// Diagnostic is a machine-readable explanation for a plan or run decision.
type Diagnostic struct {
	Code        string         `json:"code"`
	Severity    Severity       `json:"severity"`
	Message     string         `json:"message"`
	Target      string         `json:"target,omitempty"`
	Evidence    []string       `json:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// New constructs an error diagnostic.
func New(code, message string) Diagnostic {
	return Diagnostic{Code: code, Severity: SeverityError, Message: message}
}

// Newf constructs a formatted error diagnostic.
func Newf(code, format string, args ...any) Diagnostic {
	return New(code, fmt.Sprintf(format, args...))
}

// WithTarget adds target context.
func (d Diagnostic) WithTarget(target string) Diagnostic {
	d.Target = target
	return d
}

// WithEvidence adds evidence strings.
func (d Diagnostic) WithEvidence(evidence ...string) Diagnostic {
	d.Evidence = append(d.Evidence, evidence...)
	return d
}

// WithRemediation adds a remediation hint.
func (d Diagnostic) WithRemediation(remediation string) Diagnostic {
	d.Remediation = remediation
	return d
}

// WithDetails adds structured details.
func (d Diagnostic) WithDetails(details map[string]any) Diagnostic {
	d.Details = details
	return d
}

// Warning converts the diagnostic to a warning.
func (d Diagnostic) Warning() Diagnostic {
	d.Severity = SeverityWarning
	return d
}

// Info converts the diagnostic to informational output.
func (d Diagnostic) Info() Diagnostic {
	d.Severity = SeverityInfo
	return d
}

// Bag collects diagnostics while preserving order and allowing duplicate
// messages from different targets.
type Bag struct {
	items []Diagnostic
}

// Add appends a diagnostic.
func (b *Bag) Add(d Diagnostic) Diagnostic {
	b.items = append(b.items, d)
	return d
}

// Error appends an error diagnostic.
func (b *Bag) Error(code, message string) Diagnostic {
	return b.Add(New(code, message))
}

// Warn appends a warning diagnostic.
func (b *Bag) Warn(code, message string) Diagnostic {
	return b.Add(New(code, message).Warning())
}

// Extend appends all diagnostics from another slice.
func (b *Bag) Extend(items []Diagnostic) {
	b.items = append(b.items, items...)
}

// Items returns a copy of the collected diagnostics.
func (b *Bag) Items() []Diagnostic {
	out := make([]Diagnostic, len(b.items))
	copy(out, b.items)
	return out
}

// Errors returns only error-severity diagnostics.
func (b *Bag) Errors() []Diagnostic {
	var out []Diagnostic
	for _, item := range b.items {
		if item.Severity == SeverityError {
			out = append(out, item)
		}
	}
	return out
}

// HasErrors reports whether any error diagnostic exists.
func (b *Bag) HasErrors() bool {
	for _, item := range b.items {
		if item.Severity == SeverityError {
			return true
		}
	}
	return false
}

// ForTarget returns diagnostics that apply globally or to the given target.
func (b *Bag) ForTarget(target string) []Diagnostic {
	var out []Diagnostic
	for _, item := range b.items {
		if item.Target == "" || item.Target == target {
			out = append(out, item)
		}
	}
	return out
}

// Strings returns codes and messages in a stable, human-readable form.
func (b *Bag) Strings() []string {
	out := make([]string, 0, len(b.items))
	for _, item := range b.items {
		prefix := string(item.Severity)
		if item.Target != "" {
			prefix += " " + item.Target
		}
		out = append(out, fmt.Sprintf("%s [%s] %s", prefix, item.Code, item.Message))
	}
	sort.Strings(out)
	return out
}

// MarshalJSON keeps nil slices out of artifacts.
func (b *Bag) MarshalJSON() ([]byte, error) {
	items := b.Items()
	if items == nil {
		items = []Diagnostic{}
	}
	return json.Marshal(items)
}
