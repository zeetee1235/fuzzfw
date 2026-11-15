// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package planner turns analysis evidence into deterministic host-lift and
// harness plans. It must not claim a target is fuzzable before build gates run.
package planner

import (
	"encoding/json"
	"sort"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
)

// PlanSchemaVersion is the plan.json schema.
const PlanSchemaVersion = 1

// Classifications are deliberately weaker than "fuzzable".
const (
	ReadyCandidate = "ready_candidate"
	Adaptable      = "adaptable"
	Blocked        = "blocked"
	Fuzzable       = "fuzzable"
	NotFuzzable    = "not_fuzzable"
)

// Role names are the typed contract shared by planner, generator, and reports.
const (
	RoleFuzzBytes        = "FUZZ_BYTES"
	RoleFuzzBytesMutable = "FUZZ_BYTES_MUTABLE"
	RoleLogicalLength    = "LOGICAL_LENGTH"
	RoleCapacity         = "CAPACITY"
	RoleOutputBuffer     = "OUTPUT_BUFFER"
	RoleContext          = "CONTEXT"
	RoleConfig           = "CONFIG"
	RoleUnknown          = "UNKNOWN"
)

// Plan is the deterministic host-lift plan.
type Plan struct {
	SchemaVersion     int               `json:"schema_version"`
	PlanID            string            `json:"plan_id,omitempty"`
	Generator         string            `json:"generator"`
	Project           Project           `json:"project"`
	ConfigFingerprint string            `json:"config_fingerprint"`
	AnalysisSHA256    string            `json:"analysis_sha256"`
	Targets           []TargetPlan      `json:"targets"`
	Diagnostics       []diag.Diagnostic `json:"diagnostics,omitempty"`
}

// Project identifies the planned source tree.
type Project struct {
	Name           string `json:"name"`
	Root           string `json:"root"`
	SourceRevision string `json:"source_revision"`
}

// InputModel is the high-level entry contract.
type InputModel struct {
	Kind        string `json:"kind"`
	BufferArg   int    `json:"buffer_arg"`
	LengthArg   int    `json:"length_arg"`
	CapacityArg int    `json:"capacity_arg,omitempty"`
	ContextArg  int    `json:"context_arg,omitempty"`
	OutputArg   int    `json:"output_arg,omitempty"`
	OutputBytes int    `json:"output_bytes,omitempty"`
}

// RoleBinding assigns one argument a typed mutation role.
type RoleBinding struct {
	Argument int      `json:"argument"`
	Role     string   `json:"role"`
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	Evidence []string `json:"evidence,omitempty"`
}

// Constraint is a checked relation, not a guessed parser invariant.
type Constraint struct {
	Expr     string   `json:"expr"`
	Basis    string   `json:"basis"`
	Evidence []string `json:"evidence,omitempty"`
}

// ContextPlan records setup/teardown and provenance.
type ContextPlan struct {
	Setup       []string `json:"setup"`
	Teardown    []string `json:"teardown"`
	ResetPolicy string   `json:"reset_policy"`
	Provenance  []string `json:"provenance,omitempty"`
	Unknowns    []string `json:"unknowns,omitempty"`
}

// PlatformPlan records adapters and ABI guards.
type PlatformPlan struct {
	Adapters     []string `json:"adapters"`
	ABIGuards    []string `json:"abi_guards"`
	HostTriple   string   `json:"host_triple,omitempty"`
	TargetTriple string   `json:"target_triple,omitempty"`
}

// AnalysisEvidence is the provenance summary carried into the harness plan.
type AnalysisEvidence struct {
	AST                 string   `json:"ast"`
	IR                  string   `json:"ir"`
	IRDataDependent     bool     `json:"ir_data_dependent,omitempty"`
	IRAliasFacts        []string `json:"ir_alias_facts,omitempty"`
	IRMemorySSAAccesses int      `json:"ir_memory_ssa_accesses,omitempty"`
	Unknowns            []string `json:"unknowns,omitempty"`
	Provenance          []string `json:"provenance,omitempty"`
}

// EventHook is an explicit event dispatch around the target call.
type EventHook struct {
	Symbol string `json:"symbol"`
	Phase  string `json:"phase"`
}

// ContextObjectPlan describes an explicit C context allocation and lifecycle.
type ContextObjectPlan struct {
	Arg            int    `json:"arg"`
	Size           int    `json:"size"`
	Init           string `json:"init"`
	InitReturnsInt bool   `json:"init_returns_int,omitempty"`
	Reset          string `json:"reset,omitempty"`
	Destroy        string `json:"destroy,omitempty"`
}

// FactoryPlan describes an explicit C++ object construction/destruction path.
type FactoryPlan struct {
	Symbol     string `json:"symbol"`
	ClassType  string `json:"class_type"`
	ReturnType string `json:"return_type"`
	Style      string `json:"style"` // value, reference, pointer, unique_ptr, shared_ptr
	Lifetime   string `json:"lifetime,omitempty"`
	Destroy    string `json:"destroy,omitempty"`
}

// AdapterBinding is an approved platform boundary replacement.
type AdapterBinding struct {
	OriginalSymbol    string   `json:"original_symbol"`
	ReplacementSource string   `json:"replacement_source"`
	Contract          string   `json:"contract"`
	ContractSHA256    string   `json:"contract_sha256"`
	Prototype         string   `json:"prototype"`
	Model             string   `json:"model"`
	Effects           []string `json:"effects,omitempty"`
	EventModel        string   `json:"event_model,omitempty"`
	Completion        string   `json:"completion,omitempty"`
	Ownership         string   `json:"ownership,omitempty"`
	Limitations       []string `json:"limitations,omitempty"`
}

// WrapperPlan is the explicit user escape hatch.
type WrapperPlan struct {
	Symbol string `json:"symbol"`
	Source string `json:"source"`
}

// TargetPlan is one planned entry boundary.
type TargetPlan struct {
	Name           string             `json:"name"`
	Symbol         string             `json:"symbol"`
	FunctionID     string             `json:"function_id,omitempty"`
	QualifiedName  string             `json:"qualified_name,omitempty"`
	Signature      string             `json:"signature,omitempty"`
	MangledName    string             `json:"mangled_name,omitempty"`
	Source         string             `json:"source,omitempty"`
	Header         string             `json:"header,omitempty"`
	Language       string             `json:"language,omitempty"`
	VariantID      string             `json:"variant_id,omitempty"`
	Classification string             `json:"classification"`
	Status         string             `json:"status"`
	Required       bool               `json:"required"`
	InputModel     InputModel         `json:"input_model"`
	Roles          []RoleBinding      `json:"role_bindings"`
	Constraints    []Constraint       `json:"constraints"`
	Context        ContextPlan        `json:"context"`
	Platform       PlatformPlan       `json:"platform"`
	Analysis       AnalysisEvidence   `json:"analysis"`
	Adapters       []AdapterBinding   `json:"adapters,omitempty"`
	Dependencies   []string           `json:"required_translation_units,omitempty"`
	DirectCallees  []analyzer.CallRef `json:"direct_callees,omitempty"`
	Reasons        []string           `json:"reasons,omitempty"`
	Diagnostics    []diag.Diagnostic  `json:"diagnostics,omitempty"`
	MaxInputBytes  int                `json:"max_input_bytes"`
	OutputBytes    int                `json:"output_bytes,omitempty"`
	Seeds          []string           `json:"seeds,omitempty"`
	Wrapper        *WrapperPlan       `json:"wrapper,omitempty"`
	Factory        *FactoryPlan       `json:"factory,omitempty"`
	ContextObject  *ContextObjectPlan `json:"context_object,omitempty"`
	IsStaticMethod bool               `json:"is_static_method,omitempty"`
	Events         []EventHook        `json:"events,omitempty"`
	Function       *analyzer.Function `json:"-"`
}

// MarshalJSON keeps collection contracts as arrays rather than null.
func (t TargetPlan) MarshalJSON() ([]byte, error) {
	type alias TargetPlan
	copy := alias(t)
	if copy.Roles == nil {
		copy.Roles = []RoleBinding{}
	}
	if copy.Constraints == nil {
		copy.Constraints = []Constraint{}
	}
	if copy.Adapters == nil {
		copy.Adapters = []AdapterBinding{}
	}
	if copy.Dependencies == nil {
		copy.Dependencies = []string{}
	}
	if copy.DirectCallees == nil {
		copy.DirectCallees = []analyzer.CallRef{}
	}
	if copy.Reasons == nil {
		copy.Reasons = []string{}
	}
	if copy.Diagnostics == nil {
		copy.Diagnostics = []diag.Diagnostic{}
	}
	if copy.Seeds == nil {
		copy.Seeds = []string{}
	}
	if copy.Context.Setup == nil {
		copy.Context.Setup = []string{}
	}
	if copy.Context.Teardown == nil {
		copy.Context.Teardown = []string{}
	}
	if copy.Context.Provenance == nil {
		copy.Context.Provenance = []string{}
	}
	if copy.Context.Unknowns == nil {
		copy.Context.Unknowns = []string{}
	}
	if copy.Platform.Adapters == nil {
		copy.Platform.Adapters = []string{}
	}
	if copy.Platform.ABIGuards == nil {
		copy.Platform.ABIGuards = []string{}
	}
	return json.Marshal(copy)
}

// Sort makes plan artifacts deterministic.
func (p *Plan) Sort() {
	sort.Slice(p.Targets, func(i, j int) bool { return p.Targets[i].Name < p.Targets[j].Name })
	for i := range p.Targets {
		sort.Slice(p.Targets[i].Roles, func(a, b int) bool {
			return p.Targets[i].Roles[a].Argument < p.Targets[i].Roles[b].Argument
		})
		sort.Strings(p.Targets[i].Dependencies)
		sort.Strings(p.Targets[i].Reasons)
		sort.Strings(p.Targets[i].Context.Setup)
		sort.Strings(p.Targets[i].Context.Teardown)
		sort.Strings(p.Targets[i].Platform.Adapters)
		sort.Strings(p.Targets[i].Platform.ABIGuards)
		sort.Strings(p.Targets[i].Seeds)
	}
}

// Finalize computes the deterministic plan ID after all fields are set.
func (p *Plan) Finalize() error {
	p.Sort()
	hash, err := fsutil.HashJSON(p)
	if err != nil {
		return err
	}
	p.PlanID = "plan_" + hash[:24]
	return nil
}

// MarshalJSON keeps nil collections as empty arrays.
func (p Plan) MarshalJSON() ([]byte, error) {
	type alias Plan
	copy := alias(p)
	if copy.Targets == nil {
		copy.Targets = []TargetPlan{}
	}
	return json.Marshal(copy)
}

// Target returns a target plan by name.
func (p *Plan) Target(name string) (TargetPlan, bool) {
	for _, target := range p.Targets {
		if target.Name == name || target.Symbol == name {
			return target, true
		}
	}
	return TargetPlan{}, false
}
