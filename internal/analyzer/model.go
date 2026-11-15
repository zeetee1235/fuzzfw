// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package analyzer defines the stable analysis.json contract and the Clang
// front end used to produce it.
package analyzer

import (
	"encoding/json"
	"sort"

	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
)

// AnalysisSchemaVersion is the analysis.json schema.
const AnalysisSchemaVersion = 1

// Analysis modes are explicit so consumers never mistake a fallback for a full
// native LibTooling analysis.
const (
	ModeNativeAST = "NATIVE_AST"
	ModeASTJSON   = "AST_JSON_FALLBACK"
	ModeASTOnly   = "AST_ONLY"
	ModeMixed     = "NATIVE_AST_WITH_FALLBACK"
)

// Analysis is the top-level analysis.json artifact.
type Analysis struct {
	SchemaVersion        int               `json:"schema_version"`
	AnalysisMode         string            `json:"analysis_mode"`
	Generator            string            `json:"generator"`
	Project              Project           `json:"project"`
	Variants             []Variant         `json:"variants"`
	Functions            []Function        `json:"functions"`
	ExternalDeclarations []Declaration     `json:"external_declarations,omitempty"`
	IRFacts              []IRFunctionFact  `json:"ir_facts,omitempty"`
	Diagnostics          []diag.Diagnostic `json:"diagnostics,omitempty"`
}

// Project identifies the analyzed source tree.
type Project struct {
	Name              string `json:"name"`
	Root              string `json:"root"`
	SourceRevision    string `json:"source_revision"`
	ConfigFingerprint string `json:"config_fingerprint"`
}

// Variant is one translation-unit build configuration.
type Variant struct {
	ID             string   `json:"id"`
	File           string   `json:"file"`
	Language       string   `json:"language"`
	Compiler       string   `json:"compiler"`
	CompilerUsed   string   `json:"compiler_used"`
	TargetTriple   string   `json:"target_triple,omitempty"`
	HostTriple     string   `json:"host_triple,omitempty"`
	Arguments      []string `json:"arguments"`
	IncludeDirs    []string `json:"include_dirs,omitempty"`
	Defines        []string `json:"defines,omitempty"`
	Standard       string   `json:"standard,omitempty"`
	AnalysisStatus string   `json:"analysis_status"`
	IRStatus       string   `json:"ir_status"`
	Diagnostics    []string `json:"diagnostics,omitempty"`
}

// Param is one function parameter.
type Param struct {
	Index         int      `json:"index"`
	Name          string   `json:"name,omitempty"`
	Type          string   `json:"type"`
	CanonicalType string   `json:"canonical_type"`
	IsConst       bool     `json:"is_const"`
	IsPointer     bool     `json:"is_pointer"`
	IsInteger     bool     `json:"is_integer"`
	IsSigned      bool     `json:"is_signed"`
	IsVolatile    bool     `json:"is_volatile"`
	IsVoidPointer bool     `json:"is_void_pointer"`
	Bits          int      `json:"bits,omitempty"`
	Evidence      []string `json:"evidence,omitempty"`
}

// CallRef is a direct call edge.
type CallRef struct {
	Symbol    string `json:"symbol,omitempty"`
	Name      string `json:"name"`
	Source    string `json:"source,omitempty"`
	Line      int    `json:"line,omitempty"`
	Direct    bool   `json:"direct"`
	Arguments []int  `json:"arguments,omitempty"`
}

// Evidence is a source or IR observation backing a decision.
type Evidence struct {
	Kind       string `json:"kind"`
	Source     string `json:"source,omitempty"`
	Symbol     string `json:"symbol,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Confidence string `json:"confidence"` // verified, observed, heuristic, unknown
}

// Function is one analyzed declaration/definition.
type Function struct {
	ID              string     `json:"id"`
	Language        string     `json:"language"`
	Name            string     `json:"name"`
	QualifiedName   string     `json:"qualified_name"`
	MangledName     string     `json:"mangled_name,omitempty"`
	USR             string     `json:"usr,omitempty"`
	ParentType      string     `json:"parent_type,omitempty"`
	Signature       string     `json:"signature"`
	ReturnType      string     `json:"return_type"`
	Source          string     `json:"source"`
	Header          string     `json:"header,omitempty"`
	Line            int        `json:"line,omitempty"`
	Column          int        `json:"column,omitempty"`
	VariantID       string     `json:"variant_id"`
	TranslationUnit string     `json:"translation_unit"`
	Definition      bool       `json:"definition"`
	InternalLinkage bool       `json:"internal_linkage"`
	IsMethod        bool       `json:"is_method"`
	IsStaticMethod  bool       `json:"is_static_method,omitempty"`
	Variadic        bool       `json:"variadic,omitempty"`
	Params          []Param    `json:"params"`
	DirectCallees   []CallRef  `json:"direct_callees,omitempty"`
	UnresolvedCalls []string   `json:"unresolved_calls,omitempty"`
	IndirectCalls   []string   `json:"indirect_calls,omitempty"`
	GlobalReads     []string   `json:"global_reads,omitempty"`
	GlobalWrites    []string   `json:"global_writes,omitempty"`
	HardwareFlags   []string   `json:"hardware_flags,omitempty"`
	Constants       []string   `json:"constants,omitempty"`
	CaseConstants   []string   `json:"case_constants,omitempty"`
	Reasons         []string   `json:"reasons,omitempty"`
	Evidence        []Evidence `json:"evidence,omitempty"`
}

// Declaration is a function declaration without a body under the project root.
type Declaration struct {
	Name          string `json:"name"`
	QualifiedName string `json:"qualified_name"`
	MangledName   string `json:"mangled_name,omitempty"`
	Signature     string `json:"signature"`
	ReturnType    string `json:"return_type,omitempty"`
	Source        string `json:"source"`
	Line          int    `json:"line,omitempty"`
	Language      string `json:"language"`
	VariantID     string `json:"variant_id"`
	IsStatic      bool   `json:"is_static,omitempty"`
}

// IRFunctionFact is the joinable LLVM IR summary for one function.
type IRFunctionFact struct {
	SchemaVersion     int          `json:"schema_version"`
	FunctionID        string       `json:"function_id,omitempty"`
	LinkSymbol        string       `json:"link_symbol"`
	TargetTriple      string       `json:"target_triple,omitempty"`
	HostTriple        string       `json:"host_triple,omitempty"`
	IRMapping         string       `json:"ir_mapping"`
	Arguments         []IRArgument `json:"arguments,omitempty"`
	GlobalEffects     []string     `json:"global_effects,omitempty"`
	HardwareFlags     []string     `json:"hardware_flags,omitempty"`
	Unknowns          []string     `json:"unknowns,omitempty"`
	AliasFacts        []string     `json:"alias_facts,omitempty"`
	MemorySSAAccesses int          `json:"memory_ssa_accesses,omitempty"`
	Evidence          []Evidence   `json:"evidence,omitempty"`
	BranchCount       int          `json:"branch_count,omitempty"`
	LoadCount         int          `json:"load_count,omitempty"`
	StoreCount        int          `json:"store_count,omitempty"`
	IndirectCalls     int          `json:"indirect_calls,omitempty"`
	VolatileAccesses  int          `json:"volatile_accesses,omitempty"`
	DataDependent     bool         `json:"data_dependent,omitempty"`
}

// IRArgument is one argument's observed IR uses.
type IRArgument struct {
	Index       int      `json:"index"`
	ObservedUse []string `json:"observed_use,omitempty"`
	MayEscape   bool     `json:"may_escape"`
}

// MarshalJSON keeps the required parameter collection non-null.
func (f Function) MarshalJSON() ([]byte, error) {
	type alias Function
	copy := alias(f)
	if copy.Params == nil {
		copy.Params = []Param{}
	}
	if copy.DirectCallees == nil {
		copy.DirectCallees = []CallRef{}
	}
	if copy.UnresolvedCalls == nil {
		copy.UnresolvedCalls = []string{}
	}
	if copy.IndirectCalls == nil {
		copy.IndirectCalls = []string{}
	}
	if copy.GlobalReads == nil {
		copy.GlobalReads = []string{}
	}
	if copy.GlobalWrites == nil {
		copy.GlobalWrites = []string{}
	}
	if copy.HardwareFlags == nil {
		copy.HardwareFlags = []string{}
	}
	if copy.Reasons == nil {
		copy.Reasons = []string{}
	}
	if copy.Evidence == nil {
		copy.Evidence = []Evidence{}
	}
	return json.Marshal(copy)
}

// ToJSON serializes the analysis deterministically.
func (a *Analysis) ToJSON() ([]byte, error) {
	return fsutil.CanonicalJSON(a)
}

// Sort normalizes ordering for deterministic artifacts.
func (a *Analysis) Sort() {
	sort.Slice(a.Variants, func(i, j int) bool {
		if a.Variants[i].File != a.Variants[j].File {
			return a.Variants[i].File < a.Variants[j].File
		}
		return a.Variants[i].ID < a.Variants[j].ID
	})
	sort.Slice(a.Functions, func(i, j int) bool {
		if a.Functions[i].Source != a.Functions[j].Source {
			return a.Functions[i].Source < a.Functions[j].Source
		}
		if a.Functions[i].QualifiedName != a.Functions[j].QualifiedName {
			return a.Functions[i].QualifiedName < a.Functions[j].QualifiedName
		}
		return a.Functions[i].ID < a.Functions[j].ID
	})
	sort.Slice(a.ExternalDeclarations, func(i, j int) bool {
		if a.ExternalDeclarations[i].Source != a.ExternalDeclarations[j].Source {
			return a.ExternalDeclarations[i].Source < a.ExternalDeclarations[j].Source
		}
		return a.ExternalDeclarations[i].QualifiedName < a.ExternalDeclarations[j].QualifiedName
	})
	sort.Slice(a.IRFacts, func(i, j int) bool { return a.IRFacts[i].LinkSymbol < a.IRFacts[j].LinkSymbol })
}

// MarshalJSON avoids nil slices in artifacts.
func (a Analysis) MarshalJSON() ([]byte, error) {
	type alias Analysis
	copy := alias(a)
	if copy.Variants == nil {
		copy.Variants = []Variant{}
	}
	if copy.Functions == nil {
		copy.Functions = []Function{}
	}
	if copy.IRFacts == nil {
		copy.IRFacts = []IRFunctionFact{}
	}
	return json.Marshal(copy)
}
