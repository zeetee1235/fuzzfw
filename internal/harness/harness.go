// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package harness materializes the deterministic typed harness plan and C/C++
// source. It never copies or edits target function bodies.
package harness

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/version"
)

// SchemaVersion is the harness_plan.json schema version defined by the spec.
const SchemaVersion = 2

// Target is the typed entry description.
type Target struct {
	Name         string `json:"name"`
	FunctionID   string `json:"function_id,omitempty"`
	Language     string `json:"language"`
	EntryKind    string `json:"entry_kind"`
	LinkSymbol   string `json:"link_symbol"`
	CallSymbol   string `json:"call_symbol,omitempty"`
	SourceHeader string `json:"source_header,omitempty"`
	BuildVariant string `json:"build_variant,omitempty"`
	Source       string `json:"source,omitempty"`
}

// Plan is the harness generator's input/output contract.
type Plan struct {
	SchemaVersion int                      `json:"schema_version"`
	HarnessID     string                   `json:"harness_id,omitempty"`
	Generator     string                   `json:"generator"`
	Target        Target                   `json:"target"`
	RoleBindings  []planner.RoleBinding    `json:"role_bindings"`
	Constraints   []planner.Constraint     `json:"constraints"`
	Context       planner.ContextPlan      `json:"context"`
	Platform      planner.PlatformPlan     `json:"platform"`
	Analysis      planner.AnalysisEvidence `json:"analysis"`
	Validations   []string                 `json:"validations"`
	Provenance    []string                 `json:"provenance"`
	Diagnostics   []diag.Diagnostic        `json:"diagnostics,omitempty"`
}

// BuildPlan converts a planner target into the canonical harness plan.
func BuildPlan(target planner.TargetPlan, cfg *config.Config) (*Plan, error) {
	if target.Wrapper != nil {
		plan := &Plan{
			SchemaVersion: SchemaVersion,
			Generator:     "fuzzfw-harness/" + version.Version,
			Target: Target{
				Name:         target.Name,
				Language:     "c-wrapper",
				EntryKind:    "manual_wrapper",
				LinkSymbol:   target.Wrapper.Symbol,
				CallSymbol:   target.Wrapper.Symbol,
				Source:       target.Wrapper.Source,
				BuildVariant: target.VariantID,
			},
			Constraints: target.Constraints,
			Context:     target.Context,
			Platform:    target.Platform,
			Analysis:    target.Analysis,
			Validations: defaultValidations(),
			Provenance:  append([]string{"explicit_config", "user_wrapper", "fuzzfw_harness"}, target.Analysis.Provenance...),
		}
		if err := plan.Finalize(); err != nil {
			return nil, err
		}
		return plan, nil
	}
	if target.Header == "" {
		return nil, fmt.Errorf("target %s has no header declaration", target.Name)
	}
	if target.InputModel.BufferArg < 0 || target.InputModel.LengthArg < 0 {
		return nil, fmt.Errorf("target %s has no bytes+length role binding", target.Name)
	}
	plan := &Plan{
		SchemaVersion: SchemaVersion,
		Generator:     "fuzzfw-harness/" + version.Version,
		Target: Target{
			Name:         target.Name,
			FunctionID:   target.FunctionID,
			Language:     target.Language,
			EntryKind:    "direct_buffer_api",
			LinkSymbol:   target.MangledName,
			CallSymbol:   target.QualifiedName,
			SourceHeader: target.Header,
			BuildVariant: target.VariantID,
			Source:       target.Source,
		},
		RoleBindings: append([]planner.RoleBinding(nil), target.Roles...),
		Constraints:  append([]planner.Constraint(nil), target.Constraints...),
		Context:      target.Context,
		Platform:     target.Platform,
		Analysis:     target.Analysis,
		Validations:  defaultValidations(),
		Provenance:   append([]string{"project_build", "ast", "fuzzfw_harness"}, target.Analysis.Provenance...),
	}
	if plan.Target.LinkSymbol == "" {
		plan.Target.LinkSymbol = target.Symbol
	}
	if err := plan.Finalize(); err != nil {
		return nil, err
	}
	return plan, nil
}

func defaultValidations() []string {
	return []string{
		"g0_static_contract", "g1_compile", "g2_link", "g3_seed_smoke",
		"g4_target_reach", "g5_input_use", "g6_context_validity",
		"g7_stability", "g8_crash_reproduce",
	}
}

// MarshalJSON keeps collection contracts as arrays rather than null.
func (p Plan) MarshalJSON() ([]byte, error) {
	type alias Plan
	copy := alias(p)
	if copy.RoleBindings == nil {
		copy.RoleBindings = []planner.RoleBinding{}
	}
	if copy.Constraints == nil {
		copy.Constraints = []planner.Constraint{}
	}
	if copy.Validations == nil {
		copy.Validations = []string{}
	}
	if copy.Provenance == nil {
		copy.Provenance = []string{}
	}
	if copy.Diagnostics == nil {
		copy.Diagnostics = []diag.Diagnostic{}
	}
	return json.Marshal(copy)
}

// Finalize sorts and computes the stable harness ID.
func (p *Plan) Finalize() error {
	sort.Slice(p.RoleBindings, func(i, j int) bool { return p.RoleBindings[i].Argument < p.RoleBindings[j].Argument })
	sort.Strings(p.Validations)
	sort.Strings(p.Provenance)
	p.Provenance = unique(p.Provenance)
	p.HarnessID = ""
	hash, err := fsutil.HashJSON(p)
	if err != nil {
		return err
	}
	p.HarnessID = "hs_" + hash[:24]
	return nil
}

// ConstraintsSources is a deterministic helper for sorting constraint origins.
func (p *Plan) ConstraintsSources() []string {
	out := make([]string, 0, len(p.Constraints))
	for _, constraint := range p.Constraints {
		out = append(out, constraint.Basis)
	}
	return out
}

// Emit renders the fuzz entry source and returns its file extension.
func Emit(plan *Plan, cfg *config.Config) (string, string, error) {
	if plan.SchemaVersion != SchemaVersion {
		return "", "", fmt.Errorf("unsupported harness plan schema version %d", plan.SchemaVersion)
	}
	if plan.Target.EntryKind == "manual_wrapper" {
		return emitWrapper(plan), ".c", nil
	}
	if plan.Target.SourceHeader == "" {
		return "", "", fmt.Errorf("missing source header")
	}
	if plan.Target.Language != "c" && plan.Target.Language != "c++" {
		return "", "", fmt.Errorf("unsupported target language %q", plan.Target.Language)
	}

	roles := map[int]planner.RoleBinding{}
	for _, role := range plan.RoleBindings {
		if role.Role == "" || role.Role == planner.RoleUnknown {
			return "", "", fmt.Errorf("argument %d has unresolved role", role.Argument)
		}
		roles[role.Argument] = role
	}
	bufferArg, lengthArg := -1, -1
	bufferRole := ""
	capacityArgs := map[int]bool{}
	for arg, role := range roles {
		switch role.Role {
		case planner.RoleFuzzBytes, planner.RoleFuzzBytesMutable:
			if bufferArg >= 0 {
				return "", "", fmt.Errorf("multiple fuzz buffer arguments")
			}
			bufferArg = arg
			bufferRole = role.Role
		case planner.RoleLogicalLength:
			if lengthArg >= 0 {
				return "", "", fmt.Errorf("multiple logical length arguments")
			}
			lengthArg = arg
		case planner.RoleCapacity:
			capacityArgs[arg] = true
		case planner.RoleContext, planner.RoleConfig, planner.RoleOutputBuffer:
			return "", "", fmt.Errorf("argument %d role %s requires a user wrapper", arg, role.Role)
		default:
			return "", "", fmt.Errorf("argument %d has unsupported role %s", arg, role.Role)
		}
	}
	if bufferArg < 0 || lengthArg < 0 {
		return "", "", fmt.Errorf("harness plan lacks fuzz buffer or logical length")
	}

	var b strings.Builder
	b.WriteString("/* GENERATED by fuzzfw; do not edit. */\n")
	b.WriteString("/* SPDX-License-Identifier: Apache-2.0 */\n")
	b.WriteString("#include <stddef.h>\n#include <stdint.h>\n#include <limits.h>\n#include <stdlib.h>\n#include <string.h>\n")
	b.WriteString("#include \"")
	b.WriteString(escapeInclude(plan.Target.SourceHeader))
	b.WriteString("\"\n\n")
	if plan.Target.Language == "c++" {
		b.WriteString("extern \"C\" {\n")
	}
	b.WriteString("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);\n")
	if plan.Target.Language == "c++" {
		b.WriteString("}\n")
	}
	b.WriteString("\n")

	if plan.Target.Language == "c++" {
		b.WriteString("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n")
	} else {
		b.WriteString("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n")
	}
	fmt.Fprintf(&b, "    if (size > %d) return 0;\n", planMaxInput(plan, cfg))
	lengthType := ""
	for arg, role := range roles {
		if role.Role == planner.RoleLogicalLength {
			lengthType = role.Type
			if macro := lengthGuardMacro(role.Type); macro != "" {
				fmt.Fprintf(&b, "    if (size > %s) return 0;\n", macro)
			}
		}
		_ = arg
	}
	if lengthType == "" {
		return "", "", fmt.Errorf("logical length type missing")
	}

	needsCopy := bufferRole == planner.RoleFuzzBytesMutable
	if needsCopy {
		b.WriteString("    uint8_t *copy = NULL;\n")
		b.WriteString("    if (size > 0) {\n")
		b.WriteString("        copy = (uint8_t *)malloc(size);\n")
		b.WriteString("        if (copy == NULL) return 0;\n")
		b.WriteString("        memcpy(copy, data, size);\n")
		b.WriteString("    } else {\n")
		b.WriteString("        copy = (uint8_t *)malloc(1);\n")
		b.WriteString("        if (copy == NULL) return 0;\n")
		b.WriteString("    }\n")
	}
	for _, setup := range plan.Context.Setup {
		fmt.Fprintf(&b, "    %s();\n", setup)
	}
	args := make([]string, 0, len(roles))
	for arg := 0; arg < len(plan.RoleBindings); arg++ {
		role, ok := roles[arg]
		if !ok {
			return "", "", fmt.Errorf("argument %d has no role binding", arg)
		}
		switch role.Role {
		case planner.RoleFuzzBytes:
			args = append(args, "data")
		case planner.RoleFuzzBytesMutable:
			args = append(args, "copy")
		case planner.RoleLogicalLength, planner.RoleCapacity:
			args = append(args, castLength(role.Type, "size"))
		default:
			return "", "", fmt.Errorf("argument %d role %s cannot be emitted", arg, role.Role)
		}
	}
	callSymbol := plan.Target.CallSymbol
	if callSymbol == "" {
		callSymbol = plan.Target.LinkSymbol
	}
	fmt.Fprintf(&b, "    (void)%s(%s);\n", callSymbol, strings.Join(args, ", "))
	for _, teardown := range plan.Context.Teardown {
		fmt.Fprintf(&b, "    %s();\n", teardown)
	}
	if needsCopy {
		b.WriteString("    free(copy);\n")
	}
	b.WriteString("    return 0;\n}\n")
	extension := ".c"
	if plan.Target.Language == "c++" {
		extension = ".cpp"
	}
	return b.String(), extension, nil
}

func emitWrapper(plan *Plan) string {
	var b strings.Builder
	b.WriteString("/* GENERATED by fuzzfw; do not edit. */\n")
	b.WriteString("/* SPDX-License-Identifier: Apache-2.0 */\n")
	b.WriteString("#include <stddef.h>\n#include <stdint.h>\n\n")
	b.WriteString("/* User wrapper ABI: void wrapper(const uint8_t *data, size_t size). */\n")
	fmt.Fprintf(&b, "extern void %s(const uint8_t *data, size_t size);\n\n", plan.Target.CallSymbol)
	b.WriteString("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n")
	fmt.Fprintf(&b, "    if (size > %d) return 0;\n", plan.maxInputFromConstraints())
	fmt.Fprintf(&b, "    %s(data, size);\n", plan.Target.CallSymbol)
	b.WriteString("    return 0;\n}\n")
	return b.String()
}

func (p *Plan) maxInputFromConstraints() int {
	for _, constraint := range p.Constraints {
		var value int
		if _, err := fmt.Sscanf(constraint.Expr, "size <= %d", &value); err == nil {
			return value
		}
	}
	return 4096
}

func planMaxInput(plan *Plan, cfg *config.Config) int {
	if plan != nil {
		if value := plan.maxInputFromConstraints(); value > 0 {
			return value
		}
	}
	return cfg.File.Harness.MaxInputBytes
}

func lengthGuardMacro(typeName string) string {
	base := normalizeBase(typeName)
	switch base {
	case "size_t":
		return "SIZE_MAX"
	case "ssize_t":
		return "SSIZE_MAX"
	case "uint8_t", "unsigned char":
		return "UINT8_MAX"
	case "int8_t", "signed char", "char":
		return "INT8_MAX"
	case "uint16_t", "unsigned short":
		return "UINT16_MAX"
	case "int16_t", "short":
		return "INT16_MAX"
	case "uint32_t", "unsigned int", "unsigned":
		return "UINT32_MAX"
	case "int32_t", "int":
		return "INT32_MAX"
	case "uint64_t", "unsigned long", "unsigned long long":
		return "UINT64_MAX"
	case "int64_t", "long", "long long":
		return "INT64_MAX"
	default:
		return ""
	}
}

func castLength(typeName, value string) string {
	base := normalizeBase(typeName)
	if base == "size_t" {
		return value
	}
	return "(" + strings.TrimSpace(typeName) + ")" + value
}

func normalizeBase(value string) string {
	replacer := strings.NewReplacer("const", " ", "volatile", " ", "restrict", " ", "std::", "")
	return strings.Join(strings.Fields(replacer.Replace(value)), " ")
}

func escapeInclude(path string) string {
	path = filepath.ToSlash(path)
	return strings.ReplaceAll(strings.ReplaceAll(path, "\\", "\\\\"), "\"", "\\\"")
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
