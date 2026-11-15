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
	Name           string                     `json:"name"`
	FunctionID     string                     `json:"function_id,omitempty"`
	Language       string                     `json:"language"`
	EntryKind      string                     `json:"entry_kind"`
	LinkSymbol     string                     `json:"link_symbol"`
	CallSymbol     string                     `json:"call_symbol,omitempty"`
	SourceHeader   string                     `json:"source_header,omitempty"`
	BuildVariant   string                     `json:"build_variant,omitempty"`
	Source         string                     `json:"source,omitempty"`
	MethodName     string                     `json:"method_name,omitempty"`
	Factory        *planner.FactoryPlan       `json:"factory,omitempty"`
	ContextObject  *planner.ContextObjectPlan `json:"context_object,omitempty"`
	IsStaticMethod bool                       `json:"is_static_method,omitempty"`
	Events         []planner.EventHook        `json:"events,omitempty"`
	StateProbe     string                     `json:"state_probe,omitempty"`
	FrameReset     string                     `json:"frame_reset,omitempty"`
	InvariantCheck string                     `json:"invariant_check,omitempty"`
	InvariantArgs  int                        `json:"invariant_args,omitempty"`
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
	CopyInput     bool                     `json:"copy_input"`
	OutputBytes   int                      `json:"output_bytes,omitempty"`
	InputKind     string                   `json:"input_kind,omitempty"`
	MaxFrames     int                      `json:"max_frames,omitempty"`
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
			CopyInput:   cfg.File.Harness.CopyInput,
			OutputBytes: target.OutputBytes,
			InputKind:   target.InputModel.Kind,
			MaxFrames:   target.MaxFrames,
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
			Name:           target.Name,
			FunctionID:     target.FunctionID,
			Language:       target.Language,
			EntryKind:      "direct_buffer_api",
			LinkSymbol:     target.MangledName,
			CallSymbol:     target.QualifiedName,
			SourceHeader:   target.Header,
			BuildVariant:   target.VariantID,
			Source:         target.Source,
			MethodName:     methodName(target.QualifiedName),
			Factory:        target.Factory,
			ContextObject:  target.ContextObject,
			IsStaticMethod: target.IsStaticMethod,
			Events:         append([]planner.EventHook(nil), target.Events...),
			StateProbe:     target.StateProbe,
			FrameReset:     target.FrameReset,
			InvariantCheck: target.InvariantCheck,
			InvariantArgs:  target.InvariantArgs,
		},
		RoleBindings: append([]planner.RoleBinding(nil), target.Roles...),
		Constraints:  append([]planner.Constraint(nil), target.Constraints...),
		Context:      target.Context,
		Platform:     target.Platform,
		Analysis:     target.Analysis,
		Validations:  defaultValidations(),
		CopyInput:    cfg.File.Harness.CopyInput,
		OutputBytes:  target.OutputBytes,
		InputKind:    target.InputModel.Kind,
		MaxFrames:    target.MaxFrames,
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
		case planner.RoleContext:
			if plan.Target.ContextObject == nil {
				return "", "", fmt.Errorf("context role has no context object plan")
			}
		case planner.RoleOutputBuffer:
			if plan.OutputBytes <= 0 {
				return "", "", fmt.Errorf("output buffer role requires output_bytes")
			}
		case planner.RoleCapacity, planner.RoleConfig:
			if role.Role == planner.RoleConfig {
				return "", "", fmt.Errorf("argument %d role %s requires a user wrapper", arg, role.Role)
			}
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
	b.WriteString("#include \"fuzzfw_events.h\"\n")
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
	for _, role := range roles {
		if role.Role == planner.RoleLogicalLength {
			lengthType = role.Type
			if macro := lengthGuardMacro(role.Type); macro != "" {
				fmt.Fprintf(&b, "    if (size > %s) return 0;\n", macro)
			}
		}
	}
	if lengthType == "" {
		return "", "", fmt.Errorf("logical length type missing")
	}

	contextRole, hasContext := roles[targetContextArg(plan)]
	contextCast := ""
	if hasContext {
		contextCast = contextPointerCast(contextRole.Type, "fuzzfw_context")
	}
	b.WriteString("    fuzzfw_input_bind(data, size);\n")
	b.WriteString("    fuzzfw_run_begin();\n")
	needsInputCopy := plan.CopyInput && bufferRole == planner.RoleFuzzBytes
	needsCopy := bufferRole == planner.RoleFuzzBytesMutable
	if needsInputCopy {
		b.WriteString("    const uint8_t *input = NULL;\n")
		b.WriteString("    if (size > 0) {\n")
		b.WriteString("        input = (const uint8_t *)malloc(size);\n")
		b.WriteString("        if (input == NULL) return 0;\n")
		b.WriteString("        memcpy((void *)input, data, size);\n")
		b.WriteString("    } else {\n")
		b.WriteString("        uint8_t *empty = (uint8_t *)malloc(1);\n")
		b.WriteString("        if (empty == NULL) return 0;\n")
		b.WriteString("        empty[0] = 0;\n")
		b.WriteString("        input = empty;\n")
		b.WriteString("    }\n")
	}
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
	needsOutput := false
	for _, role := range roles {
		if role.Role == planner.RoleOutputBuffer {
			needsOutput = true
		}
	}
	if needsOutput {
		fmt.Fprintf(&b, "    uint8_t *output = (uint8_t *)calloc(1, %d);\n", plan.OutputBytes)
		b.WriteString("    if (output == NULL) return 0;\n")
	}
	for _, setup := range plan.Context.Setup {
		fmt.Fprintf(&b, "    %s();\n", setup)
	}
	if plan.Target.ContextObject != nil {
		ctx := plan.Target.ContextObject
		fmt.Fprintf(&b, "    void *fuzzfw_context = calloc(1, %d);\n", ctx.Size)
		b.WriteString("    if (fuzzfw_context == NULL) return 0;\n")
		if ctx.InitReturnsInt {
			fmt.Fprintf(&b, "    if (%s(%s) != 0) { free(fuzzfw_context); return 0; }\n", ctx.Init, contextCast)
		} else {
			fmt.Fprintf(&b, "    %s(%s);\n", ctx.Init, contextCast)
		}
	}
	if plan.Target.Factory != nil && !plan.Target.IsStaticMethod {
		switch plan.Target.Factory.Style {
		case "value", "unique_ptr", "shared_ptr":
			fmt.Fprintf(&b, "    auto fuzzfw_object = %s();\n", plan.Target.Factory.Symbol)
		case "reference":
			fmt.Fprintf(&b, "    auto &fuzzfw_object = %s();\n", plan.Target.Factory.Symbol)
		case "pointer":
			fmt.Fprintf(&b, "    auto *fuzzfw_object = %s();\n", plan.Target.Factory.Symbol)
			b.WriteString("    if (fuzzfw_object == nullptr) return 0;\n")
		default:
			return "", "", fmt.Errorf("unsupported factory style %q", plan.Target.Factory.Style)
		}
	}

	sequence := plan.InputKind == "length_prefixed"
	baseExpr := "data"
	if needsInputCopy {
		baseExpr = "input"
	} else if needsCopy {
		baseExpr = "copy"
	}
	if sequence {
		if err := emitSequence(&b, plan, roles, baseExpr, contextCast, needsOutput); err != nil {
			return "", "", err
		}
	} else {
		capture := invariantCapture(plan)
		if capture != "" {
			fmt.Fprintf(&b, "    long long %s = 0;\n", capture)
		}
		for _, event := range plan.Target.Events {
			if event.Phase == "before" {
				fmt.Fprintf(&b, "    %s();\n", event.Symbol)
			}
		}
		args, err := callArgs(plan, roles, normalBufferExpr(needsCopy, needsInputCopy), "size", needsOutput, contextCast)
		if err != nil {
			return "", "", err
		}
		if err := emitCall(&b, plan, args, capture, "    "); err != nil {
			return "", "", err
		}
		for _, event := range plan.Target.Events {
			if event.Phase == "after" {
				fmt.Fprintf(&b, "    %s();\n", event.Symbol)
			}
		}
		emitInvariant(&b, plan, needsOutput, "    ")
		emitStateProbe(&b, plan, "0", contextCast, "    ")
	}
	for _, teardown := range plan.Context.Teardown {
		fmt.Fprintf(&b, "    %s();\n", teardown)
	}
	if plan.Target.ContextObject != nil {
		ctx := plan.Target.ContextObject
		if ctx.Reset != "" {
			fmt.Fprintf(&b, "    %s(%s);\n", ctx.Reset, contextCast)
		}
		if ctx.Destroy != "" {
			fmt.Fprintf(&b, "    %s(%s);\n", ctx.Destroy, contextCast)
		}
		b.WriteString("    free(fuzzfw_context);\n")
	}
	b.WriteString("    fuzzfw_input_clear();\n")
	if needsInputCopy {
		b.WriteString("    free((void *)input);\n")
	}
	if needsCopy {
		b.WriteString("    free(copy);\n")
	}
	if needsOutput {
		b.WriteString("    free(output);\n")
	}
	b.WriteString("    return 0;\n}\n")
	extension := ".c"
	if plan.Target.Language == "c++" {
		extension = ".cpp"
	}
	return b.String(), extension, nil
}

func normalBufferExpr(mutable, inputCopy bool) string {
	if mutable {
		return "copy"
	}
	if inputCopy {
		return "input"
	}
	return "data"
}

func callArgs(plan *Plan, roles map[int]planner.RoleBinding, bufferExpr, lengthExpr string, hasOutput bool, contextCast string) ([]string, error) {
	args := make([]string, 0, len(roles))
	for arg := 0; arg < len(plan.RoleBindings); arg++ {
		role, ok := roles[arg]
		if !ok {
			return nil, fmt.Errorf("argument %d has no role binding", arg)
		}
		switch role.Role {
		case planner.RoleFuzzBytes, planner.RoleFuzzBytesMutable:
			args = append(args, bufferExpr)
		case planner.RoleLogicalLength:
			args = append(args, castLength(role.Type, lengthExpr))
		case planner.RoleCapacity:
			if hasOutput {
				args = append(args, castLength(role.Type, fmt.Sprintf("%d", plan.OutputBytes)))
			} else {
				args = append(args, castLength(role.Type, lengthExpr))
			}
		case planner.RoleOutputBuffer:
			args = append(args, outputPointerCast(role.Type, "output"))
		case planner.RoleContext:
			args = append(args, contextCast)
		default:
			return nil, fmt.Errorf("argument %d role %s cannot be emitted", arg, role.Role)
		}
	}
	return args, nil
}

func emitCall(b *strings.Builder, plan *Plan, args []string, capture, indent string) error {
	callSymbol := plan.Target.CallSymbol
	if callSymbol == "" {
		callSymbol = plan.Target.LinkSymbol
	}
	invoke := func(invocation string) {
		if capture != "" {
			fmt.Fprintf(b, "%s%s = %s;\n", indent, capture, invocation)
		} else {
			fmt.Fprintf(b, "%s(void)%s;\n", indent, invocation)
		}
	}
	switch {
	case plan.Target.IsStaticMethod:
		invoke(fmt.Sprintf("%s(%s)", callSymbol, strings.Join(args, ", ")))
	case plan.Target.Factory != nil:
		method := plan.Target.MethodName
		if method == "" {
			return fmt.Errorf("factory harness has no method name")
		}
		switch plan.Target.Factory.Style {
		case "value", "reference":
			invoke(fmt.Sprintf("fuzzfw_object.%s(%s)", method, strings.Join(args, ", ")))
		case "unique_ptr", "shared_ptr", "pointer":
			invoke(fmt.Sprintf("fuzzfw_object->%s(%s)", method, strings.Join(args, ", ")))
		default:
			return fmt.Errorf("unsupported factory style %q", plan.Target.Factory.Style)
		}
		if plan.Target.Factory.Style == "pointer" && plan.Target.Factory.Destroy != "" {
			fmt.Fprintf(b, "%s%s(fuzzfw_object);\n", indent, plan.Target.Factory.Destroy)
		}
	default:
		invoke(fmt.Sprintf("%s(%s)", callSymbol, strings.Join(args, ", ")))
	}
	return nil
}

func emitSequence(b *strings.Builder, plan *Plan, roles map[int]planner.RoleBinding, baseExpr, contextCast string, hasOutput bool) error {
	maxFrames := plan.MaxFrames
	if maxFrames <= 0 {
		maxFrames = 64
	}
	b.WriteString("    size_t fuzzfw_offset = 0;\n")
	b.WriteString("    unsigned fuzzfw_frames = 0;\n")
	fmt.Fprintf(b, "    while (fuzzfw_offset + 4 <= size && fuzzfw_frames < %d) {\n", maxFrames)
	fmt.Fprintf(b, "        uint32_t fuzzfw_frame_len = (uint32_t)%s[fuzzfw_offset] |\n", baseExpr)
	fmt.Fprintf(b, "            ((uint32_t)%s[fuzzfw_offset + 1] << 8) |\n", baseExpr)
	fmt.Fprintf(b, "            ((uint32_t)%s[fuzzfw_offset + 2] << 16) |\n", baseExpr)
	fmt.Fprintf(b, "            ((uint32_t)%s[fuzzfw_offset + 3] << 24);\n", baseExpr)
	b.WriteString("        fuzzfw_offset += 4;\n")
	b.WriteString("        if ((size_t)fuzzfw_frame_len > size - fuzzfw_offset) break;\n")
	for _, role := range roles {
		if role.Role == planner.RoleLogicalLength {
			if macro := lengthGuardMacro(role.Type); macro != "" {
				fmt.Fprintf(b, "        if (fuzzfw_frame_len > %s) break;\n", macro)
			}
		}
	}
	b.WriteString("        uint8_t *frame_copy = (uint8_t *)malloc(fuzzfw_frame_len ? fuzzfw_frame_len : 1);\n")
	b.WriteString("        if (frame_copy == NULL) return 0;\n")
	b.WriteString("        if (fuzzfw_frame_len) memcpy(frame_copy, ")
	b.WriteString(baseExpr)
	b.WriteString(" + fuzzfw_offset, fuzzfw_frame_len); else frame_copy[0] = 0;\n")
	capture := invariantCapture(plan)
	if capture != "" {
		fmt.Fprintf(b, "        long long %s = 0;\n", capture)
	}
	for _, event := range plan.Target.Events {
		if event.Phase == "before" {
			fmt.Fprintf(b, "        %s();\n", event.Symbol)
		}
	}
	args, err := callArgs(plan, roles, "frame_copy", "fuzzfw_frame_len", hasOutput, contextCast)
	if err != nil {
		b.WriteString("        free(frame_copy);\n")
		return err
	}
	if err := emitCall(b, plan, args, capture, "        "); err != nil {
		b.WriteString("        free(frame_copy);\n")
		return err
	}
	for _, event := range plan.Target.Events {
		if event.Phase == "after" {
			fmt.Fprintf(b, "        %s();\n", event.Symbol)
		}
	}
	emitInvariant(b, plan, hasOutput, "        ")
	emitStateProbe(b, plan, "(uint32_t)fuzzfw_frames", contextCast, "        ")
	if plan.Target.FrameReset != "" {
		if plan.Target.ContextObject != nil {
			fmt.Fprintf(b, "        %s(%s);\n", plan.Target.FrameReset, contextCast)
		} else {
			fmt.Fprintf(b, "        %s();\n", plan.Target.FrameReset)
		}
	}
	b.WriteString("        free(frame_copy);\n")
	b.WriteString("        fuzzfw_offset += fuzzfw_frame_len;\n")
	b.WriteString("        fuzzfw_frames++;\n")
	b.WriteString("    }\n")
	return nil
}
func emitWrapper(plan *Plan) string {
	var b strings.Builder
	b.WriteString("/* GENERATED by fuzzfw; do not edit. */\n")
	b.WriteString("/* SPDX-License-Identifier: Apache-2.0 */\n")
	b.WriteString("#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n\n")
	b.WriteString("/* User wrapper ABI: void wrapper(const uint8_t *data, size_t size). */\n")
	fmt.Fprintf(&b, "extern void %s(const uint8_t *data, size_t size);\n\n", plan.Target.CallSymbol)
	b.WriteString("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n")
	fmt.Fprintf(&b, "    if (size > %d) return 0;\n", plan.maxInputFromConstraints())
	if plan.CopyInput {
		b.WriteString("    const uint8_t *input = NULL;\n")
		b.WriteString("    if (size > 0) {\n")
		b.WriteString("        input = (const uint8_t *)malloc(size);\n")
		b.WriteString("        if (input == NULL) return 0;\n")
		b.WriteString("        memcpy((void *)input, data, size);\n")
		b.WriteString("    } else {\n")
		b.WriteString("        uint8_t *empty = (uint8_t *)malloc(1);\n")
		b.WriteString("        if (empty == NULL) return 0;\n")
		b.WriteString("        empty[0] = 0;\n")
		b.WriteString("        input = empty;\n")
		b.WriteString("    }\n")
		fmt.Fprintf(&b, "    %s(input, size);\n", plan.Target.CallSymbol)
		b.WriteString("    free((void *)input);\n")
	} else {
		fmt.Fprintf(&b, "    %s(data, size);\n", plan.Target.CallSymbol)
	}
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

func methodName(qualified string) string {
	if idx := strings.LastIndex(qualified, "::"); idx >= 0 {
		return qualified[idx+2:]
	}
	return qualified
}

func targetContextArg(plan *Plan) int {
	if plan.Target.ContextObject == nil {
		return -1
	}
	return plan.Target.ContextObject.Arg
}

func contextPointerCast(typeName, value string) string {
	trimmed := strings.TrimSpace(typeName)
	if trimmed == "" || trimmed == "void *" {
		return value
	}
	return "(" + trimmed + ")" + value
}

func outputPointerCast(typeName, value string) string {
	trimmed := strings.TrimSpace(typeName)
	if trimmed == "" || trimmed == "void *" {
		return value
	}
	return "(" + trimmed + ")" + value
}

func emitStateProbe(b *strings.Builder, plan *Plan, indexExpr, contextCast, indent string) {
	if plan.Target.ContextObject != nil && plan.Target.StateProbe != "" {
		fmt.Fprintf(b, "%sint fuzzfw_state = %s(%s);\n", indent, plan.Target.StateProbe, contextCast)
		fmt.Fprintf(b, "%sfuzzfw_run_frame(%s, fuzzfw_state);\n", indent, indexExpr)
		return
	}
	if plan.Target.StateProbe != "" {
		fmt.Fprintf(b, "%sint fuzzfw_state = %s();\n", indent, plan.Target.StateProbe)
		fmt.Fprintf(b, "%sfuzzfw_run_frame(%s, fuzzfw_state);\n", indent, indexExpr)
		return
	}
	fmt.Fprintf(b, "%sfuzzfw_run_frame(%s, 0);\n", indent, indexExpr)
}

func invariantCapture(plan *Plan) string {
	if plan.Target.InvariantCheck == "" {
		return ""
	}
	return "fuzzfw_return"
}

func emitInvariant(b *strings.Builder, plan *Plan, hasOutput bool, indent string) {
	check := plan.Target.InvariantCheck
	if check == "" {
		return
	}
	outputExpr := "NULL"
	capacityExpr := "0"
	if hasOutput {
		outputExpr = "(const uint8_t *)output"
		capacityExpr = fmt.Sprintf("(size_t)%d", plan.OutputBytes)
	}
	switch plan.Target.InvariantArgs {
	case 1:
		fmt.Fprintf(b, "%sif (%s((int)fuzzfw_return) != 0) fuzzfw_invariant_failed(\"%s\");\n", indent, check, check)
	case 3:
		fmt.Fprintf(b, "%sif (%s((int)fuzzfw_return, %s, %s) != 0) fuzzfw_invariant_failed(\"%s\");\n", indent, check, outputExpr, capacityExpr, check)
	default:
		fmt.Fprintf(b, "%s/* invariant check has unsupported arity */\n", indent)
	}
}
