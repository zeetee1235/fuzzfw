// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package harness

import (
	"strings"
	"testing"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/planner"
)

func testPlan(t *testing.T) *Plan {
	t.Helper()
	fn := &analyzer.Function{Name: "parse", QualifiedName: "parse", ID: "fn", Signature: "int (const uint8_t *, size_t)", Source: "src/parse.c", Header: "include/parse.h", Language: "c", VariantID: "v1", TranslationUnit: "src/parse.c", Definition: true}
	target := planner.TargetPlan{
		Name: "parse", Symbol: "parse", FunctionID: "fn", QualifiedName: "parse",
		Signature: fn.Signature, MangledName: "parse", Source: "src/parse.c", Header: "include/parse.h",
		Language: "c", VariantID: "v1", Classification: planner.ReadyCandidate,
		MaxInputBytes: 256, Function: fn,
		InputModel: planner.InputModel{Kind: "bytes_length", BufferArg: 0, LengthArg: 1},
		Roles: []planner.RoleBinding{
			{Argument: 0, Role: planner.RoleFuzzBytes, Source: "fuzz_input", Type: "const uint8_t *"},
			{Argument: 1, Role: planner.RoleLogicalLength, Source: "fuzz_input.size", Type: "size_t"},
		},
		Constraints: []planner.Constraint{{Expr: "size <= 256", Basis: "configured_engine_limit"}},
		Context:     planner.ContextPlan{ResetPolicy: "isolated"},
	}
	plan, err := BuildPlan(target, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestEmitConstBuffer(t *testing.T) {
	plan := testPlan(t)
	plan.CopyInput = true
	source, extension, err := Emit(plan, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if extension != ".c" {
		t.Fatalf("extension = %s", extension)
	}
	for _, want := range []string{
		`#include "include/parse.h"`,
		`if (size > 256) return 0;`,
		`const uint8_t *input = NULL;`,
		`memcpy((void *)input, data, size);`,
		`(void)parse(input, size);`,
		`free((void *)input);`,
		`int LLVMFuzzerTestOneInput`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
	if !strings.Contains(source, "malloc(size)") {
		t.Fatal("const buffer should be copied into an exact-size allocation")
	}
}

func TestEmitMutableBufferCopies(t *testing.T) {
	plan := testPlan(t)
	plan.RoleBindings[0].Role = planner.RoleFuzzBytesMutable
	source, _, err := Emit(plan, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"malloc(size)", "memcpy(copy, data, size)", "free(copy)", "(void)parse(copy, size)"} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
}

func TestHarnessIDIsDeterministic(t *testing.T) {
	a := testPlan(t)
	b := testPlan(t)
	if a.HarnessID != b.HarnessID {
		t.Fatalf("IDs differ: %s %s", a.HarnessID, b.HarnessID)
	}
}

func TestEmitFactoryValueAndPointer(t *testing.T) {
	plan := testPlan(t)
	plan.Target.Language = "c++"
	plan.Target.SourceHeader = "include/parser.hpp"
	plan.Target.CallSymbol = "Parser::feed"
	plan.Target.MethodName = "feed"
	plan.Target.Factory = &planner.FactoryPlan{
		Symbol: "Parser::create_default", ClassType: "Parser", ReturnType: "Parser", Style: "value",
	}
	source, extension, err := Emit(plan, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if extension != ".cpp" {
		t.Fatalf("extension = %s", extension)
	}
	for _, want := range []string{"auto fuzzfw_object = Parser::create_default();", "(void)fuzzfw_object.feed(data, size);"} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
	plan.Target.Factory = &planner.FactoryPlan{
		Symbol: "RawParser::create", ClassType: "RawParser", ReturnType: "RawParser *", Style: "pointer", Destroy: "RawParser::destroy",
	}
	plan.Target.CallSymbol = "RawParser::feed"
	source, _, err = Emit(plan, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"auto *fuzzfw_object = RawParser::create();", "fuzzfw_object->feed(data, size);", "RawParser::destroy(fuzzfw_object);"} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
}

func TestSequenceHarnessEmitsFrames(t *testing.T) {
	plan := testPlan(t)
	plan.CopyInput = true
	plan.InputKind = "length_prefixed"
	plan.MaxFrames = 8
	plan.Target.StateProbe = "state_probe"
	plan.Target.FrameReset = "state_frame_reset"
	source, _, err := Emit(plan, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"while (fuzzfw_offset + 4 <= size",
		"fuzzfw_frame_len",
		"frame_copy",
		"fuzzfw_frames++",
		"fuzzfw_run_begin();",
		"int fuzzfw_state = state_probe();",
		"fuzzfw_run_frame((uint32_t)fuzzfw_frames, fuzzfw_state);",
		"state_frame_reset();",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
}

func TestSequenceHarnessContextStateProbe(t *testing.T) {
	plan := testPlan(t)
	plan.CopyInput = true
	plan.InputKind = "length_prefixed"
	plan.MaxFrames = 8
	plan.Target.ContextObject = &planner.ContextObjectPlan{
		Arg: 2, Size: 8, Init: "ctx_init", InitReturnsInt: true, Reset: "ctx_reset", Destroy: "ctx_destroy",
	}
	plan.Target.StateProbe = "ctx_state"
	plan.Target.FrameReset = "ctx_frame_reset"
	plan.RoleBindings = append(plan.RoleBindings, planner.RoleBinding{
		Argument: 2, Role: planner.RoleContext, Source: "explicit_context", Type: "Ctx *",
	})
	source, _, err := Emit(plan, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"void *fuzzfw_context = calloc(1, 8);",
		"if (ctx_init((Ctx *)fuzzfw_context) != 0)",
		"(void)parse(frame_copy, fuzzfw_frame_len, (Ctx *)fuzzfw_context);",
		"int fuzzfw_state = ctx_state((Ctx *)fuzzfw_context);",
		"fuzzfw_run_frame((uint32_t)fuzzfw_frames, fuzzfw_state);",
		"ctx_frame_reset((Ctx *)fuzzfw_context);",
		"ctx_reset((Ctx *)fuzzfw_context);",
		"ctx_destroy((Ctx *)fuzzfw_context);",
		"free(fuzzfw_context);",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
}

func TestInvariantCheckEmission(t *testing.T) {
	plan := testPlan(t)
	plan.Target.InvariantCheck = "packet_invariant"
	plan.Target.InvariantArgs = 1
	source, _, err := Emit(plan, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"long long fuzzfw_return = 0;",
		"fuzzfw_return = parse(data, size);",
		`if (packet_invariant((int)fuzzfw_return) != 0) fuzzfw_invariant_failed("packet_invariant");`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
}

func TestInvariantCheckOutputEmission(t *testing.T) {
	plan := testPlan(t)
	plan.CopyInput = true
	plan.OutputBytes = 16
	plan.Target.InvariantCheck = "packet_invariant"
	plan.Target.InvariantArgs = 3
	plan.RoleBindings = append(plan.RoleBindings,
		planner.RoleBinding{Argument: 2, Role: planner.RoleOutputBuffer, Source: "output", Type: "uint8_t *"},
		planner.RoleBinding{Argument: 3, Role: planner.RoleCapacity, Source: "output.capacity", Type: "size_t"},
	)
	source, _, err := Emit(plan, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"long long fuzzfw_return = 0;",
		"fuzzfw_return = parse(input, size, (uint8_t *)output, 16);",
		`if (packet_invariant((int)fuzzfw_return, (const uint8_t *)output, (size_t)16) != 0) fuzzfw_invariant_failed("packet_invariant");`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
}
