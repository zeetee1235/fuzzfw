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
		`(void)parse(data, size);`,
		`int LLVMFuzzerTestOneInput`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("missing %q in:\n%s", want, source)
		}
	}
	if strings.Contains(source, "malloc") {
		t.Fatal("const buffer should not be copied")
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
