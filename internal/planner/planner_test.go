// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package planner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/config"
)

func testFunction(params ...analyzer.Param) *analyzer.Function {
	return &analyzer.Function{
		ID: "fn_test", Name: "parse", QualifiedName: "parse",
		Signature: "int (const uint8_t *, size_t)", ReturnType: "int",
		Source: "src/parse.c", Header: "include/parse.h",
		VariantID: "v1", TranslationUnit: "src/parse.c", Definition: true,
		Language: "c", Params: params,
	}
}

func TestInferRolesConstBufferLength(t *testing.T) {
	fn := testFunction(
		analyzer.Param{Index: 0, Name: "data", Type: "const uint8_t *", CanonicalType: "const unsigned char *", IsPointer: true, IsConst: true},
		analyzer.Param{Index: 1, Name: "len", Type: "size_t", CanonicalType: "unsigned long", IsInteger: true, Bits: 64},
	)
	fact := &analyzer.IRFunctionFact{Arguments: []analyzer.IRArgument{
		{Index: 0, ObservedUse: []string{"memory_read"}},
		{Index: 1, ObservedUse: []string{"compare", "branch"}},
	}}
	result := inferRoles(fn, fact, config.Target{Name: "parse"}, 4096)
	if result.blocked || result.ambiguous {
		t.Fatalf("result = %+v", result)
	}
	if result.input.BufferArg != 0 || result.input.LengthArg != 1 {
		t.Fatalf("input = %+v", result.input)
	}
	if result.roles[0].Role != RoleFuzzBytes || result.roles[1].Role != RoleLogicalLength {
		t.Fatalf("roles = %+v", result.roles)
	}
}

func TestOutputOnlyPointerIsBlocked(t *testing.T) {
	fn := testFunction(
		analyzer.Param{Index: 0, Name: "out", Type: "uint8_t *", CanonicalType: "unsigned char *", IsPointer: true},
		analyzer.Param{Index: 1, Name: "len", Type: "size_t", CanonicalType: "unsigned long", IsInteger: true, Bits: 64},
	)
	fact := &analyzer.IRFunctionFact{Arguments: []analyzer.IRArgument{
		{Index: 0, ObservedUse: []string{"memory_write"}},
		{Index: 1, ObservedUse: []string{"compare"}},
	}}
	result := inferRoles(fn, fact, config.Target{Name: "parse"}, 4096)
	if !result.blocked {
		t.Fatalf("expected blocked, got %+v", result)
	}
}

func TestAmbiguousPairsAdaptable(t *testing.T) {
	fn := testFunction(
		analyzer.Param{Index: 0, Name: "a", Type: "const uint8_t *", CanonicalType: "const unsigned char *", IsPointer: true, IsConst: true},
		analyzer.Param{Index: 1, Name: "b", Type: "const uint8_t *", CanonicalType: "const unsigned char *", IsPointer: true, IsConst: true},
		analyzer.Param{Index: 2, Name: "n", Type: "size_t", CanonicalType: "unsigned long", IsInteger: true, Bits: 64},
	)
	result := inferRoles(fn, nil, config.Target{Name: "parse"}, 4096)
	if !result.ambiguous {
		t.Fatalf("expected ambiguity, got %+v", result)
	}
}

func TestStaticFunctionInSourceBlocked(t *testing.T) {
	fn := testFunction(
		analyzer.Param{Index: 0, Name: "data", Type: "const uint8_t *", CanonicalType: "const unsigned char *", IsPointer: true, IsConst: true},
		analyzer.Param{Index: 1, Name: "len", Type: "size_t", CanonicalType: "unsigned long", IsInteger: true, Bits: 64},
	)
	fn.InternalLinkage = true
	cfg := &config.Config{Root: "/tmp", File: config.Defaults()}
	analysis := &analyzer.Analysis{
		Project:   analyzer.Project{Name: "p", Root: cfg.Root, SourceRevision: "rev"},
		Functions: []analyzer.Function{*fn},
		Variants:  []analyzer.Variant{{ID: "v1", File: "src/parse.c", HostTriple: "x86_64-unknown-linux-gnu", TargetTriple: "x86_64-unknown-linux-gnu"}},
	}
	plan, err := Build(cfg, analysis, "analysis", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Targets) != 1 || plan.Targets[0].Classification != Blocked {
		t.Fatalf("targets = %+v", plan.Targets)
	}
}

func TestUnapprovedHALCallBlocks(t *testing.T) {
	fn := testFunction(
		analyzer.Param{Index: 0, Name: "data", Type: "const uint8_t *", CanonicalType: "const unsigned char *", IsPointer: true, IsConst: true},
		analyzer.Param{Index: 1, Name: "len", Type: "size_t", CanonicalType: "unsigned long", IsInteger: true, Bits: 64},
	)
	fn.DirectCallees = []analyzer.CallRef{{Name: "HAL_UART_Read", Symbol: "HAL_UART_Read", Direct: true}}
	fn.HardwareFlags = []string{"HAL_EXTERNAL"}
	cfg := &config.Config{Root: "/tmp", File: config.Defaults()}
	analysis := &analyzer.Analysis{
		Project:   analyzer.Project{Name: "p", Root: cfg.Root, SourceRevision: "rev"},
		Functions: []analyzer.Function{*fn},
		Variants:  []analyzer.Variant{{ID: "v1", File: "src/parse.c", HostTriple: "x86_64-unknown-linux-gnu", TargetTriple: "x86_64-unknown-linux-gnu"}},
	}
	plan, err := Build(cfg, analysis, "analysis", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Targets) != 1 || plan.Targets[0].Classification != Blocked {
		t.Fatalf("targets = %+v", plan.Targets)
	}
	found := false
	for _, diagnostic := range plan.Targets[0].Diagnostics {
		if diagnostic.Code == "E_HAL_UNMODELED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing E_HAL_UNMODELED: %+v", plan.Targets[0].Diagnostics)
	}
}

func TestAdapterContractPrototypeMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "adapter.c")
	contract := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(source, []byte("int HAL_Read(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `{"schema_version":1,"original_symbol":"HAL_Read","prototype":"int(int)","model":"status_only","effects":["return_status"],"valid_context":"test","nondeterminism":"none"}`
	if err := os.WriteFile(contract, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Root: dir, File: config.Defaults()}
	adapter := config.Adapter{OriginalSymbol: "HAL_Read", ReplacementSource: source, Contract: contract}
	analysis := &analyzer.Analysis{ExternalDeclarations: []analyzer.Declaration{{
		Name: "HAL_Read", Signature: "int (void)", Source: "include/hal.h",
	}}}
	if _, diagnostic := loadAdapterBinding(cfg, adapter, analysis); diagnostic == nil || diagnostic.Code != "E_ADAPTER_INVALID" {
		t.Fatalf("expected prototype mismatch, got %+v", diagnostic)
	}
}

func TestTrivialInputAdapterRejected(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "adapter.c")
	contract := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(source, []byte("int HAL_Read(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `{"schema_version":1,"original_symbol":"HAL_Read","prototype":"int(void)","model":"input_source","effects":["write_buffer"],"valid_context":"test","nondeterminism":"none"}`
	if err := os.WriteFile(contract, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Root: dir, File: config.Defaults()}
	adapter := config.Adapter{OriginalSymbol: "HAL_Read", ReplacementSource: source, Contract: contract}
	analysis := &analyzer.Analysis{ExternalDeclarations: []analyzer.Declaration{{
		Name: "HAL_Read", Signature: "int (void)", Source: "include/hal.h",
	}}}
	if _, diagnostic := loadAdapterBinding(cfg, adapter, analysis); diagnostic == nil || diagnostic.Code != "E_ADAPTER_TRIVIAL" {
		t.Fatalf("expected trivial adapter rejection, got %+v", diagnostic)
	}
}
