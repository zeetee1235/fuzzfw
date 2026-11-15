// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package planner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
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

func TestRawFactoryWithoutDestroyBlocked(t *testing.T) {
	fn := testFunction(
		analyzer.Param{Index: 0, Name: "data", Type: "const uint8_t *", CanonicalType: "const unsigned char *", IsPointer: true, IsConst: true},
		analyzer.Param{Index: 1, Name: "len", Type: "size_t", CanonicalType: "unsigned long", IsInteger: true, Bits: 64},
	)
	fn.IsMethod = true
	fn.QualifiedName = "RawParser::feed"
	fn.ParentType = "RawParser"
	factory := analyzer.Function{
		Name: "create", QualifiedName: "RawParser::create", ReturnType: "RawParser *",
		Signature: "RawParser *()", Definition: true, IsMethod: true, IsStaticMethod: true, ParentType: "RawParser",
	}
	analysis := &analyzer.Analysis{Functions: []analyzer.Function{factory}}
	plan, diagnostics := resolveFactory(analysis, fn, config.Target{Name: "raw", Factory: "RawParser::create"})
	if plan != nil || len(diagnostics) == 0 || diagnostics[0].Code != "E_HARNESS_CONTEXT_UNKNOWN" {
		t.Fatalf("plan=%+v diagnostics=%+v", plan, diagnostics)
	}
}

func TestFactoryClassMismatchBlocked(t *testing.T) {
	fn := testFunction()
	fn.IsMethod = true
	fn.QualifiedName = "Parser::feed"
	fn.ParentType = "Parser"
	factory := analyzer.Function{
		Name: "create", QualifiedName: "Other::create", ReturnType: "Other",
		Signature: "Other ()", Definition: true, IsMethod: true, IsStaticMethod: true, ParentType: "Other",
	}
	analysis := &analyzer.Analysis{Functions: []analyzer.Function{factory}}
	plan, diagnostics := resolveFactory(analysis, fn, config.Target{Name: "p", Factory: "Other::create"})
	if plan != nil || len(diagnostics) == 0 || diagnostics[0].Code != "E_CONTEXT_INVALID" {
		t.Fatalf("plan=%+v diagnostics=%+v", plan, diagnostics)
	}
}

func TestHardwareBoundaryModels(t *testing.T) {
	dma := []AdapterBinding{{OriginalSymbol: "DMA_Read", EventModel: "dma_completion", Completion: "deferred"}}
	blocked, _, diags := evaluateHardwareBoundaries(map[string]bool{"DMA_ASYNC": true}, dma, 0)
	if !blocked || len(diags) == 0 || diags[0].Code != "E_DMA_UNMODELED" {
		t.Fatalf("deferred DMA without events: blocked=%v diags=%+v", blocked, diags)
	}
	blocked, _, diags = evaluateHardwareBoundaries(map[string]bool{"DMA_ASYNC": true}, dma, 1)
	if blocked || len(diags) != 0 {
		t.Fatalf("modeled DMA with events: blocked=%v diags=%+v", blocked, diags)
	}
	blocked, _, _ = evaluateHardwareBoundaries(map[string]bool{"RTOS_CONTEXT": true}, nil, 1)
	if !blocked {
		t.Fatal("RTOS without adapter should be blocked")
	}
	rtos := []AdapterBinding{{OriginalSymbol: "osEvent", EventModel: "rtos_event"}}
	blocked, _, _ = evaluateHardwareBoundaries(map[string]bool{"RTOS_CONTEXT": true}, rtos, 1)
	if blocked {
		t.Fatal("modeled RTOS event should not be blocked")
	}
}

func TestStateProbeAndFrameResetSignatures(t *testing.T) {
	analysis := &analyzer.Analysis{Functions: []analyzer.Function{
		{Name: "state_probe", QualifiedName: "state_probe", Signature: "int (void)"},
		{Name: "frame_reset", QualifiedName: "frame_reset", Signature: "void (void)"},
		{Name: "ctx_probe", QualifiedName: "ctx_probe", Signature: "int (Ctx *)"},
		{Name: "ctx_frame_reset", QualifiedName: "ctx_frame_reset", Signature: "void (Ctx *)"},
		{Name: "bad_probe", QualifiedName: "bad_probe", Signature: "void (void)"},
		{Name: "bad_reset", QualifiedName: "bad_reset", Signature: "int (void)"},
		{Name: "bad_ctx_probe", QualifiedName: "bad_ctx_probe", Signature: "int (void)"},
	}}
	target := config.Target{Name: "parse", StateProbe: "state_probe", FrameReset: "frame_reset"}
	if diagnostic := validateStateProbe(analysis, target); diagnostic != nil {
		t.Fatalf("valid probe rejected: %v", diagnostic)
	}
	if diagnostic := validateFrameReset(analysis, target); diagnostic != nil {
		t.Fatalf("valid reset rejected: %v", diagnostic)
	}
	contextTarget := config.Target{Name: "parse", Context: &config.ContextConfig{Arg: 0}, StateProbe: "ctx_probe", FrameReset: "ctx_frame_reset"}
	if diagnostic := validateStateProbe(analysis, contextTarget); diagnostic != nil {
		t.Fatalf("valid context probe rejected: %v", diagnostic)
	}
	if diagnostic := validateFrameReset(analysis, contextTarget); diagnostic != nil {
		t.Fatalf("valid context reset rejected: %v", diagnostic)
	}
	for _, testCase := range []struct {
		name   string
		target config.Target
		probe  bool
	}{
		{"bad probe return", config.Target{Name: "parse", StateProbe: "bad_probe"}, true},
		{"missing probe", config.Target{Name: "parse", StateProbe: "missing_probe"}, true},
		{"bad reset return", config.Target{Name: "parse", FrameReset: "bad_reset"}, false},
		{"missing reset", config.Target{Name: "parse", FrameReset: "missing_reset"}, false},
		{"context probe without context argument", config.Target{Name: "parse", Context: &config.ContextConfig{Arg: 0}, StateProbe: "bad_ctx_probe"}, true},
	} {
		var diagnostic *diag.Diagnostic
		if testCase.probe {
			diagnostic = validateStateProbe(analysis, testCase.target)
		} else {
			diagnostic = validateFrameReset(analysis, testCase.target)
		}
		if diagnostic == nil {
			t.Fatalf("%s: expected a diagnostic", testCase.name)
		}
	}
}

func TestInvariantCheckSignatures(t *testing.T) {
	analysis := &analyzer.Analysis{Functions: []analyzer.Function{
		{Name: "packet_invariant", QualifiedName: "packet_invariant", Signature: "int (int, const uint8_t *, size_t)"},
		{Name: "ret_check", QualifiedName: "ret_check", Signature: "int (int)"},
		{Name: "bad_invariant", QualifiedName: "bad_invariant", Signature: "void (int)"},
		{Name: "bad_arity", QualifiedName: "bad_arity", Signature: "int (int, int)"},
	}}
	targetFn := &analyzer.Function{Name: "decode_packet", ReturnType: "int"}
	for _, testCase := range []struct {
		name string
		cfg  config.Target
		args int
		ok   bool
	}{
		{"three args", config.Target{Name: "decode_packet", InvariantCheck: "packet_invariant"}, 3, true},
		{"one arg", config.Target{Name: "decode_packet", InvariantCheck: "ret_check"}, 1, true},
		{"bad return", config.Target{Name: "decode_packet", InvariantCheck: "bad_invariant"}, 0, false},
		{"bad arity", config.Target{Name: "decode_packet", InvariantCheck: "bad_arity"}, 0, false},
		{"missing", config.Target{Name: "decode_packet", InvariantCheck: "missing"}, 0, false},
	} {
		diagnostic, args := validateInvariantCheck(analysis, testCase.cfg, targetFn)
		if testCase.ok {
			if diagnostic != nil || args != testCase.args {
				t.Fatalf("%s: diagnostic=%v args=%d", testCase.name, diagnostic, args)
			}
			continue
		}
		if diagnostic == nil {
			t.Fatalf("%s: expected a diagnostic", testCase.name)
		}
	}
	voidTarget := &analyzer.Function{Name: "decode_packet", ReturnType: "void"}
	if diagnostic, _ := validateInvariantCheck(analysis, config.Target{Name: "decode_packet", InvariantCheck: "ret_check"}, voidTarget); diagnostic == nil {
		t.Fatal("void target return should be rejected")
	}
}
