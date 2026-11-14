// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package analyzer

import "testing"

func TestSplitFunctionType(t *testing.T) {
	ret, params := splitFunctionType("int (const unsigned char *, size_t)")
	if ret != "int" || len(params) != 2 || params[0] != "const unsigned char *" || params[1] != "size_t" {
		t.Fatalf("ret=%q params=%#v", ret, params)
	}
	ret, _ = splitFunctionType("void (*)(int)")
	if ret != "void" {
		t.Fatalf("function-pointer return = %q", ret)
	}
}

func TestParamClassification(t *testing.T) {
	buffer := makeParam(0, "data", "const uint8_t *")
	if !buffer.IsPointer || !buffer.IsConst || buffer.IsInteger {
		t.Fatalf("buffer = %+v", buffer)
	}
	length := makeParam(1, "len", "uint16_t")
	if !length.IsInteger || length.IsSigned || length.Bits != 16 {
		t.Fatalf("length = %+v", length)
	}
	if macro, ok := LengthLimitMacro(length); !ok || macro != "UINT16_MAX" {
		t.Fatalf("macro = %q %t", macro, ok)
	}
	signed := makeParam(1, "len", "ssize_t")
	if !signed.IsSigned {
		t.Fatalf("ssize_t signed = %+v", signed)
	}
}

func TestParseIRArgumentUses(t *testing.T) {
	ir := `target triple = "x86_64-unknown-linux-gnu"
@g_state = global i32 0

define i32 @decode(ptr noundef %data, i64 noundef %len) {
entry:
  %len.addr = alloca i64
  store i64 %len, ptr %len.addr
  %loaded = load i64, ptr %len.addr
  %cmp = icmp ult i64 %loaded, 4
  br i1 %cmp, label %bad, label %ok
bad:
  ret i32 -1
ok:
  %idx = getelementptr inbounds i8, ptr %data, i64 0
  %byte = load volatile i8, ptr %idx
  store i32 1, ptr @g_state
  %out = call i32 @external_helper(ptr %data)
  ret i32 %out
}

declare i32 @external_helper(ptr)
`
	module := parseIR(ir)
	if module == nil || len(module.functions) != 1 {
		t.Fatalf("module = %#v", module)
	}
	fn := module.functions["decode"]
	if fn == nil {
		t.Fatal("decode not parsed")
	}
	fact := summarizeIR(fn, module, Variant{File: "a.c"}, "x86_64-unknown-linux-gnu")
	arg0 := findArg(fact, 0)
	arg1 := findArg(fact, 1)
	if !containsUse(arg0, "memory_read") {
		t.Fatalf("arg0 uses = %#v", arg0)
	}
	if !containsUse(arg1, "compare") || !containsUse(arg1, "branch") {
		t.Fatalf("arg1 uses = %#v", arg1)
	}
	if !containsString(fact.HardwareFlags, "MMIO_DIRECT") {
		t.Fatalf("hardware flags = %#v", fact.HardwareFlags)
	}
	if !containsString(fact.GlobalEffects, "write:g_state") {
		t.Fatalf("global effects = %#v", fact.GlobalEffects)
	}
	if !containsString(fact.Unknowns, "external_call:external_helper") {
		t.Fatalf("unknowns = %#v", fact.Unknowns)
	}
}

func findArg(fact IRFunctionFact, index int) IRArgument {
	for _, arg := range fact.Arguments {
		if arg.Index == index {
			return arg
		}
	}
	return IRArgument{Index: index}
}

func containsUse(arg IRArgument, use string) bool {
	return containsString(arg.ObservedUse, use)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
