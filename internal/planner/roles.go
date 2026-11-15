// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package planner

import (
	"fmt"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
)

type roleResult struct {
	input       InputModel
	roles       []RoleBinding
	constraints []Constraint
	reasons     []string
	diagnostics []diag.Diagnostic
	ambiguous   bool
	blocked     bool
}

var allowedRoles = map[string]bool{
	RoleFuzzBytes:        true,
	RoleFuzzBytesMutable: true,
	RoleLogicalLength:    true,
	RoleCapacity:         true,
	RoleOutputBuffer:     true,
	RoleContext:          true,
	RoleConfig:           true,
	RoleUnknown:          true,
}

func inferRoles(fn *analyzer.Function, fact *analyzer.IRFunctionFact, target config.Target, maxInputBytes int) roleResult {
	result := roleResult{
		input: InputModel{Kind: "bytes_length", BufferArg: -1, LengthArg: -1, CapacityArg: -1},
	}
	if target.Args != nil {
		return explicitRoles(fn, fact, target, maxInputBytes)
	}
	if len(fn.Params) == 0 {
		result.blocked = true
		result.reasons = append(result.reasons, "function has no parameters")
		result.diagnostics = append(result.diagnostics, diag.New(diag.ERoleAmbiguous,
			"function has no parameters; no input boundary can be synthesized",
		).WithTarget(fn.Name))
		return result
	}

	var buffers []argCandidate
	var lengths []argCandidate
	var others []argCandidate
	for index, param := range fn.Params {
		if param.IsPointer {
			base := pointeeBase(param)
			switch {
			case isCharLike(base):
				score := 0
				if param.IsConst {
					score += 3
				}
				if hasNameHint(param.Name, bufferHints) {
					score += 2
				}
				buffers = append(buffers, argCandidate{index: index, param: param, score: score, kind: "buffer"})
			case base == "void":
				buffers = append(buffers, argCandidate{index: index, param: param, score: -2, kind: "void_buffer"})
			default:
				others = append(others, argCandidate{index: index, param: param, score: 0, kind: "context"})
			}
			continue
		}
		if param.IsInteger {
			score := 0
			if hasNameHint(param.Name, lengthHints) {
				score += 3
			}
			if normalizeTypeBase(param.CanonicalType) == "size_t" {
				score += 2
			}
			lengths = append(lengths, argCandidate{index: index, param: param, score: score, kind: "length"})
			continue
		}
		others = append(others, argCandidate{index: index, param: param, kind: "config"})
	}

	if len(buffers) == 0 || len(lengths) == 0 {
		result.blocked = true
		switch {
		case len(buffers) == 0:
			result.reasons = append(result.reasons, "no byte-buffer pointer parameter was identified")
		case len(lengths) == 0:
			result.reasons = append(result.reasons, "no logical length parameter was identified")
		}
		result.diagnostics = append(result.diagnostics, diag.New(diag.ERoleAmbiguous,
			"cannot identify a bytes+length entry boundary from AST/IR evidence",
		).WithTarget(fn.Name).WithEvidence(result.reasons...))
		return result
	}

	bestBuffer, bestLength, ambiguous := choosePair(buffers, lengths, fact)
	if ambiguous {
		result.ambiguous = true
		result.reasons = append(result.reasons, "multiple equally plausible buffer/length pairs")
		result.diagnostics = append(result.diagnostics, diag.New(diag.ERoleAmbiguous,
			"multiple equally plausible buffer/length argument pairs; automatic synthesis refused",
		).WithTarget(fn.Name).WithEvidence(result.reasons...))
		return result
	}

	bufferUses := irUses(fact, bestBuffer.index)
	lengthUses := irUses(fact, bestLength.index)
	bufferRole := RoleFuzzBytes
	switch {
	case hasUse(bufferUses, "memory_write") && !hasUse(bufferUses, "memory_read"):
		bufferRole = RoleOutputBuffer
		result.ambiguous = true
		result.reasons = append(result.reasons, "pointer appears to be write-only in IR; treated as output buffer, not fuzz input")
	case !bestBuffer.param.IsConst:
		bufferRole = RoleFuzzBytesMutable
		if !hasUse(bufferUses, "memory_read") && fact != nil {
			result.ambiguous = true
			result.reasons = append(result.reasons, "mutable pointer has no observed read; mutable input is not proven")
		}
	}
	if bestBuffer.kind == "void_buffer" && target.Input != "bytes_length" {
		result.ambiguous = true
		result.reasons = append(result.reasons, "void* buffer lacks a typed input contract")
	}

	result.input.BufferArg = bestBuffer.index
	result.input.LengthArg = bestLength.index
	result.roles = append(result.roles,
		RoleBinding{
			Argument: bestBuffer.index, Role: bufferRole, Source: "fuzz_input",
			Type: bestBuffer.param.Type, Evidence: bufferEvidence(bestBuffer.param, bufferUses),
		},
		RoleBinding{
			Argument: bestLength.index, Role: RoleLogicalLength, Source: "fuzz_input.size",
			Type: bestLength.param.Type, Evidence: lengthEvidence(bestLength.param, lengthUses),
		},
	)
	result.reasons = append(result.reasons, "bytes+length boundary selected from type and observed uses")

	for _, candidate := range buffers {
		if candidate.index == bestBuffer.index {
			continue
		}
		result.roles = append(result.roles, RoleBinding{
			Argument: candidate.index, Role: RoleUnknown, Source: "unassigned",
			Type: candidate.param.Type, Evidence: []string{"additional_pointer"},
		})
		result.ambiguous = true
	}
	for _, candidate := range lengths {
		if candidate.index == bestLength.index {
			continue
		}
		role := RoleUnknown
		if hasNameHint(candidate.param.Name, capacityHints) {
			role = RoleCapacity
			result.input.CapacityArg = candidate.index
			result.ambiguous = true
			result.reasons = append(result.reasons, "capacity/length relation is not verified")
		}
		result.roles = append(result.roles, RoleBinding{
			Argument: candidate.index, Role: role, Source: "unassigned",
			Type: candidate.param.Type, Evidence: []string{"additional_integer"},
		})
	}
	for _, candidate := range others {
		role := RoleContext
		if candidate.kind == "config" {
			role = RoleConfig
		}
		result.roles = append(result.roles, RoleBinding{
			Argument: candidate.index, Role: role, Source: "unassigned",
			Type: candidate.param.Type, Evidence: []string{"non_buffer_argument"},
		})
		result.ambiguous = true
	}
	if bufferRole == RoleOutputBuffer {
		result.blocked = true
		result.diagnostics = append(result.diagnostics, diag.New(diag.ERoleAmbiguous,
			"only an output buffer was identified; no external fuzz bytes boundary exists",
		).WithTarget(fn.Name))
	}

	if fact == nil {
		result.reasons = append(result.reasons, "IR facts unavailable; role inference is type/name-only")
	}
	result.constraints = buildConstraints(fn, bestBuffer.param, bestLength.param, bufferRole, result.input, maxInputBytes, target.Args != nil)
	return result
}

func explicitRoles(fn *analyzer.Function, fact *analyzer.IRFunctionFact, target config.Target, maxInputBytes int) roleResult {
	result := roleResult{
		input: InputModel{Kind: "bytes_length", BufferArg: -1, LengthArg: -1, CapacityArg: -1},
	}
	if len(target.Args) != len(fn.Params) {
		result.blocked = true
		result.diagnostics = append(result.diagnostics, diag.Newf(diag.EConfigInvalid,
			"target %s: args has %d roles but %s has %d parameters",
			target.Name, len(target.Args), fn.Name, len(fn.Params),
		).WithTarget(target.Name))
		return result
	}
	for index, role := range target.Args {
		role = strings.TrimSpace(role)
		if !allowedRoles[role] {
			result.blocked = true
			result.diagnostics = append(result.diagnostics, diag.Newf(diag.EConfigInvalid,
				"target %s: unknown role %q for argument %d", target.Name, role, index,
			).WithTarget(target.Name))
			return result
		}
		param := fn.Params[index]
		result.roles = append(result.roles, RoleBinding{
			Argument: index, Role: role, Source: "user_contract", Type: param.Type,
			Evidence: []string{"user_contract", fmt.Sprintf("ast_param:%s", param.Type)},
		})
		switch role {
		case RoleFuzzBytes, RoleFuzzBytesMutable:
			result.input.BufferArg = index
		case RoleLogicalLength:
			result.input.LengthArg = index
		case RoleCapacity:
			result.input.CapacityArg = index
		case RoleContext:
			result.blocked = true
			result.reasons = append(result.reasons, "explicit CONTEXT argument is unsupported in P0; provide a wrapper")
		case RoleOutputBuffer:
			result.blocked = true
			result.reasons = append(result.reasons, "explicit OUTPUT_BUFFER synthesis is P1; provide a wrapper")
		case RoleConfig:
			result.blocked = true
			result.reasons = append(result.reasons, "explicit CONFIG argument has no value source; provide a wrapper")
		case RoleUnknown:
			result.ambiguous = true
			result.reasons = append(result.reasons, "explicit UNKNOWN role cannot be synthesized")
		}
	}
	if result.input.BufferArg < 0 || result.input.LengthArg < 0 {
		result.blocked = true
		result.reasons = append(result.reasons, "explicit roles must include one buffer and one logical length")
		result.diagnostics = append(result.diagnostics, diag.New(diag.ERoleAmbiguous,
			"explicit role mapping lacks a fuzz-byte buffer and logical length",
		).WithTarget(fn.Name))
		return result
	}
	bufferParam := fn.Params[result.input.BufferArg]
	lengthParam := fn.Params[result.input.LengthArg]
	result.constraints = buildConstraints(fn, bufferParam, lengthParam, target.Args[result.input.BufferArg], result.input, maxInputBytes, true)
	if result.input.CapacityArg >= 0 {
		result.constraints = append(result.constraints, Constraint{
			Expr: "capacity == size", Basis: "user_contract",
			Evidence: []string{"target.args explicitly assigns CAPACITY; harness uses one size for both"},
		})
		result.reasons = append(result.reasons, "capacity is derived from the same input size by explicit user contract")
	}
	if fact == nil {
		result.reasons = append(result.reasons, "IR facts unavailable; user role contract is authoritative")
	}
	return result
}

type argCandidate struct {
	index int
	param analyzer.Param
	score int
	kind  string
}

func choosePair(buffers, lengths []argCandidate, fact *analyzer.IRFunctionFact) (argCandidate, argCandidate, bool) {
	bestScore := -1 << 30
	var bestBuffer, bestLength argCandidate
	ties := 0
	for _, buffer := range buffers {
		bufferUses := irUses(fact, buffer.index)
		for _, length := range lengths {
			lengthUses := irUses(fact, length.index)
			score := buffer.score + length.score
			if hasUse(bufferUses, "memory_read") {
				score += 4
			}
			if hasUse(bufferUses, "memory_write") {
				score++
			}
			if hasUse(bufferUses, "memory_write") && !hasUse(bufferUses, "memory_read") {
				score -= 6
			}
			if hasUse(bufferUses, "passed_to_call") {
				score++
			}
			if hasUse(lengthUses, "compare") {
				score += 2
			}
			if hasUse(lengthUses, "branch") {
				score += 2
			}
			if hasUse(lengthUses, "indexed") {
				score += 2
			}
			if hasUse(lengthUses, "loop_bound") {
				score += 3
			}
			if hasUse(lengthUses, "compare_constant") {
				score++
			}
			if hasUse(lengthUses, "allocation_size") {
				score++
			}
			if hasUse(lengthUses, "memory_write") {
				score -= 6
			}
			if hasUse(lengthUses, "memory_read") {
				score++
			}
			switch {
			case score > bestScore:
				bestScore = score
				bestBuffer = buffer
				bestLength = length
				ties = 1
			case score == bestScore:
				ties++
			}
		}
	}
	return bestBuffer, bestLength, ties > 1
}

func bufferEvidence(param analyzer.Param, uses []string) []string {
	evidence := []string{fmt.Sprintf("type:%s", param.Type)}
	if param.IsConst {
		evidence = append(evidence, "type:const_pointer")
	}
	if hasNameHint(param.Name, bufferHints) {
		evidence = append(evidence, "name_hint:"+param.Name)
	}
	for _, use := range uses {
		evidence = append(evidence, "ir:"+use)
	}
	return evidence
}

func lengthEvidence(param analyzer.Param, uses []string) []string {
	evidence := []string{fmt.Sprintf("type:%s", param.Type)}
	if hasNameHint(param.Name, lengthHints) {
		evidence = append(evidence, "name_hint:"+param.Name)
	}
	if macro, ok := analyzer.LengthLimitMacro(param); ok {
		evidence = append(evidence, "guard:"+macro)
	}
	for _, use := range uses {
		evidence = append(evidence, "ir:"+use)
	}
	return evidence
}

func buildConstraints(fn *analyzer.Function, bufferParam, lengthParam analyzer.Param, bufferRole string, input InputModel, maxInputBytes int, explicit bool) []Constraint {
	constraints := []Constraint{{
		Expr: fmt.Sprintf("size <= %d", maxInputBytes), Basis: "configured_engine_limit",
		Evidence: []string{"harness.max_input_bytes"},
	}}
	if macro, ok := analyzer.LengthLimitMacro(lengthParam); ok {
		constraints = append(constraints, Constraint{
			Expr: "size <= " + macro, Basis: "compiler_abi",
			Evidence: []string{"logical length type: " + lengthParam.CanonicalType},
		})
	} else {
		constraints = append(constraints, Constraint{
			Expr: "size fits logical length type", Basis: "heuristic",
			Evidence: []string{"unrecognized integer type: " + lengthParam.CanonicalType},
		})
	}
	if bufferRole == RoleFuzzBytesMutable {
		constraints = append(constraints, Constraint{
			Expr: "copy_lifetime >= target_call", Basis: "harness_contract",
			Evidence: []string{"mutable input is copied into a harness-owned buffer"},
		})
	}
	if input.CapacityArg >= 0 {
		basis := "heuristic"
		if explicit {
			basis = "user_contract"
		}
		constraints = append(constraints, Constraint{
			Expr: "capacity == size", Basis: basis,
			Evidence: []string{"capacity argument present"},
		})
	}
	return constraints
}

func irUses(fact *analyzer.IRFunctionFact, index int) []string {
	if fact == nil {
		return nil
	}
	for _, argument := range fact.Arguments {
		if argument.Index == index {
			return append([]string(nil), argument.ObservedUse...)
		}
	}
	return nil
}

func hasUse(uses []string, want string) bool {
	for _, use := range uses {
		if use == want || strings.HasPrefix(use, want+"_") {
			return true
		}
	}
	return false
}

func pointeeBase(param analyzer.Param) string {
	text := param.CanonicalType
	if star := strings.LastIndex(text, "*"); star >= 0 {
		text = text[:star]
	}
	return normalizeTypeBase(text)
}

func normalizeTypeBase(value string) string {
	replacer := strings.NewReplacer(
		"const", " ", "volatile", " ", "restrict", " ", "__restrict", " ", "__restrict__", " ",
		"struct", " ", "class", " ", "enum", " ", "&", " ",
	)
	value = replacer.Replace(value)
	value = strings.ReplaceAll(value, "std::", "")
	return strings.Join(strings.Fields(value), " ")
}

func isCharLike(base string) bool {
	switch base {
	case "char", "signed char", "unsigned char", "uint8_t", "int8_t":
		return true
	default:
		return false
	}
}

var bufferHints = []string{"buf", "data", "packet", "input", "payload", "msg", "message", "frame", "bytes", "src", "in"}
var lengthHints = []string{"len", "length", "size", "count", "n", "bytes", "sz"}
var capacityHints = []string{"cap", "capacity", "max", "limit", "room"}

func hasNameHint(name string, hints []string) bool {
	lower := strings.ToLower(name)
	for _, hint := range hints {
		if hint == "n" {
			if lower == "n" {
				return true
			}
			continue
		}
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}
