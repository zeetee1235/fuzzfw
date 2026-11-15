// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package planner

import (
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
)

// buildContextPlan validates an explicit C context object and its lifecycle.
func buildContextPlan(analysis *analyzer.Analysis, target config.Target) (*ContextObjectPlan, []diag.Diagnostic) {
	if target.Context == nil {
		return nil, nil
	}
	if target.Context.Size <= 0 {
		return nil, []diag.Diagnostic{diag.New(diag.EContextInvalid,
			"context.size must be positive").WithTarget(target.Name)}
	}
	plan := &ContextObjectPlan{
		Arg: target.Context.Arg, Size: target.Context.Size,
		Init: target.Context.Init, Reset: target.Context.Reset, Destroy: target.Context.Destroy,
	}
	if fn, ok := findFactory(analysis, target.Context.Init); !ok {
		return nil, []diag.Diagnostic{diag.Newf(diag.EContextUnknown,
			"context init function %s is not declared", target.Context.Init).WithTarget(target.Name)}
	} else {
		returnType, params := analyzer.ParseFunctionType(fn.Signature)
		if !contextFunctionParams(params) {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
				"context init %s must take one pointer argument", fn.QualifiedName).WithTarget(target.Name)}
		}
		if returnType != "void" && returnType != "int" {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
				"context init %s must return void or int, got %s", fn.QualifiedName, returnType).WithTarget(target.Name)}
		}
		plan.InitReturnsInt = returnType == "int"
	}
	if plan.Reset != "" {
		fn, ok := findFactory(analysis, plan.Reset)
		if !ok {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextUnknown,
				"context reset function %s is not declared", plan.Reset).WithTarget(target.Name)}
		}
		returnType, params := analyzer.ParseFunctionType(fn.Signature)
		if !contextFunctionParams(params) || returnType != "void" {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
				"context reset %s must be void(pointer)", fn.QualifiedName).WithTarget(target.Name)}
		}
	}
	if plan.Destroy != "" {
		fn, ok := findFactory(analysis, plan.Destroy)
		if !ok {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextUnknown,
				"context destroy function %s is not declared", plan.Destroy).WithTarget(target.Name)}
		}
		returnType, params := analyzer.ParseFunctionType(fn.Signature)
		if !contextFunctionParams(params) || returnType != "void" {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
				"context destroy %s must be void(pointer)", fn.QualifiedName).WithTarget(target.Name)}
		}
	}
	return plan, nil
}

func contextFunctionParams(params []string) bool {
	return len(params) == 1 && strings.Contains(params[0], "*")
}

func validateStateProbe(analysis *analyzer.Analysis, target config.Target) *diag.Diagnostic {
	fn, ok := findFactory(analysis, target.StateProbe)
	if !ok {
		d := diag.Newf(diag.EContextUnknown, "state probe %s is not declared", target.StateProbe).WithTarget(target.Name)
		return &d
	}
	returnType, params := analyzer.ParseFunctionType(fn.Signature)
	if returnType != "int" {
		d := diag.Newf(diag.EContextInvalid, "state probe %s must return int", fn.QualifiedName).WithTarget(target.Name)
		return &d
	}
	if target.Context != nil {
		if !contextFunctionParams(params) {
			d := diag.Newf(diag.EContextInvalid, "context state probe %s must take one pointer", fn.QualifiedName).WithTarget(target.Name)
			return &d
		}
	} else if len(params) != 0 {
		d := diag.Newf(diag.EContextInvalid, "state probe %s must take no arguments", fn.QualifiedName).WithTarget(target.Name)
		return &d
	}
	return nil
}

func validateFrameReset(analysis *analyzer.Analysis, target config.Target) *diag.Diagnostic {
	fn, ok := findFactory(analysis, target.FrameReset)
	if !ok {
		d := diag.Newf(diag.EContextUnknown, "frame reset %s is not declared", target.FrameReset).WithTarget(target.Name)
		return &d
	}
	returnType, params := analyzer.ParseFunctionType(fn.Signature)
	if returnType != "void" {
		d := diag.Newf(diag.EContextInvalid, "frame reset %s must return void", fn.QualifiedName).WithTarget(target.Name)
		return &d
	}
	if target.Context != nil {
		if !contextFunctionParams(params) {
			d := diag.Newf(diag.EContextInvalid, "context frame reset %s must take one pointer", fn.QualifiedName).WithTarget(target.Name)
			return &d
		}
	} else if len(params) != 0 {
		d := diag.Newf(diag.EContextInvalid, "frame reset %s must take no arguments", fn.QualifiedName).WithTarget(target.Name)
		return &d
	}
	return nil
}

func validateInvariantCheck(analysis *analyzer.Analysis, target config.Target, targetFn *analyzer.Function) (*diag.Diagnostic, int) {
	if target.InvariantCheck == "" {
		return nil, 0
	}
	if targetFn != nil && !integerValueType(targetFn.ReturnType) {
		d := diag.Newf(diag.EContextInvalid,
			"invariant_check requires an integer target return type, got %s", targetFn.ReturnType).WithTarget(target.Name)
		return &d, 0
	}
	fn, ok := findFactory(analysis, target.InvariantCheck)
	if !ok {
		d := diag.Newf(diag.EContextUnknown,
			"invariant check %s is not declared", target.InvariantCheck).WithTarget(target.Name)
		return &d, 0
	}
	returnType, params := analyzer.ParseFunctionType(fn.Signature)
	if returnType != "int" {
		d := diag.Newf(diag.EContextInvalid,
			"invariant check %s must return int", fn.QualifiedName).WithTarget(target.Name)
		return &d, 0
	}
	switch len(params) {
	case 1:
		if !integerValueType(params[0]) {
			d := diag.Newf(diag.EContextInvalid,
				"invariant check %s one-argument form must be int(int)", fn.QualifiedName).WithTarget(target.Name)
			return &d, 0
		}
	case 3:
		if !integerValueType(params[0]) || !strings.Contains(params[1], "*") ||
			!strings.Contains(params[1], "const") || !integerValueType(params[2]) {
			d := diag.Newf(diag.EContextInvalid,
				"invariant check %s three-argument form must be int(int, const uint8_t *, size_t)", fn.QualifiedName).WithTarget(target.Name)
			return &d, 0
		}
	default:
		d := diag.Newf(diag.EContextInvalid,
			"invariant check %s must take one or three arguments", fn.QualifiedName).WithTarget(target.Name)
		return &d, 0
	}
	return nil, len(params)
}

func integerValueType(typeName string) bool {
	text := strings.TrimSpace(typeName)
	if text == "" || strings.Contains(text, "*") || strings.Contains(text, "[") {
		return false
	}
	text = strings.TrimPrefix(text, "const ")
	text = strings.TrimPrefix(text, "unsigned ")
	text = strings.TrimPrefix(text, "signed ")
	switch text {
	case "void", "float", "double", "long double", "struct", "union":
		return false
	}
	if strings.HasPrefix(text, "struct ") || strings.HasPrefix(text, "union ") || strings.HasPrefix(text, "float") || strings.HasPrefix(text, "double") {
		return false
	}
	return true
}
