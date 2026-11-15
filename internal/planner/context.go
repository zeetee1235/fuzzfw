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
