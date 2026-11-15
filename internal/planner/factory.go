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

// resolveFactory validates the explicit C++ object construction path. It never
// invents a constructor or treats raw zeroed memory as an object.
func resolveFactory(analysis *analyzer.Analysis, fn *analyzer.Function, target config.Target) (*FactoryPlan, []diag.Diagnostic) {
	if target.Factory == "" {
		return nil, []diag.Diagnostic{diag.New(diag.EContextUnknown,
			"C++ method requires targets.factory or a user wrapper").WithTarget(target.Name)}
	}
	if !fn.IsMethod {
		return nil, []diag.Diagnostic{diag.New(diag.EContextInvalid,
			"targets.factory is only valid for C++ member functions").WithTarget(target.Name)}
	}
	factory, ok := findFactory(analysis, target.Factory)
	if !ok {
		return nil, []diag.Diagnostic{diag.Newf(diag.EContextUnknown,
			"factory %s is not defined or declared in analyzed translation units", target.Factory,
		).WithTarget(target.Name)}
	}
	if factory.IsMethod && !factory.IsStaticMethod {
		return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
			"factory %s is a non-static member function; use a static factory or unit-test sequence", factory.QualifiedName,
		).WithTarget(target.Name)}
	}
	parent := fn.ParentType
	if parent == "" {
		parent = classFromQualified(fn.QualifiedName)
	}
	if parent == "" {
		return nil, []diag.Diagnostic{diag.New(diag.EContextInvalid,
			"cannot determine the target class from the qualified function name").WithTarget(target.Name)}
	}
	factoryParent := factory.ParentType
	if factoryParent == "" {
		factoryParent = classFromQualified(factory.QualifiedName)
	}
	if factory.IsMethod && factoryParent != "" && lastComponent(factoryParent) != lastComponent(parent) {
		return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
			"factory %s belongs to %s, target belongs to %s", factory.QualifiedName, factoryParent, parent,
		).WithTarget(target.Name)}
	}
	returnType := factory.ReturnType
	if returnType == "" {
		returnType = analyzer.ParseReturnType(factory.Signature)
	}
	style, classType := factoryStyle(returnType)
	if style == "" || classType == "" {
		return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
			"factory %s returns unsupported type %q; use value, pointer + destroy, unique_ptr, or shared_ptr",
			factory.QualifiedName, returnType,
		).WithTarget(target.Name)}
	}
	if lastComponent(classType) != lastComponent(parent) {
		return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
			"factory %s returns %s, expected target class %s", factory.QualifiedName, classType, parent,
		).WithTarget(target.Name)}
	}
	plan := &FactoryPlan{
		Symbol: factory.QualifiedName, ClassType: classType, ReturnType: returnType, Style: style,
	}
	if style == "pointer" {
		if target.Destroy == "" {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextUnknown,
				"factory %s returns a raw pointer; targets.destroy is required", factory.QualifiedName,
			).WithTarget(target.Name)}
		}
		destroy, exists := findFactory(analysis, target.Destroy)
		if !exists {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextUnknown,
				"destroy function %s is not declared in analyzed translation units", target.Destroy,
			).WithTarget(target.Name)}
		}
		if !destroyAcceptsPointer(destroy) {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
				"destroy function %s does not take a pointer argument", destroy.QualifiedName,
			).WithTarget(target.Name)}
		}
		if returnType := analyzer.ParseReturnType(destroy.Signature); returnType != "" && returnType != "void" {
			return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
				"destroy function %s returns %s, expected void", destroy.QualifiedName, returnType,
			).WithTarget(target.Name)}
		}
		plan.Destroy = destroy.QualifiedName
	}
	if style != "pointer" && target.Destroy != "" {
		return nil, []diag.Diagnostic{diag.Newf(diag.EContextInvalid,
			"targets.destroy is only valid when the factory returns a raw pointer; factory %s returns %s",
			factory.QualifiedName, returnType,
		).WithTarget(target.Name)}
	}
	return plan, nil
}

func findFactory(analysis *analyzer.Analysis, symbol string) (*analyzer.Function, bool) {
	var matches []*analyzer.Function
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if fn.Name == symbol || fn.QualifiedName == symbol || fn.MangledName == symbol {
			matches = append(matches, fn)
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if fn.QualifiedName == symbol {
			return fn, true
		}
	}
	return nil, false
}

func destroyAcceptsPointer(fn *analyzer.Function) bool {
	return len(fn.Params) == 1 && fn.Params[0].IsPointer
}

func classFromQualified(qualified string) string {
	if idx := strings.LastIndex(qualified, "::"); idx > 0 {
		return qualified[:idx]
	}
	return ""
}

func lastComponent(value string) string {
	if idx := strings.LastIndex(value, "::"); idx >= 0 {
		value = value[idx+2:]
	}
	value = strings.ReplaceAll(value, " ", "")
	if idx := strings.Index(value, "<"); idx >= 0 {
		value = value[:idx]
	}
	return value
}

func factoryStyle(returnType string) (string, string) {
	text := strings.TrimSpace(returnType)
	text = strings.ReplaceAll(text, "const ", "")
	text = strings.ReplaceAll(text, "volatile ", "")
	text = strings.ReplaceAll(text, "std::", "")
	if strings.HasPrefix(text, "unique_ptr<") && strings.HasSuffix(text, ">") {
		return "unique_ptr", strings.TrimSuffix(strings.TrimPrefix(text, "unique_ptr<"), ">")
	}
	if strings.HasPrefix(text, "shared_ptr<") && strings.HasSuffix(text, ">") {
		return "shared_ptr", strings.TrimSuffix(strings.TrimPrefix(text, "shared_ptr<"), ">")
	}
	if strings.HasSuffix(text, "*") {
		return "pointer", strings.TrimSpace(strings.TrimSuffix(text, "*"))
	}
	if strings.HasSuffix(text, "&") {
		return "", ""
	}
	if strings.ContainsAny(text, "*&") {
		return "", ""
	}
	if text == "" || text == "void" {
		return "", ""
	}
	return "value", text
}

func factoryDescription(plan *FactoryPlan) string {
	return fmt.Sprintf("%s (%s)", plan.Symbol, plan.Style)
}
