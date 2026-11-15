// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package analyzer

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/proc"
)

// UnitTestContext is setup/teardown evidence extracted from an existing unit
// test callsite. It is intentionally limited to direct zero-argument calls
// around the target call.
type UnitTestContext struct {
	Function    string   `json:"function"`
	Source      string   `json:"source"`
	Setup       []string `json:"setup,omitempty"`
	Teardown    []string `json:"teardown,omitempty"`
	TargetCalls int      `json:"target_calls"`
}

// ExtractUnitTestContext parses one unit-test function and extracts direct
// zero-argument calls before and after the target call.
func ExtractUnitTestContext(ctx context.Context, cfg *config.Config, source, function, targetSymbol, targetName string, includeDirs, defines []string) (*UnitTestContext, error) {
	compiler := cfg.File.Host.Clang
	language := "c"
	switch strings.ToLower(filepath.Ext(source)) {
	case ".cpp", ".cc", ".cxx":
		compiler = cfg.File.Host.ClangXX
		language = "c++"
	}
	args := []string{compiler, "-I", cfg.Root}
	for _, dir := range includeDirs {
		args = append(args, "-I", dir)
	}
	for _, define := range defines {
		args = append(args, "-D"+define)
	}
	if language == "c++" {
		args = append(args, "-std=c++17")
	} else {
		args = append(args, "-std=c11")
	}
	args = append(args, source, "-Xclang", "-ast-dump=json", "-fsyntax-only",
		"-fno-color-diagnostics", "-Wno-error", "-Wno-unused-command-line-argument")
	result, err := (proc.Runner{Timeout: time.Duration(cfg.File.Analysis.TimeoutSeconds) * time.Second}).Run(ctx, cfg.Root, args...)
	if err != nil {
		return nil, fmt.Errorf("unit-test AST analysis failed to start: %w", err)
	}
	if result == nil || !result.OK() {
		message := "unit-test AST analysis failed"
		if result != nil {
			message = fmt.Sprintf("unit-test AST analysis failed (exit %d): %s", result.ExitCode, firstLines(result.Stderr, 6))
		}
		return nil, fmt.Errorf("%s", message)
	}
	doc, err := decodeAST([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("cannot decode unit-test AST: %w", err)
	}
	node := findFunctionDefinition(doc.Inner, function)
	if node == nil && function == "" {
		node = findTestFunction(doc.Inner)
	}
	if node == nil {
		return nil, fmt.Errorf("unit-test function %q was not found", function)
	}
	info := &UnitTestContext{Function: node.Name, Source: fsutilRel(cfg.Root, source)}
	for _, child := range node.Inner {
		if child.Kind != "CompoundStmt" {
			continue
		}
		for i := range child.Inner {
			call, argCount, ok := statementCall(&child.Inner[i])
			if !ok {
				continue
			}
			if call.Name == targetSymbol || call.Symbol == targetSymbol || call.Name == targetName {
				info.TargetCalls++
				continue
			}
			if argCount != 0 {
				continue
			}
			if info.TargetCalls > 0 {
				info.Teardown = append(info.Teardown, call.Name)
			} else {
				info.Setup = append(info.Setup, call.Name)
			}
		}
	}
	info.Setup = uniqueStrings(info.Setup)
	info.Teardown = uniqueStrings(info.Teardown)
	if info.TargetCalls == 0 {
		return nil, fmt.Errorf("unit-test function %s does not call %s", node.Name, targetSymbol)
	}
	return info, nil
}

func findTestFunction(nodes []astNode) *astNode {
	for i := range nodes {
		node := &nodes[i]
		if node.Kind == "FunctionDecl" && strings.HasPrefix(node.Name, "test") && node.hasKind("CompoundStmt") {
			return node
		}
		if found := findTestFunction(node.Inner); found != nil {
			return found
		}
	}
	return nil
}

func statementCall(node *astNode) (CallRef, int, bool) {
	if node.Kind != "CallExpr" || len(node.Inner) == 0 {
		return CallRef{}, 0, false
	}
	call, ok := findDirectCallee(node)
	return call, len(node.Inner) - 1, ok
}
