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

// AdapterDefinition is the source-level evidence for a reviewed adapter.
type AdapterDefinition struct {
	Symbol         string
	Signature      string
	StatementCount int
	TrivialReturn  bool
	Source         string
}

// CheckAdapterDefinition parses an adapter source and confirms that the
// replacement symbol is actually defined. It is a consistency check, not proof
// that the adapter models the hardware correctly.
func CheckAdapterDefinition(ctx context.Context, cfg *config.Config, source string, includeDirs, defines []string, symbol string) (*AdapterDefinition, error) {
	compiler := cfg.File.Host.Clang
	language := "c"
	extension := strings.ToLower(filepath.Ext(source))
	if extension == ".cpp" || extension == ".cc" || extension == ".cxx" {
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
	args = append(args,
		source,
		"-Xclang", "-ast-dump=json",
		"-fsyntax-only",
		"-fno-color-diagnostics",
		"-Wno-error",
		"-Wno-unused-command-line-argument",
	)
	result, err := (proc.Runner{Timeout: time.Duration(cfg.File.Analysis.TimeoutSeconds) * time.Second}).
		Run(ctx, cfg.Root, args...)
	if err != nil {
		return nil, fmt.Errorf("adapter AST analysis failed to start: %w", err)
	}
	if result == nil || !result.OK() {
		message := "adapter AST analysis failed"
		if result != nil {
			message = fmt.Sprintf("adapter AST analysis failed (exit %d): %s", result.ExitCode, firstLines(result.Stderr, 6))
		}
		return nil, fmt.Errorf("%s", message)
	}
	doc, err := decodeAST([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("cannot decode adapter AST: %w", err)
	}
	node := findFunctionDefinition(doc.Inner, symbol)
	if node == nil {
		return nil, fmt.Errorf("adapter does not define symbol %s", symbol)
	}
	definition := &AdapterDefinition{
		Symbol:    symbol,
		Signature: node.Type.QualType,
		Source:    fsutilRel(cfg.Root, source),
	}
	for _, child := range node.Inner {
		if child.Kind != "CompoundStmt" {
			continue
		}
		definition.StatementCount = len(child.Inner)
		if len(child.Inner) == 1 && child.Inner[0].Kind == "ReturnStmt" && isConstantReturn(&child.Inner[0]) {
			definition.TrivialReturn = true
		}
	}
	return definition, nil
}

func findFunctionDefinition(nodes []astNode, symbol string) *astNode {
	for i := range nodes {
		node := &nodes[i]
		if (node.Kind == "FunctionDecl" || node.Kind == "CXXMethodDecl") &&
			(node.Name == symbol || node.MangledName == symbol) && node.hasKind("CompoundStmt") {
			return node
		}
		if found := findFunctionDefinition(node.Inner, symbol); found != nil {
			return found
		}
	}
	return nil
}

func isConstantReturn(node *astNode) bool {
	for _, child := range node.Inner {
		if child.Kind == "IntegerLiteral" || child.Kind == "GNUNullExpr" ||
			child.Kind == "CXXBoolLiteralExpr" {
			return true
		}
		if child.Kind == "ImplicitCastExpr" || child.Kind == "CStyleCastExpr" {
			if isConstantReturn(&child) {
				return true
			}
		}
	}
	return false
}

func fsutilRel(root, path string) string {
	// Keep this helper local to avoid making adapter checks depend on the whole
	// path utility package.
	if root == "" {
		return path
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(relative, "..") {
		return path
	}
	return filepath.ToSlash(relative)
}
