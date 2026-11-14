// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/proc"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

type nativeInvocation struct {
	SchemaVersion int      `json:"schema_version"`
	Root          string   `json:"root"`
	Directory     string   `json:"directory"`
	File          string   `json:"file"`
	Language      string   `json:"language"`
	VariantID     string   `json:"variant_id"`
	Arguments     []string `json:"arguments"`
}

type nativeFragment struct {
	SchemaVersion int           `json:"schema_version"`
	Generator     string        `json:"generator"`
	Functions     []Function    `json:"functions"`
	Declarations  []Declaration `json:"declarations"`
}

// nativeAnalyzerPath returns the native LibTooling analyzer when available.
func nativeAnalyzerPath(cfg *config.Config, tools *toolchain.Report) string {
	if os.Getenv("FUZZFW_DISABLE_NATIVE") == "1" {
		return ""
	}
	if cfg.File.Analysis.Analyzer != "" {
		if fsutil.Exists(cfg.File.Analysis.Analyzer) {
			return cfg.File.Analysis.Analyzer
		}
		if resolved, err := proc.LookPath(cfg.File.Analysis.Analyzer); err == nil {
			return resolved
		}
	}
	if tools != nil {
		if tool, ok := tools.Tools["fuzzfw-analyze"]; ok && tool.Found {
			return tool.Path
		}
	}
	return ""
}

func analyzeCommandNative(
	ctx context.Context,
	cfg *config.Config,
	command compdb.Command,
	tools *toolchain.Report,
) ([]Function, []Declaration, []diag.Diagnostic, bool) {
	analyzerPath := nativeAnalyzerPath(cfg, tools)
	if analyzerPath == "" {
		return nil, nil, nil, false
	}
	tempDir, err := os.MkdirTemp("", "fuzzfw-native-analyze-*")
	if err != nil {
		return nil, nil, []diag.Diagnostic{diag.Newf(diag.EInternal, "cannot create analyzer temp dir: %v", err).Warning().WithTarget(command.File)}, false
	}
	defer os.RemoveAll(tempDir)
	inputPath := filepath.Join(tempDir, "input.json")
	outputPath := filepath.Join(tempDir, "fragment.json")
	args := append([]string(nil), command.Arguments...)
	if resourceDir := clangResourceDir(ctx, cfg); resourceDir != "" {
		// FixedCompilationDatabase does not infer the Clang resource directory
		// when the original compiler was GCC. Add it explicitly without
		// changing user macros or include paths.
		args = append([]string{args[0], "-resource-dir", resourceDir}, args[1:]...)
	}
	invocation := nativeInvocation{
		SchemaVersion: 1,
		Root:          cfg.Root,
		Directory:     command.Directory,
		File:          command.File,
		Language:      command.Language,
		VariantID:     command.VariantID,
		Arguments:     args,
	}
	data, err := json.Marshal(invocation)
	if err != nil {
		return nil, nil, nil, false
	}
	if err := fsutil.WriteFileAtomic(inputPath, data, 0o644); err != nil {
		return nil, nil, nil, false
	}
	result, err := (proc.Runner{Timeout: time.Duration(cfg.File.Analysis.TimeoutSeconds) * time.Second}).
		Run(ctx, cfg.Root, analyzerPath, "--input", inputPath, "--output", outputPath)
	if err != nil || result == nil || !result.OK() {
		message := "native analyzer failed"
		var evidence []string
		if result != nil {
			message = fmt.Sprintf("native analyzer exited %d", result.ExitCode)
			evidence = append(evidence, firstLines(result.Stderr, 6))
		}
		if err != nil {
			message += ": " + err.Error()
		}
		d := diag.Newf(diag.WARNativeAnalyzer, "%s for %s", message, filepath.Base(command.File)).Warning().WithTarget(command.File).WithEvidence(evidence...)
		return nil, nil, []diag.Diagnostic{d}, false
	}
	var fragment nativeFragment
	if err := fsutil.ReadJSON(outputPath, &fragment); err != nil {
		d := diag.Newf(diag.WARNativeAnalyzer, "cannot decode native analyzer output: %v", err).Warning().WithTarget(command.File)
		return nil, nil, []diag.Diagnostic{d}, false
	}
	if fragment.SchemaVersion != 1 {
		d := diag.Newf(diag.WARNativeAnalyzer, "unsupported native analyzer schema %d", fragment.SchemaVersion).Warning().WithTarget(command.File)
		return nil, nil, []diag.Diagnostic{d}, false
	}
	for i := range fragment.Functions {
		fn := &fragment.Functions[i]
		fn.VariantID = command.VariantID
		fn.TranslationUnit = fsutil.Rel(cfg.Root, command.File)
		if fn.Language == "" {
			fn.Language = command.Language
		}
		if fn.ID == "" {
			fn.ID = functionID(*fn)
		}
	}
	for i := range fragment.Declarations {
		fragment.Declarations[i].VariantID = command.VariantID
	}
	return fragment.Functions, fragment.Declarations, nil, true
}

func clangResourceDir(ctx context.Context, cfg *config.Config) string {
	result, err := proc.RunSimple(ctx, cfg.Root, 10*time.Second, cfg.File.Host.Clang, "-print-resource-dir")
	if err != nil || result == nil || !result.OK() {
		return ""
	}
	return stringsTrim(result.Stdout)
}

func stringsTrim(value string) string {
	for len(value) > 0 && (value[len(value)-1] == '\n' || value[len(value)-1] == '\r' || value[len(value)-1] == ' ') {
		value = value[:len(value)-1]
	}
	return value
}

type nativeIRDocument struct {
	SchemaVersion int              `json:"schema_version"`
	Generator     string           `json:"generator"`
	TargetTriple  string           `json:"target_triple"`
	Facts         []IRFunctionFact `json:"facts"`
}

func analyzeIRNative(
	ctx context.Context,
	cfg *config.Config,
	tools *toolchain.Report,
	functions []Function,
	irText string,
	variant Variant,
	hostTriple string,
) ([]IRFunctionFact, bool) {
	toolPath := ""
	if os.Getenv("FUZZFW_DISABLE_NATIVE") == "1" {
		return nil, false
	}
	if cfg.File.Analysis.IRAnalyzer != "" {
		if fsutil.Exists(cfg.File.Analysis.IRAnalyzer) {
			toolPath = cfg.File.Analysis.IRAnalyzer
		} else if resolved, err := proc.LookPath(cfg.File.Analysis.IRAnalyzer); err == nil {
			toolPath = resolved
		}
	}
	if toolPath == "" && tools != nil {
		if tool, ok := tools.Tools["fuzzfw-ir-analyze"]; ok && tool.Found {
			toolPath = tool.Path
		}
	}
	if toolPath == "" {
		return nil, false
	}
	tempDir, err := os.MkdirTemp("", "fuzzfw-native-ir-*")
	if err != nil {
		return nil, false
	}
	defer os.RemoveAll(tempDir)
	irPath := filepath.Join(tempDir, "module.ll")
	outputPath := filepath.Join(tempDir, "facts.json")
	if err := fsutil.WriteFileAtomic(irPath, []byte(irText), 0o644); err != nil {
		return nil, false
	}
	result, err := (proc.Runner{Timeout: time.Duration(cfg.File.Analysis.TimeoutSeconds) * time.Second}).
		Run(ctx, cfg.Root, toolPath, "--input", irPath, "--output", outputPath)
	if err != nil || result == nil || !result.OK() {
		return nil, false
	}
	var document nativeIRDocument
	if err := fsutil.ReadJSON(outputPath, &document); err != nil || document.SchemaVersion != 1 {
		return nil, false
	}
	bySymbol := map[string]string{}
	for _, fn := range functions {
		bySymbol[fn.MangledName] = fn.ID
		bySymbol[fn.Name] = fn.ID
	}
	for i := range document.Facts {
		fact := &document.Facts[i]
		fact.FunctionID = bySymbol[fact.LinkSymbol]
		fact.HostTriple = hostTriple
		if fact.TargetTriple == "" {
			fact.TargetTriple = firstNonEmpty(variant.TargetTriple, document.TargetTriple)
		}
		if fact.IRMapping == "" {
			fact.IRMapping = "resolved"
		}
		var unknowns []string
		for _, unknown := range fact.Unknowns {
			if strings.HasPrefix(unknown, "external_call:") &&
				AllowedExternalCall(strings.TrimPrefix(unknown, "external_call:")) {
				continue
			}
			unknowns = append(unknowns, unknown)
		}
		fact.Unknowns = unknowns
	}
	sort.Slice(document.Facts, func(i, j int) bool { return document.Facts[i].LinkSymbol < document.Facts[j].LinkSymbol })
	return document.Facts, true
}
