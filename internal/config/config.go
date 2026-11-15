// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package config loads and validates fuzzfw.toml.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
)

// FileName is the conventional configuration file name.
const FileName = "fuzzfw.toml"

// SchemaVersion is the current configuration schema.
const SchemaVersion = 1

// File is the raw TOML shape. Defaults are applied before decoding.
type File struct {
	SchemaVersion int       `toml:"schema_version"`
	Project       Project   `toml:"project"`
	Host          Host      `toml:"host"`
	Analysis      Analysis  `toml:"analysis"`
	Harness       Harness   `toml:"harness"`
	CI            CI        `toml:"ci"`
	Targets       []Target  `toml:"targets"`
	Adapters      []Adapter `toml:"adapters"`
}

// Project identifies source and build metadata.
type Project struct {
	Name           string `toml:"name"`
	Source         string `toml:"source"`
	CompDB         string `toml:"compdb"`
	ArtifactDir    string `toml:"artifact_dir"`
	SourceRevision string `toml:"source_revision"`
}

// Host describes the Linux host build profile.
type Host struct {
	Triple         string   `toml:"triple"`
	Clang          string   `toml:"clang"`
	ClangXX        string   `toml:"clangxx"`
	BuildCommand   []string `toml:"build_command"`
	LinkLibraries  []string `toml:"link_libraries"`
	LinkObjects    []string `toml:"link_objects"`
	Libraries      []string `toml:"libraries"`
	ExtraCFlags    []string `toml:"extra_cflags"`
	ExtraLDFlags   []string `toml:"extra_ldflags"`
	Sanitizers     []string `toml:"sanitizers"`
	Optimization   string   `toml:"optimization"`
	Coverage       bool     `toml:"coverage"`
	CoverageMode   string   `toml:"coverage_mode"`
	TimeoutSeconds int      `toml:"timeout_seconds"`
}

// Analysis controls Clang AST/IR analysis.
type Analysis struct {
	TimeoutSeconds int      `toml:"timeout_seconds"`
	ExtraArgs      []string `toml:"extra_args"`
	EmitIR         bool     `toml:"emit_ir"`
	IROptLevel     string   `toml:"ir_opt_level"`
	ASTOnly        bool     `toml:"ast_only"`
	MaxFunctions   int      `toml:"max_functions"`
	MaxIRBytes     int      `toml:"max_ir_bytes"`
	Analyzer       string   `toml:"analyzer"`
	IRAnalyzer     string   `toml:"ir_analyzer"`
}

// Harness controls generated harness limits and replay policy.
type Harness struct {
	MaxInputBytes         int  `toml:"max_input_bytes"`
	ReproductionAttempts  int  `toml:"reproduction_attempts"`
	Minimize              bool `toml:"minimize"`
	MinInputBytes         int  `toml:"min_input_bytes"`
	PreserveNonNilOnEmpty bool `toml:"preserve_nonnull_on_empty"`
	PersistentResetCheck  bool `toml:"persistent_reset_check"`
	CopyInput             bool `toml:"copy_input"`
}

// CI controls the check/fuzz gate.
type CI struct {
	Mode                string `toml:"mode"`
	Engine              string `toml:"engine"`
	TimeSeconds         int    `toml:"time_seconds"`
	Jobs                int    `toml:"jobs"`
	FailOnNewReproduced bool   `toml:"fail_on_new_reproduced"`
	IncompleteIsFailure bool   `toml:"incomplete_is_failure"`
	Baseline            string `toml:"baseline"`
	CorpusDir           string `toml:"corpus_dir"`
	OutputDir           string `toml:"output_dir"`
	MaxFindings         int    `toml:"max_findings"`
	PerTargetSeconds    int    `toml:"per_target_seconds"`
}

// Target is a user-declared fuzz target or an explicit wrapper escape hatch.
type Target struct {
	Name            string            `toml:"name"`
	Symbol          string            `toml:"symbol"`
	Source          string            `toml:"source"`
	Header          string            `toml:"header"`
	Required        bool              `toml:"required"`
	Input           string            `toml:"input"`
	MaxInputBytes   int               `toml:"max_input_bytes"`
	Setup           string            `toml:"setup"`
	Teardown        string            `toml:"teardown"`
	Factory         string            `toml:"factory"`
	FactoryLifetime string            `toml:"factory_lifetime"`
	Destroy         string            `toml:"destroy"`
	WrapperSymbol   string            `toml:"wrapper_symbol"`
	WrapperSource   string            `toml:"wrapper_source"`
	Seeds           []string          `toml:"seeds"`
	Args            []string          `toml:"args"`
	BuildVariant    string            `toml:"build_variant"`
	Events          []EventHookConfig `toml:"events"`
}

// EventHookConfig is an explicit event dispatch around the target call.
type EventHookConfig struct {
	Symbol string `toml:"symbol"`
	Phase  string `toml:"phase"` // before or after
}

// Adapter is an approved replacement for an external hardware symbol.
type Adapter struct {
	OriginalSymbol    string `toml:"original_symbol"`
	ReplacementSource string `toml:"replacement_source"`
	Contract          string `toml:"contract"`
}

// Config is a validated configuration with absolute paths.
type Config struct {
	Path        string
	Root        string
	CompDB      string
	ArtifactDir string
	File        File
	Targets     []Target
	Adapters    []Adapter
	Fingerprint string
}

// Defaults returns a config with safe explicit defaults.
func Defaults() File {
	return File{
		SchemaVersion: SchemaVersion,
		Project: Project{
			Source:         ".",
			CompDB:         "build/compile_commands.json",
			ArtifactDir:    ".fuzzfw",
			SourceRevision: "auto",
		},
		Host: Host{
			Triple:         "x86_64-unknown-linux-gnu",
			Clang:          "clang",
			ClangXX:        "clang++",
			Sanitizers:     []string{"address", "undefined"},
			Optimization:   "-O1",
			Coverage:       true,
			CoverageMode:   "trace-pc-guard",
			TimeoutSeconds: 300,
		},
		Analysis: Analysis{
			TimeoutSeconds: 300,
			EmitIR:         true,
			IROptLevel:     "-O0",
			MaxFunctions:   5000,
			MaxIRBytes:     64 * 1024 * 1024,
		},
		Harness: Harness{
			MaxInputBytes:         4096,
			ReproductionAttempts:  3,
			Minimize:              true,
			PreserveNonNilOnEmpty: true,
			PersistentResetCheck:  true,
			CopyInput:             true,
		},
		CI: CI{
			Mode:                "pr",
			Engine:              "honggfuzz",
			TimeSeconds:         600,
			Jobs:                2,
			FailOnNewReproduced: true,
			IncompleteIsFailure: true,
			MaxFindings:         50,
		},
	}
}

// Discover walks from start towards the filesystem root looking for fuzzfw.toml.
func Discover(start string) string {
	path, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		if filepath.Base(path) == FileName {
			return path
		}
		path = filepath.Dir(path)
	}
	for {
		candidate := filepath.Join(path, FileName)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(path)
		if parent == path {
			return ""
		}
		path = parent
	}
}

// Load reads a config file or returns defaults when requireFile is false.
func Load(path, start string, requireFile bool) (*Config, error) {
	if path == "" {
		path = Discover(start)
	}
	if path == "" {
		if requireFile {
			return nil, &diag.Error{
				Code:        diag.EConfigNotFound,
				Message:     "no fuzzfw.toml found; pass --config or create one",
				ExitCode:    exitcode.Usage,
				Remediation: "See docs/reference/configuration.md for the schema.",
			}
		}
		root, err := filepath.Abs(start)
		if err != nil {
			return nil, err
		}
		file := Defaults()
		file.Project.Name = filepath.Base(root)
		return normalize(file, "", root)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &diag.Error{
				Code:     diag.EConfigNotFound,
				Message:  fmt.Sprintf("configuration file not found: %s", abs),
				ExitCode: exitcode.Usage,
			}
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	file := Defaults()
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, &diag.Error{
			Code:     diag.EConfigInvalid,
			Message:  fmt.Sprintf("invalid configuration %s: %v", abs, err),
			ExitCode: exitcode.Usage,
		}
	}
	if file.SchemaVersion != SchemaVersion {
		return nil, &diag.Error{
			Code:     diag.EConfigInvalid,
			Message:  fmt.Sprintf("unsupported schema_version %d; expected %d", file.SchemaVersion, SchemaVersion),
			ExitCode: exitcode.Usage,
		}
	}
	base := filepath.Dir(abs)
	return normalize(file, abs, base)
}

// Default returns a config rooted at start without reading any file.
func Default(root string) (*Config, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	file := Defaults()
	file.Project.Name = filepath.Base(abs)
	return normalize(file, "", abs)
}

func normalize(file File, path, base string) (*Config, error) {
	if file.Project.Name == "" {
		file.Project.Name = filepath.Base(base)
	}
	root := filepath.Clean(fsutil.Resolve(base, file.Project.Source))
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil, &diag.Error{
			Code:     diag.EConfigNotFound,
			Message:  fmt.Sprintf("project.source is not a directory: %s", root),
			ExitCode: exitcode.Usage,
		}
	}
	compDB := filepath.Clean(fsutil.Resolve(root, file.Project.CompDB))
	artifactDir := filepath.Clean(fsutil.Resolve(root, file.Project.ArtifactDir))

	if file.Project.SourceRevision == "" {
		file.Project.SourceRevision = "auto"
	}
	if len(file.Host.Sanitizers) == 0 {
		file.Host.Sanitizers = []string{"address", "undefined"}
	}
	for _, sanitizer := range file.Host.Sanitizers {
		switch sanitizer {
		case "address", "undefined", "leak", "memory", "thread":
		default:
			return nil, usageError(fmt.Sprintf("unknown sanitizer: %s", sanitizer))
		}
	}
	switch file.Host.Optimization {
	case "-O0", "-O1", "-O2", "-O3", "-Os", "-Oz":
	default:
		return nil, usageError(fmt.Sprintf("host.optimization must be -O0..-O3, -Os, or -Oz; got %q", file.Host.Optimization))
	}
	if file.Host.CoverageMode != "trace-pc-guard" && file.Host.CoverageMode != "none" {
		return nil, usageError("host.coverage_mode must be trace-pc-guard or none")
	}
	if file.Host.TimeoutSeconds <= 0 {
		return nil, usageError("host.timeout_seconds must be positive")
	}
	if file.Analysis.TimeoutSeconds <= 0 {
		return nil, usageError("analysis.timeout_seconds must be positive")
	}
	if file.Analysis.MaxFunctions <= 0 {
		return nil, usageError("analysis.max_functions must be positive")
	}
	if file.Analysis.MaxIRBytes <= 0 {
		return nil, usageError("analysis.max_ir_bytes must be positive")
	}
	file.Analysis.Analyzer = resolveToolPath(root, file.Analysis.Analyzer)
	file.Analysis.IRAnalyzer = resolveToolPath(root, file.Analysis.IRAnalyzer)
	if file.Harness.MaxInputBytes <= 0 {
		return nil, usageError("harness.max_input_bytes must be positive")
	}
	if file.Harness.ReproductionAttempts <= 0 {
		return nil, usageError("harness.reproduction_attempts must be positive")
	}
	if file.Harness.MinInputBytes < 0 || file.Harness.MinInputBytes > file.Harness.MaxInputBytes {
		return nil, usageError("harness.min_input_bytes must be between 0 and max_input_bytes")
	}
	switch file.CI.Mode {
	case "pr", "nightly", "release":
	default:
		return nil, usageError(fmt.Sprintf("ci.mode must be pr, nightly, or release; got %q", file.CI.Mode))
	}
	switch file.CI.Engine {
	case "honggfuzz", "libfuzzer", "replay":
	default:
		return nil, usageError(fmt.Sprintf("ci.engine must be honggfuzz, libfuzzer, or replay; got %q", file.CI.Engine))
	}
	if file.CI.TimeSeconds <= 0 || file.CI.Jobs <= 0 || file.CI.MaxFindings <= 0 {
		return nil, usageError("ci.time_seconds, ci.jobs, and ci.max_findings must be positive")
	}
	if file.CI.PerTargetSeconds < 0 {
		return nil, usageError("ci.per_target_seconds must not be negative")
	}
	file.CI.Baseline = resolveOptional(root, file.CI.Baseline)
	file.CI.CorpusDir = resolveOptional(root, file.CI.CorpusDir)
	file.CI.OutputDir = resolveOptional(root, file.CI.OutputDir)

	targets := make([]Target, 0, len(file.Targets))
	seenTargets := map[string]bool{}
	for i := range file.Targets {
		target := file.Targets[i]
		if strings.TrimSpace(target.Name) == "" {
			return nil, usageError(fmt.Sprintf("targets[%d].name is required", i))
		}
		if seenTargets[target.Name] {
			return nil, usageError(fmt.Sprintf("duplicate target name: %s", target.Name))
		}
		seenTargets[target.Name] = true
		if target.Symbol == "" {
			target.Symbol = target.Name
		}
		target.Source = resolveOptional(root, target.Source)
		target.Header = resolveOptional(root, target.Header)
		target.WrapperSource = resolveOptional(root, target.WrapperSource)
		if target.Source != "" && !fsutil.Exists(target.Source) {
			return nil, usageError(fmt.Sprintf("target %s: source not found: %s", target.Name, target.Source))
		}
		if target.Header != "" && !fsutil.Exists(target.Header) {
			return nil, usageError(fmt.Sprintf("target %s: header not found: %s", target.Name, target.Header))
		}
		if target.WrapperSource != "" && !fsutil.Exists(target.WrapperSource) {
			return nil, usageError(fmt.Sprintf("target %s: wrapper_source not found: %s", target.Name, target.WrapperSource))
		}
		if (target.WrapperSource == "") != (target.WrapperSymbol == "") {
			return nil, usageError(fmt.Sprintf("target %s: wrapper_source and wrapper_symbol must be set together", target.Name))
		}
		if target.Destroy != "" && target.Factory == "" {
			return nil, usageError(fmt.Sprintf("target %s: destroy requires factory", target.Name))
		}
		if target.WrapperSource != "" && target.Input == "" {
			target.Input = "manual_wrapper"
		}
		switch target.Input {
		case "", "bytes_length", "manual_wrapper", "existing_harness":
		default:
			return nil, usageError(fmt.Sprintf("target %s: unknown input model %q", target.Name, target.Input))
		}
		if target.Input == "manual_wrapper" && target.WrapperSource == "" {
			return nil, usageError(fmt.Sprintf("target %s: manual_wrapper requires wrapper_source and wrapper_symbol", target.Name))
		}
		if target.MaxInputBytes < 0 || (target.MaxInputBytes > file.Harness.MaxInputBytes && file.Harness.MaxInputBytes > 0) {
			return nil, usageError(fmt.Sprintf("target %s: max_input_bytes must be 0 (inherit) or between 1 and %d", target.Name, file.Harness.MaxInputBytes))
		}
		resolvedSeeds := make([]string, 0, len(target.Seeds))
		for _, seed := range target.Seeds {
			seedPath := fsutil.Resolve(root, seed)
			if !fsutil.Exists(seedPath) {
				return nil, usageError(fmt.Sprintf("target %s: seed not found: %s", target.Name, seedPath))
			}
			resolvedSeeds = append(resolvedSeeds, seedPath)
		}
		target.Seeds = resolvedSeeds
		for _, role := range target.Args {
			if strings.TrimSpace(role) == "" {
				return nil, usageError(fmt.Sprintf("target %s: args entries must be role names", target.Name))
			}
		}
		targets = append(targets, target)
	}

	adapters := make([]Adapter, 0, len(file.Adapters))
	seenAdapters := map[string]bool{}
	for i := range file.Adapters {
		adapter := file.Adapters[i]
		if strings.TrimSpace(adapter.OriginalSymbol) == "" {
			return nil, usageError(fmt.Sprintf("adapters[%d].original_symbol is required", i))
		}
		if seenAdapters[adapter.OriginalSymbol] {
			return nil, usageError(fmt.Sprintf("duplicate adapter for symbol: %s", adapter.OriginalSymbol))
		}
		seenAdapters[adapter.OriginalSymbol] = true
		adapter.ReplacementSource = resolveOptional(root, adapter.ReplacementSource)
		adapter.Contract = resolveOptional(root, adapter.Contract)
		if adapter.ReplacementSource == "" || adapter.Contract == "" {
			return nil, usageError(fmt.Sprintf("adapter %s: replacement_source and contract are required", adapter.OriginalSymbol))
		}
		if !fsutil.Exists(adapter.ReplacementSource) {
			return nil, usageError(fmt.Sprintf("adapter %s: replacement_source not found: %s", adapter.OriginalSymbol, adapter.ReplacementSource))
		}
		if !fsutil.Exists(adapter.Contract) {
			return nil, usageError(fmt.Sprintf("adapter %s: contract not found: %s", adapter.OriginalSymbol, adapter.Contract))
		}
		adapters = append(adapters, adapter)
	}

	file.Targets = targets
	file.Adapters = adapters
	cfg := &Config{
		Path:        path,
		Root:        root,
		CompDB:      compDB,
		ArtifactDir: artifactDir,
		File:        file,
		Targets:     targets,
		Adapters:    adapters,
	}
	fingerprint, err := fsutil.HashJSON(cfg.normalized())
	if err != nil {
		return nil, err
	}
	cfg.Fingerprint = fingerprint
	return cfg, nil
}

// Target returns a configured target by name or symbol.
func (c *Config) Target(nameOrSymbol string) (Target, bool) {
	for _, target := range c.Targets {
		if target.Name == nameOrSymbol || target.Symbol == nameOrSymbol {
			return target, true
		}
	}
	return Target{}, false
}

// Adapter returns an adapter by original symbol.
func (c *Config) Adapter(symbol string) (Adapter, bool) {
	for _, adapter := range c.Adapters {
		if adapter.OriginalSymbol == symbol {
			return adapter, true
		}
	}
	return Adapter{}, false
}

// RequiredTargets returns targets declared as required.
func (c *Config) RequiredTargets() []Target {
	var out []Target
	for _, target := range c.Targets {
		if target.Required {
			out = append(out, target)
		}
	}
	return out
}

// EffectiveMaxInputBytes returns the target override or the global default.
func (c *Config) EffectiveMaxInputBytes(target Target) int {
	if target.MaxInputBytes > 0 {
		return target.MaxInputBytes
	}
	return c.File.Harness.MaxInputBytes
}

type normalizedConfig struct {
	SchemaVersion int       `json:"schema_version"`
	Project       Project   `json:"project"`
	CompDB        string    `json:"compdb"`
	ArtifactDir   string    `json:"artifact_dir"`
	Host          Host      `json:"host"`
	Analysis      Analysis  `json:"analysis"`
	Harness       Harness   `json:"harness"`
	CI            CI        `json:"ci"`
	Targets       []Target  `json:"targets"`
	Adapters      []Adapter `json:"adapters"`
}

func (c *Config) normalized() normalizedConfig {
	project := c.File.Project
	project.Source = "."
	project.CompDB = ""
	project.ArtifactDir = ""
	ci := c.File.CI
	ci.Baseline = relOrEmpty(c.Root, ci.Baseline)
	ci.CorpusDir = relOrEmpty(c.Root, ci.CorpusDir)
	ci.OutputDir = relOrEmpty(c.Root, ci.OutputDir)
	targets := make([]Target, len(c.Targets))
	for i, target := range c.Targets {
		target.Source = relOrEmpty(c.Root, target.Source)
		target.Header = relOrEmpty(c.Root, target.Header)
		target.WrapperSource = relOrEmpty(c.Root, target.WrapperSource)
		for j, seed := range target.Seeds {
			target.Seeds[j] = relOrEmpty(c.Root, seed)
		}
		targets[i] = target
	}
	adapters := make([]Adapter, len(c.Adapters))
	for i, adapter := range c.Adapters {
		adapter.ReplacementSource = relOrEmpty(c.Root, adapter.ReplacementSource)
		adapter.Contract = relOrEmpty(c.Root, adapter.Contract)
		adapters[i] = adapter
	}
	return normalizedConfig{
		SchemaVersion: c.File.SchemaVersion,
		Project:       project,
		CompDB:        relOrEmpty(c.Root, c.CompDB),
		ArtifactDir:   relOrEmpty(c.Root, c.ArtifactDir),
		Host:          c.File.Host,
		Analysis:      c.File.Analysis,
		Harness:       c.File.Harness,
		CI:            ci,
		Targets:       targets,
		Adapters:      adapters,
	}
}

func resolveToolPath(root, value string) string {
	if value == "" {
		return ""
	}
	if strings.ContainsAny(value, "/\\") {
		return filepath.Clean(fsutil.Resolve(root, value))
	}
	return value
}

func resolveOptional(root, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return filepath.Clean(fsutil.Resolve(root, value))
}

func relOrEmpty(root, value string) string {
	if value == "" {
		return ""
	}
	return fsutil.Rel(root, value)
}

func usageError(message string) *diag.Error {
	return &diag.Error{Code: diag.EConfigInvalid, Message: message, ExitCode: exitcode.Usage}
}
