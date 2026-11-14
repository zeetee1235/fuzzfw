// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package manifest builds the reproducible record of source and build inputs.
package manifest

import (
	"context"
	"path/filepath"
	"sort"

	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

// SchemaVersion is the build manifest schema.
const SchemaVersion = 1

// Project identifies the source tree.
type Project struct {
	Name           string `json:"name"`
	Root           string `json:"root"`
	SourceRevision string `json:"source_revision"`
	ConfigPath     string `json:"config_path,omitempty"`
	ConfigSHA256   string `json:"config_sha256"`
	Fingerprint    string `json:"config_fingerprint"`
}

// CompDB records the compilation database.
type CompDB struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Entries int    `json:"entries"`
}

// Manifest is the build_manifest.json contract.
type Manifest struct {
	SchemaVersion int                 `json:"schema_version"`
	CreatedAt     string              `json:"created_at"`
	Project       Project             `json:"project"`
	CompDB        CompDB              `json:"compdb"`
	Toolchain     *toolchain.Report   `json:"toolchain"`
	Commands      []compdb.Command    `json:"commands"`
	InputHashes   map[string]string   `json:"input_hashes"`
	Git           *fsutil.GitRevision `json:"git,omitempty"`
	Diagnostics   []diag.Diagnostic   `json:"diagnostics,omitempty"`
}

// Collect gathers the manifest for cfg and db.
func Collect(ctx context.Context, cfg *config.Config, db *compdb.Database, tools *toolchain.Report) (*Manifest, error) {
	configHash := ""
	if cfg.Path != "" {
		hash, err := fsutil.HashFile(cfg.Path)
		if err != nil {
			return nil, err
		}
		configHash = hash
	}
	revision := cfg.File.Project.SourceRevision
	var git *fsutil.GitRevision
	if revision == "auto" {
		collected := fsutil.CollectGit(ctx, cfg.Root)
		git = &collected
		revision = collected.RevisionString()
	}

	inputs := map[string]bool{}
	for _, command := range db.Commands {
		inputs[command.File] = true
	}
	if cfg.Path != "" {
		inputs[cfg.Path] = true
	}
	for _, adapter := range cfg.Adapters {
		inputs[adapter.ReplacementSource] = true
		inputs[adapter.Contract] = true
	}
	for _, target := range cfg.Targets {
		for _, path := range []string{target.Source, target.Header, target.WrapperSource} {
			if path != "" {
				inputs[path] = true
			}
		}
	}
	hashes := map[string]string{}
	paths := make([]string, 0, len(inputs))
	for path := range inputs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		hash, err := fsutil.HashFile(path)
		if err != nil {
			return nil, err
		}
		hashes[fsutil.Rel(cfg.Root, path)] = hash
	}

	diagnostics := append([]diag.Diagnostic(nil), db.Diagnostics...)
	return &Manifest{
		SchemaVersion: SchemaVersion,
		CreatedAt:     fsutil.NowUTC(),
		Project: Project{
			Name:           cfg.File.Project.Name,
			Root:           cfg.Root,
			SourceRevision: revision,
			ConfigPath:     cfg.Path,
			ConfigSHA256:   configHash,
			Fingerprint:    cfg.Fingerprint,
		},
		CompDB: CompDB{
			Path:    fsutil.Rel(cfg.Root, db.Path),
			SHA256:  db.SHA256,
			Entries: len(db.Commands),
		},
		Toolchain:   tools,
		Commands:    db.Commands,
		InputHashes: hashes,
		Git:         git,
		Diagnostics: diagnostics,
	}, nil
}

// SourceHashes returns only hashes for translation units.
func (m *Manifest) SourceHashes() map[string]string {
	out := map[string]string{}
	for _, command := range m.Commands {
		rel := fsutil.Rel(m.Project.Root, command.File)
		if hash, ok := m.InputHashes[rel]; ok {
			out[rel] = hash
		}
	}
	return out
}

// CommandFor finds the exact variant for a file.
func (m *Manifest) CommandFor(file, variant string) (compdb.Command, bool) {
	for _, command := range m.Commands {
		if command.File != file {
			continue
		}
		if variant == "" || command.VariantID == variant {
			return command, true
		}
	}
	return compdb.Command{}, false
}

// Ensure config path helper is used by callers that need a relative display.
func ConfigDisplay(root string, path string) string {
	if path == "" {
		return ""
	}
	return filepath.ToSlash(fsutil.Rel(root, path))
}
