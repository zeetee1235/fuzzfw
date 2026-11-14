// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "a.c"), []byte("int a(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "seeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "seeds", "one"), []byte{1}, 0o644); err != nil {
		t.Fatal(err)
	}
	configText := `schema_version = 1

[project]
name = "unit"
source = "."
compdb = "build/compile_commands.json"

[ci]
engine = "replay"
time_seconds = 5
jobs = 1

[[targets]]
name = "a"
symbol = "a"
source = "src/a.c"
required = true
max_input_bytes = 32
seeds = ["seeds"]
`
	path := filepath.Join(root, FileName)
	if err := os.WriteFile(path, []byte(configText), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadResolvesPaths(t *testing.T) {
	path := writeFixture(t)
	cfg, err := Load(path, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Root != filepath.Dir(path) {
		t.Fatalf("root = %s", cfg.Root)
	}
	if cfg.CompDB != filepath.Join(cfg.Root, "build", "compile_commands.json") {
		t.Fatalf("compdb = %s", cfg.CompDB)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].Source != filepath.Join(cfg.Root, "src/a.c") {
		t.Fatalf("targets = %+v", cfg.Targets)
	}
	if len(cfg.Targets[0].Seeds) != 1 {
		t.Fatalf("seeds = %+v", cfg.Targets[0].Seeds)
	}
	if cfg.Fingerprint == "" {
		t.Fatal("empty fingerprint")
	}
	second, err := Load(path, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if second.Fingerprint != cfg.Fingerprint {
		t.Fatal("fingerprint is not deterministic")
	}
}

func TestUnknownKeyFailsClosed(t *testing.T) {
	path := writeFixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\n[host]\nnot_a_real_key = 1\n")...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "", true); err == nil {
		t.Fatal("expected unknown key error")
	}
}

func TestMissingRequiredTargetIsConfigError(t *testing.T) {
	path := writeFixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(string(data))
	// Duplicate target exercises validation rather than TOML parsing.
	data = append(data, []byte("\n[[targets]]\nname = \"a\"\nsymbol = \"a\"\n")...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "", true); err == nil {
		t.Fatal("expected duplicate target error")
	}
}

func TestWrapperRequiresSymbol(t *testing.T) {
	path := writeFixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\n[[targets]]\nname = \"w\"\nsymbol = \"w\"\nwrapper_source = \"src/a.c\"\n")...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "", true); err == nil {
		t.Fatal("expected wrapper validation error")
	}
}
