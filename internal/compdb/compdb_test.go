// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package compdb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitCommand(t *testing.T) {
	got, err := splitCommand(`cc -DNAME="a b" -I inc 'src/a.c'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cc", "-DNAME=a b", "-I", "inc", "src/a.c"}
	if len(got) != len(want) {
		t.Fatalf("got %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := splitCommand(`cc "unterminated`); err == nil {
		t.Fatal("expected quote error")
	}
}

func TestLoadNormalizesAndDeduplicates(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "src", "a.c")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("int a(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry := Entry{
		Directory: root,
		File:      source,
		Arguments: []string{"clang", "-I", "include", "-DNAME=1", "-o", "a.o", "-c", source},
	}
	data, err := json.Marshal([]Entry{entry, entry})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "compile_commands.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Load(context.Background(), path, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Commands) != 1 {
		t.Fatalf("commands = %d", len(db.Commands))
	}
	command := db.Commands[0]
	if command.Language != "c" {
		t.Fatalf("language = %s", command.Language)
	}
	if command.VariantID == "" {
		t.Fatal("empty variant")
	}
	foundSource := false
	for _, arg := range command.Normalized {
		if arg == "<source>" {
			foundSource = true
		}
		if arg == "-o" || arg == "a.o" || arg == "-c" {
			t.Fatalf("output flag not removed: %q", arg)
		}
	}
	if !foundSource {
		t.Fatalf("normalized args = %#v", command.Normalized)
	}
}
