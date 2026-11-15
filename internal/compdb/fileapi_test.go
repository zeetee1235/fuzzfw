// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package compdb

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLoadCMakeFileAPI(t *testing.T) {
	if _, err := exec.LookPath("cmake"); err != nil {
		t.Skip("cmake is not available")
	}
	root := t.TempDir()
	build := filepath.Join(root, "build")
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "CMakeLists.txt"), []byte(
		"cmake_minimum_required(VERSION 3.20)\nproject(fileapi C)\nadd_library(api STATIC src/api.c)\ntarget_include_directories(api PUBLIC include)\ntarget_compile_definitions(api PRIVATE API=1)\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "include"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "include", "api.h"), []byte("int api(void);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "api.c"), []byte("#include \"api.h\"\nint api(void){return API;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	queryDir := filepath.Join(build, ".cmake", "api", "v1", "query", "client-fuzzfw")
	if err := os.MkdirAll(queryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	query := []byte(`{"requests":[{"kind":"codemodel","version":2},{"kind":"cache","version":2}]}`)
	if err := os.WriteFile(filepath.Join(queryDir, "query.json"), query, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cmake", "-S", root, "-B", build, "-G", "Ninja")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cmake configure failed: %v\n%s", err, output)
	}
	db, err := LoadCMakeFileAPI(context.Background(), build, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Commands) != 1 {
		t.Fatalf("commands = %d", len(db.Commands))
	}
	command := db.Commands[0]
	if filepath.Base(command.File) != "api.c" {
		t.Fatalf("file = %s", command.File)
	}
	foundInclude := false
	foundDefine := false
	for _, arg := range command.Arguments {
		if arg == "-I"+filepath.Join(root, "include") {
			foundInclude = true
		}
		if arg == "-DAPI=1" {
			foundDefine = true
		}
	}
	if !foundInclude || !foundDefine {
		t.Fatalf("arguments = %v", command.Arguments)
	}
}
