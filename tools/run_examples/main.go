// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Command run_examples configures, builds, and checks the repository examples.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "run_examples: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	binDir, err := os.MkdirTemp("", "fuzzfw-examples-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(binDir)
	binary := filepath.Join(binDir, "fuzzfw")
	if err := command(root, "go", "build", "-o", binary, "./cmd/fuzzfw"); err != nil {
		return err
	}
	project := filepath.Join(root, "examples", "simple-parser")
	if err := command(project, "cmake", "-S", ".", "-B", "build", "-G", "Ninja", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"); err != nil {
		return err
	}
	if err := command(project, "cmake", "--build", "build"); err != nil {
		return err
	}
	output := filepath.Join(binDir, "out")
	err = command(project, binary, "check", "--engine", "replay", "--time", "1s", "--output", output, "--quiet")
	if err == nil {
		fmt.Println("example check passed")
		return nil
	}
	var commandErr *commandError
	if errors.As(err, &commandErr) && commandErr.Code == 1 {
		fmt.Println("example check found the intentional fixture bug (expected)")
		return nil
	}
	return err
}

type commandError struct {
	Argv   []string
	Code   int
	Output string
}

func (e *commandError) Error() string {
	return fmt.Sprintf("%v: exit %d\n%s", e.Argv, e.Code, e.Output)
}

func command(dir string, argv ...string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return &commandError{Argv: argv, Code: exitErr.ExitCode(), Output: output.String()}
		}
		return fmt.Errorf("%v: %v", argv, err)
	}
	return nil
}
