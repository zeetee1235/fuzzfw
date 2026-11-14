// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Command check_headers verifies SPDX headers on source files.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var extensions = map[string]bool{
	".go": true, ".c": true, ".h": true, ".cc": true, ".cpp": true, ".hpp": true, ".hxx": true,
}

var skipDirs = map[string]bool{
	".git": true, ".fuzzfw": true, "build": true, "dist": true, "__pycache__": true,
}

func main() {
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var missing []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if skipDirs[entry.Name()] || strings.HasPrefix(entry.Name(), "fuzzfw-out") {
				return filepath.SkipDir
			}
			return nil
		}
		if !extensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		found := false
		for line := 0; line < 5 && scanner.Scan(); line++ {
			if strings.Contains(scanner.Text(), "SPDX-License-Identifier:") {
				found = true
				break
			}
		}
		if !found {
			rel, _ := filepath.Rel(root, path)
			missing = append(missing, rel)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(missing) > 0 {
		fmt.Fprintln(os.Stderr, "missing SPDX header:")
		for _, path := range missing {
			fmt.Fprintln(os.Stderr, "  "+path)
		}
		os.Exit(1)
	}
	fmt.Println("SPDX headers: ok")
}
