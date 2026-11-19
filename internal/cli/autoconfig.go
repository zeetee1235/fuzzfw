// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/toolchain"
)

// isAutoConfig reports whether the run has no project configuration file and
// therefore relies on discovery. An explicit config file always opts out.
func isAutoConfig(cfg *config.Config) bool {
	return cfg.Path == "" && len(cfg.Targets) == 0
}

// selectAutoEngine prefers a real mutation engine, then falls back to replay.
// Configured projects keep their explicit ci.engine value.
func selectAutoEngine(tools *toolchain.Report) string {
	for _, name := range []string{"libfuzzer", "honggfuzz"} {
		if ok, _ := tools.EngineAvailable(name); ok {
			return name
		}
	}
	return "replay"
}

// applyAutoTargets makes discovered ready candidates required and attaches
// conventional seed directories. It is a no-op when the user selected targets
// or declared them in fuzzfw.toml.
func applyAutoTargets(cfg *config.Config, plan *planner.Plan, selected []string) []diag.Diagnostic {
	seeds := autoSeedDirs(cfg.Root)
	var chosen []string
	for i := range plan.Targets {
		target := &plan.Targets[i]
		if target.Classification != planner.ReadyCandidate {
			continue
		}
		if len(target.Seeds) == 0 {
			target.Seeds = append([]string(nil), seeds...)
		}
		if len(selected) > 0 {
			continue
		}
		target.Required = true
		chosen = append(chosen, target.Name)
	}
	if len(selected) > 0 || len(chosen) == 0 {
		return nil
	}
	return []diag.Diagnostic{{
		Code:     diag.WAutoconfig,
		Severity: diag.SeverityInfo,
		Message: fmt.Sprintf("no fuzzfw.toml: auto-selected %d target(s): %s",
			len(chosen), strings.Join(chosen, ", ")),
	}}
}

func autoSeedDirs(root string) []string {
	for _, rel := range []string{"seeds", "tests/fuzzfw/seeds", "corpus"} {
		entries, err := os.ReadDir(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				return []string{rel}
			}
		}
	}
	return nil
}

// autoPrepareBuild configures and builds a CMake project when no compilation
// database exists. This runs only in zero-config mode so a fresh checkout can
// be fuzzed without a manual setup step.
func autoPrepareBuild(ctx context.Context, cfg *config.Config) ([]diag.Diagnostic, error) {
	if fsutil.Exists(cfg.CompDB) {
		return nil, nil
	}
	if !fsutil.Exists(filepath.Join(cfg.Root, "CMakeLists.txt")) {
		return nil, nil
	}
	cmake, err := exec.LookPath("cmake")
	if err != nil {
		return nil, diag.NewError(diag.ECompDBMissing,
			"compile_commands.json is missing and cmake is not installed")
	}
	buildDir := filepath.Dir(cfg.CompDB)
	args := []string{"-S", cfg.Root, "-B", buildDir, "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}
	if _, err := exec.LookPath("ninja"); err == nil {
		args = append(args, "-G", "Ninja")
	}
	if output, err := runCommand(ctx, cfg.Root, cmake, args...); err != nil {
		return nil, autoBuildError("configure", buildDir, output, err)
	}
	if output, err := runCommand(ctx, cfg.Root, cmake, "--build", buildDir); err != nil {
		return nil, autoBuildError("build", buildDir, output, err)
	}
	if !fsutil.Exists(cfg.CompDB) {
		return nil, diag.NewError(diag.ECompDBMissing,
			fmt.Sprintf("cmake finished but did not produce %s", cfg.CompDB))
	}
	return []diag.Diagnostic{{
		Code:     diag.WAutoconfig,
		Severity: diag.SeverityInfo,
		Message:  "no compile_commands.json: auto-configured and built " + buildDir,
	}}, nil
}

func runCommand(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func autoBuildError(phase, buildDir, output string, err error) error {
	tail := strings.TrimSpace(output)
	if len(tail) > 4000 {
		tail = tail[len(tail)-4000:]
	}
	message := fmt.Sprintf("auto CMake %s failed in %s: %v", phase, buildDir, err)
	if tail != "" {
		message += "\n" + tail
	}
	return diag.NewError(diag.ECompDBMissing, message)
}
