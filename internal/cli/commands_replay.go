// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/triage"
)

func runReplay(ctx context.Context, global globalOptions, args []string) (int, error) {
	flags := newFlagSet("replay")
	targetFlag := flags.String("target", "", "target name")
	attemptsFlag := flags.Int("attempts", 0, "reproduction attempts (default harness.reproduction_attempts)")
	jsonOutput := flags.Bool("json", false, "print machine-readable result")
	output := flags.String("output", "", "write replay JSON to this path")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	if flags.NArg() != 1 {
		return exitcode.Usage, fmt.Errorf("replay requires one input file or finding directory")
	}
	inputPath := flags.Arg(0)
	targetName := *targetFlag
	dir := ""
	if info, err := os.Stat(inputPath); err == nil && info.IsDir() {
		dir = inputPath
		inputPath = filepath.Join(dir, "input.bin")
		if targetName == "" {
			var finding triage.Finding
			if err := fsutil.ReadJSON(filepath.Join(dir, "finding.json"), &finding); err == nil {
				targetName = finding.Target
			}
		}
	}
	if targetName == "" {
		return exitcode.Usage, fmt.Errorf("replay requires --target when the input is not a finding directory")
	}
	cfg, err := loadConfigOrError(global, ".", false)
	if err != nil {
		return exitcode.Usage, err
	}
	ws := artifacts.NewWorkspace(cfg)
	state, err := loadBuildState(ws)
	if err != nil {
		return exitcode.Incomplete, err
	}
	built, ok := state.target(targetName)
	if !ok || built.Result.SelftestBinary == "" {
		return exitcode.Incomplete, diag.NewError(diag.EArtifactInvalid,
			fmt.Sprintf("no self-test binary for target %s; rebuild first", targetName))
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return exitcode.Usage, fmt.Errorf("cannot read input: %w", err)
	}
	attempts := *attemptsFlag
	if attempts <= 0 {
		attempts = cfg.File.Harness.ReproductionAttempts
	}
	started := time.Now()
	var outcomes []triage.ReplayOutcome
	crashes := 0
	for attempt := 0; attempt < attempts; attempt++ {
		outcome := triage.RunOnce(ctx, cfg, &built.Result, data, targetName, "", 30*time.Second)
		outcomes = append(outcomes, outcome)
		if outcome.Crashed {
			crashes++
		}
	}
	result := map[string]any{
		"schema_version":   1,
		"target":           targetName,
		"input_sha256":     fsutil.HashBytes(data),
		"attempts":         attempts,
		"crashes":          crashes,
		"reproduced":       crashes > 0,
		"duration_seconds": time.Since(started).Seconds(),
		"outcomes":         outcomes,
	}
	if *output != "" {
		if err := fsutil.WriteJSON(*output, result, true); err != nil {
			return exitcode.Incomplete, err
		}
	}
	if *jsonOutput {
		if err := writeJSONTo("", result); err != nil {
			return exitcode.Incomplete, err
		}
	} else {
		fmt.Printf("target: %s\n", targetName)
		fmt.Printf("input sha256: %s\n", fsutil.HashBytes(data))
		fmt.Printf("attempts: %d, crashes: %d\n", attempts, crashes)
		for index, outcome := range outcomes {
			fmt.Printf("  attempt %d: exit=%d signal=%d kind=%s origin=%s\n",
				index+1, outcome.ExitCode, outcome.Signal, outcome.Kind, outcome.Origin)
		}
	}
	if crashes > 0 {
		return exitcode.Findings, nil
	}
	return exitcode.OK, nil
}
