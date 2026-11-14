// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package cli implements the fuzzfw command line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/version"
)

const usageText = `fuzzfw — deterministic source-level host-lifting for embedded C/C++

Usage:
  fuzzfw [global flags] <command> [command flags]

Commands:
  doctor    Check toolchain, compiler sanitizer support, and engine availability.
  scan      Import build metadata and analyze C/C++ functions.
  plan      Produce host-lift and harness plans with evidence.
  build     Generate a harness, compile original TUs, and run self-tests.
  fuzz      Run an external fuzzing engine against built targets.
  check     CI gate: analyze, build, replay corpus, fuzz briefly, and report.
  replay    Re-run one finding input in an isolated self-test binary.
  report    Re-render summary/JUnit/Markdown from an output directory.
  inspect   Show evidence and diagnostics for one planned target.

Global flags:
  --config PATH     Configuration file (default: discover fuzzfw.toml upward)
  --verbose         Verbose logs (repeat for debug)
  --quiet           Only errors
  --log-file PATH   Also write debug logs to a file
  --version         Print version
  -h, --help        Show help

Exit codes:
  0  completed, no failing new reproduced finding
  1  failing new reproduced target finding
  2  build/environment/self-test failure or required check incomplete
  3  invalid configuration or CLI usage
`

type globalOptions struct {
	configPath string
	verbose    int
	quiet      bool
	logFile    string
}

// Run executes the CLI and returns the process exit code.
func Run(args []string) (code int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Fprintf(os.Stderr, "internal error: %v\n", recovered)
			code = exitcode.Incomplete
		}
	}()
	global, remaining, err := extractGlobal(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitcode.Usage
	}
	if global.verbose > 0 {
		_ = os.Setenv("FUZZFW_VERBOSE", "1")
	}
	if global.quiet {
		_ = os.Setenv("FUZZFW_QUIET", "1")
	}
	if len(remaining) == 0 {
		fmt.Fprint(os.Stdout, usageText)
		return exitcode.Usage
	}
	if remaining[0] == "--version" || remaining[0] == "version" {
		fmt.Fprintln(os.Stdout, version.String())
		return exitcode.OK
	}
	if remaining[0] == "--help" || remaining[0] == "-h" || remaining[0] == "help" {
		fmt.Fprint(os.Stdout, usageText)
		return exitcode.OK
	}
	command, commandArgs := remaining[0], remaining[1:]
	ctx := context.Background()
	var runErr error
	switch command {
	case "doctor":
		code, runErr = runDoctor(ctx, global, commandArgs)
	case "scan":
		code, runErr = runScan(ctx, global, commandArgs)
	case "plan":
		code, runErr = runPlan(ctx, global, commandArgs)
	case "build":
		code, runErr = runBuild(ctx, global, commandArgs)
	case "fuzz":
		code, runErr = runFuzz(ctx, global, commandArgs)
	case "check":
		code, runErr = runCheck(ctx, global, commandArgs)
	case "replay":
		code, runErr = runReplay(ctx, global, commandArgs)
	case "report":
		code, runErr = runReport(ctx, global, commandArgs)
	case "inspect":
		code, runErr = runInspect(ctx, global, commandArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", command, usageText)
		return exitcode.Usage
	}
	if runErr != nil {
		printError(runErr, global.verbose > 0)
		errCode := exitCodeFor(runErr)
		if code == 0 || (errCode == exitcode.Usage && code == exitcode.Incomplete) {
			code = errCode
		}
	}
	return code
}

func extractGlobal(args []string) (globalOptions, []string, error) {
	var opts globalOptions
	var remaining []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config":
			if i+1 >= len(args) {
				return opts, nil, errors.New("--config requires a path")
			}
			i++
			opts.configPath = args[i]
		case strings.HasPrefix(arg, "--config="):
			opts.configPath = strings.TrimPrefix(arg, "--config=")
		case arg == "--verbose" || arg == "-v":
			opts.verbose++
		case arg == "--quiet" || arg == "-q":
			opts.quiet = true
		case arg == "--log-file":
			if i+1 >= len(args) {
				return opts, nil, errors.New("--log-file requires a path")
			}
			i++
			opts.logFile = args[i]
		case strings.HasPrefix(arg, "--log-file="):
			opts.logFile = strings.TrimPrefix(arg, "--log-file=")
		case arg == "--version":
			remaining = append(remaining, arg)
		default:
			remaining = append(remaining, arg)
		}
	}
	return opts, remaining, nil
}

func loadConfigOrError(opts globalOptions, start string, require bool) (*config.Config, error) {
	cfg, err := config.Load(opts.configPath, start, require)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func newFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	return set
}

func parseDurations(value string, fallback int) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return time.Duration(fallback) * time.Second, nil
	}
	if seconds, err := time.ParseDuration(value); err == nil {
		if seconds < time.Second {
			return 0, fmt.Errorf("time budget must be at least one second")
		}
		return seconds, nil
	}
	var seconds int
	if _, err := fmt.Sscanf(value, "%d", &seconds); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid duration %q (use 30s, 10m, or 1h)", value)
}

func printError(err error, verbose bool) {
	var expected *diag.Error
	if errors.As(err, &expected) {
		fmt.Fprintf(os.Stderr, "error [%s]: %s\n", expected.Code, expected.Message)
		if expected.Remediation != "" {
			fmt.Fprintf(os.Stderr, "remediation: %s\n", expected.Remediation)
		}
		if verbose {
			for _, evidence := range expected.Evidence {
				fmt.Fprintf(os.Stderr, "evidence: %s\n", evidence)
			}
			if expected.Err != nil {
				fmt.Fprintf(os.Stderr, "cause: %v\n", expected.Err)
			}
		}
		return
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
}

func exitCodeFor(err error) int {
	var expected *diag.Error
	if errors.As(err, &expected) {
		if expected.ExitCode != 0 {
			return expected.ExitCode
		}
	}
	return exitcode.Incomplete
}

// writeJSONTo writes JSON to stdout when path is empty.
func writeJSONTo(path string, value any) error {
	data, err := fsutil.PrettyJSON(value)
	if err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0o644)
}

// stringList implements flag.Value for repeatable string flags.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}
