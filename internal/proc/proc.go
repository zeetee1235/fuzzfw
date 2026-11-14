// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package proc is the only package that starts child processes.
package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/logx"
)

// TimeoutExitCode is used when a command is terminated by the runner.
const TimeoutExitCode = 124

// Result is the complete outcome of a child process.
type Result struct {
	Argv       []string      `json:"argv"`
	Dir        string        `json:"directory,omitempty"`
	ExitCode   int           `json:"exit_code"`
	Signal     int           `json:"signal,omitempty"`
	SignalName string        `json:"signal_name,omitempty"`
	Stdout     string        `json:"stdout,omitempty"`
	Stderr     string        `json:"stderr,omitempty"`
	Duration   time.Duration `json:"duration_ns"`
	TimedOut   bool          `json:"timed_out"`
}

// OK reports a clean zero exit.
func (r *Result) OK() bool { return r.ExitCode == 0 && !r.TimedOut && r.Signal == 0 }

// Display returns a shell-like representation for logs, never for execution.
func (r *Result) Display() string { return Display(r.Argv) }

// Runner executes argv arrays with deterministic locale and a timeout.
type Runner struct {
	// Timeout is applied when the caller's context has no earlier deadline.
	Timeout time.Duration
	// Env overrides process environment entries.
	Env map[string]string
}

// Run executes argv in dir. Non-zero exits are returned as Result, not as Go
// errors. Go errors are reserved for OS-level failures.
func (r Runner) Run(ctx context.Context, dir string, argv ...string) (*Result, error) {
	if len(argv) == 0 {
		return nil, errors.New("proc: empty argv")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := r.Timeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = buildEnv(r.Env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Kill the whole group so compiler drivers and fuzz workers do not
		// outlive their supervisor.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil &&
			!errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	logx.Debugf("exec %s (cwd=%s)", Display(argv), dir)
	started := time.Now()
	err := cmd.Run()
	duration := time.Since(started)

	result := &Result{
		Argv:     append([]string(nil), argv...),
		Dir:      dir,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			result.Signal = int(status.Signal())
			result.SignalName = status.Signal().String()
			result.ExitCode = 128 + result.Signal
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
		result.ExitCode = TimeoutExitCode
	}
	logx.Debugf("exit=%d signal=%d timeout=%t duration=%s", result.ExitCode, result.Signal, result.TimedOut, result.Duration)
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, err
	}
	return result, nil
}

// RunSimple is a convenience wrapper with an explicit timeout.
func RunSimple(ctx context.Context, dir string, timeout time.Duration, argv ...string) (*Result, error) {
	return (Runner{Timeout: timeout}).Run(ctx, dir, argv...)
}

// LookPath resolves an executable without invoking a shell.
func LookPath(name string) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		info, err := os.Stat(name)
		if err != nil {
			return "", err
		}
		if info.IsDir() || info.Mode()&0o111 == 0 {
			return "", fmt.Errorf("%s is not executable", name)
		}
		abs, err := filepath.Abs(name)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	return exec.LookPath(name)
}

// Version returns the first line of `tool --version` or an empty string.
func Version(ctx context.Context, tool string, args ...string) string {
	result, err := RunSimple(ctx, "", 10*time.Second, append([]string{tool}, args...)...)
	if err != nil || result == nil {
		return ""
	}
	text := strings.TrimSpace(result.Stdout)
	if text == "" {
		text = strings.TrimSpace(result.Stderr)
	}
	if line, _, ok := strings.Cut(text, "\n"); ok {
		return strings.TrimSpace(line)
	}
	return text
}

// Display formats argv for humans with minimal quoting.
func Display(argv []string) string {
	parts := make([]string, len(argv))
	for i, arg := range argv {
		parts[i] = quoteArg(arg)
	}
	return strings.Join(parts, " ")
}

func quoteArg(arg string) string {
	if arg == "" {
		return "''"
	}
	if strings.IndexFunc(arg, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\'' || r == '"' || r == '$' || r == '\\'
	}) < 0 {
		return arg
	}
	return strconv.Quote(arg)
}

func buildEnv(overrides map[string]string) []string {
	env := make(map[string]string, len(os.Environ())+len(overrides)+3)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		env[key] = value
	}
	// Deterministic diagnostics across developer and CI machines.
	env["LC_ALL"] = "C"
	env["LANG"] = "C"
	env["TZ"] = "UTC"
	for key, value := range overrides {
		env[key] = value
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+env[key])
	}
	return result
}
