// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package fsutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/proc"
)

// GitRevision is recorded in build manifests and build-info artifacts.
type GitRevision struct {
	Available   bool   `json:"available"`
	Head        string `json:"head,omitempty"`
	Branch      string `json:"branch,omitempty"`
	Dirty       bool   `json:"dirty"`
	DirtyDigest string `json:"dirty_digest,omitempty"`
	Describe    string `json:"describe,omitempty"`
	Error       string `json:"error,omitempty"`
}

// RevisionString returns a stable identifier including dirty state.
func (g GitRevision) RevisionString() string {
	if !g.Available {
		return "unknown"
	}
	head := g.Head
	if head == "" {
		head = "unknown"
	}
	if !g.Dirty {
		return head
	}
	digest := g.DirtyDigest
	if digest == "" {
		digest = "unknown"
	}
	return head + "+dirty." + digest
}

// CollectGit reads revision information without requiring a repository.
func CollectGit(ctx context.Context, root string) GitRevision {
	runner := proc.Runner{Timeout: 30 * time.Second}
	probe, err := runner.Run(ctx, root, "git", "-C", root, "rev-parse", "--is-inside-work-tree")
	if err != nil || !probe.OK() || strings.TrimSpace(probe.Stdout) != "true" {
		return GitRevision{Available: false, Error: lastLine(errorText(probe, err))}
	}
	head, _ := runner.Run(ctx, root, "git", "-C", root, "rev-parse", "HEAD")
	branch, _ := runner.Run(ctx, root, "git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD")
	describe, _ := runner.Run(ctx, root, "git", "-C", root, "describe", "--always", "--dirty", "--tags")

	revision := GitRevision{
		Available: true,
		Head:      strings.TrimSpace(head.Stdout),
		Branch:    strings.TrimSpace(branch.Stdout),
		Describe:  strings.TrimSpace(describe.Stdout),
	}
	names := dirtyNames(ctx, root, runner)
	if len(names) > 0 {
		revision.Dirty = true
		revision.DirtyDigest = dirtyDigest(ctx, root, runner)
	}
	return revision
}

func dirtyNames(ctx context.Context, root string, runner proc.Runner) []string {
	namesResult, err := runner.Run(ctx, root, "git", "-C", root, "ls-files", "-m", "-o", "-d", "--exclude-standard", "-z")
	if err != nil || namesResult == nil {
		return nil
	}
	repoResult, _ := runner.Run(ctx, root, "git", "-C", root, "rev-parse", "--show-toplevel")
	repoRoot := strings.TrimSpace(repoResult.Stdout)
	if repoRoot == "" {
		repoRoot = root
	}
	var names []string
	for _, name := range strings.Split(namesResult.Stdout, "\x00") {
		if name == "" {
			continue
		}
		path := filepath.Join(repoRoot, name)
		if Within(root, path) {
			names = append(names, name)
		}
	}
	return names
}

func dirtyDigest(ctx context.Context, root string, runner proc.Runner) string {
	names := dirtyNames(ctx, root, runner)
	if len(names) == 0 {
		return ""
	}
	repoResult, _ := runner.Run(ctx, root, "git", "-C", root, "rev-parse", "--show-toplevel")
	repoRoot := strings.TrimSpace(repoResult.Stdout)
	if repoRoot == "" {
		repoRoot = root
	}
	sortStrings(names)
	hash := hashString(strings.Join(names, "\x00"))
	for _, name := range names {
		path := filepath.Join(repoRoot, name)
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		fileHash, err := HashFile(path)
		if err != nil {
			continue
		}
		hash = hashString(hash + "\x00" + name + "\x00" + fileHash)
	}
	if len(hash) > 24 {
		hash = hash[:24]
	}
	return hash
}

func errorText(result *proc.Result, err error) string {
	if err != nil {
		return err.Error()
	}
	if result != nil {
		return result.Stderr
	}
	return ""
}

func lastLine(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func hashString(text string) string {
	return HashString(text)
}

// FormatUTC returns a stable RFC3339 timestamp.
func FormatUTC(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// NowUTC returns a stable timestamp with second precision.
func NowUTC() string { return FormatUTC(time.Now().UTC()) }

// ParseTime parses RFC3339 or returns the zero time.
func ParseTime(value string) time.Time {
	t, _ := time.Parse(time.RFC3339, value)
	return t
}

// EnsureRelativePath validates that a user-provided path does not escape root.
func EnsureRelativePath(root, path string) error {
	resolved := Resolve(root, path)
	if !Within(root, resolved) {
		return fmt.Errorf("path escapes project root: %s", path)
	}
	return nil
}
