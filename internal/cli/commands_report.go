// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/report"
)

func runReport(_ context.Context, _ globalOptions, args []string) (int, error) {
	flags := newFlagSet("report")
	input := flags.String("input", "fuzzfw-out", "fuzzfw output directory or summary.json")
	format := flags.String("format", "markdown", "markdown, json, or junit")
	output := flags.String("output", "", "write to this file instead of stdout")
	if err := flags.Parse(args); err != nil {
		return exitcode.Usage, err
	}
	path := *input
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, "summary.json")
	}
	summary, err := report.Load(path)
	if err != nil {
		return exitcode.Incomplete, fmt.Errorf("cannot load summary: %w", err)
	}
	var data []byte
	switch *format {
	case "markdown", "md":
		data = []byte(report.RenderMarkdown(summary))
	case "json":
		data, err = fsutil.PrettyJSON(summary)
	case "junit", "xml":
		data, err = report.RenderJUnit(summary)
	default:
		return exitcode.Usage, fmt.Errorf("unknown report format %q", *format)
	}
	if err != nil {
		return exitcode.Incomplete, err
	}
	if *output == "" {
		_, err = os.Stdout.Write(data)
		if err == nil {
			return exitcode.OK, nil
		}
		return exitcode.Incomplete, err
	}
	return exitcode.OK, fsutil.WriteFileAtomic(*output, data, 0o644)
}
