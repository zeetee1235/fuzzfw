// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package version exposes build-time version information.
package version

import "fmt"

// Version is the semantic version of fuzzfw. Release builds override it with
// -ldflags "-X github.com/fuzzfw/fuzzfw/internal/version.Version=...".
var (
	Version   = "0.0.2"
	Commit    = "unknown"
	BuildDate = "unknown"
	Builder   = "unknown"
)

// String returns a single-line version suitable for logs and --version.
func String() string {
	return fmt.Sprintf("fuzzfw %s (commit %s, built %s by %s)", Version, Commit, BuildDate, Builder)
}
