// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package exitcode defines the stable CI exit code contract.
package exitcode

const (
	OK         = 0
	Findings   = 1
	Incomplete = 2
	Usage      = 3
)
