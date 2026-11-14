// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package replay embeds the native single-input replay driver.
package replay

import _ "embed"

// DriverSource is compiled into every self-test binary.
//
//go:embed driver/replay_driver.c
var DriverSource []byte
