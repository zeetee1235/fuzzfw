// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package events embeds the adapter-visible input stream runtime.
package events

import _ "embed"

// HeaderSource is written into the target build include directory.
//
//go:embed fuzzfw_events.h
var HeaderSource []byte

// Source compiles into every self-test and fuzz binary.
//
//go:embed driver/fuzzfw_events.c
var Source []byte
