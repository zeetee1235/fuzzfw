// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package main

import (
	"os"

	"github.com/fuzzfw/fuzzfw/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
