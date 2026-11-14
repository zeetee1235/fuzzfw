// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package hostbuild

import (
	"strings"
	"testing"

	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/config"
)

func TestHostFlagsDropTargetFlagsKeepPreprocessor(t *testing.T) {
	cfg := &config.Config{Root: "/project"}
	cfg.File = config.Defaults()
	cfg.File.Host.ExtraCFlags = []string{"-DFUZZFW_HOST=1"}
	cmd := compdb.Command{
		Directory: "/project/build",
		File:      "/project/src/a.c",
		Arguments: []string{
			"arm-none-eabi-gcc", "-mthumb", "-mcpu=cortex-m4", "--target=arm-none-eabi",
			"-Iinclude", "-DNAME=1", "-Werror", "-O2", "-c", "/project/src/a.c", "-o", "a.o",
		},
		Language: "c",
	}
	flags, delta := hostFlags(cfg, cmd)
	joined := strings.Join(flags, " ")
	for _, want := range []string{"-Iinclude", "-DNAME=1", "-I /project", "-DFUZZFW_HOST=1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %s", want, joined)
		}
	}
	for _, forbidden := range []string{"-mthumb", "-mcpu", "--target", "-Werror"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("target flag survived: %s", joined)
		}
	}
	if len(delta.RemovedFlags) == 0 {
		t.Fatal("expected build delta")
	}
}
