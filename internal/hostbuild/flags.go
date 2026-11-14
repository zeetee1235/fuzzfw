// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package hostbuild

import (
	"path/filepath"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/config"
)

var hostDropWithValue = map[string]bool{
	"-o": true, "-MF": true, "-MT": true, "-MQ": true, "-MJ": true,
	"--output": true, "-x": true, "--sysroot": true, "-isysroot": true,
	"-target": true, "--target": true, "-specs": true, "-mllvm": true,
	"-Xclang": true, "-include-pch": true, "-Xlinker": true,
}

var hostDropExact = map[string]bool{
	"-c": true, "-S": true, "-E": true, "-fsyntax-only": true, "-Werror": true,
	"-MD": true, "-MMD": true, "-MP": true, "-MG": true, "-Winvalid-pch": true,
	"-nostdlib": true, "-nostartfiles": true, "-nodefaultlibs": true,
	"-nostdinc": true, "-static": true, "-shared": true, "-pie": true, "-no-pie": true,
	"-rdynamic": true, "--coverage": true, "-save-temps": true,
}

var hostDropPrefixes = []string{
	"-o", "-MF", "-MT", "-MQ", "-MJ", "-L", "-l", "-Wl,", "-fuse-ld=",
	"-m", "-O", "-flto", "-fprofile", "-fcoverage", "-fshort-enums", "-fshort-wchar",
	"-fpack-struct", "-Werror", "--target=", "-Wp,-Werror",
}

// hostFlags returns audited host compiler flags for one translation unit and a
// delta record. It never removes -D/-U/-I/-include preprocessing inputs.
func hostFlags(cfg *config.Config, command compdb.Command) ([]string, BuildDelta) {
	delta := BuildDelta{Compiler: cfg.File.Host.Clang}
	if command.Language == "c++" {
		delta.Compiler = cfg.File.Host.ClangXX
	}
	var flags []string
	for i := 1; i < len(command.Arguments); i++ {
		arg := command.Arguments[i]
		if hostDropWithValue[arg] {
			delta.RemovedFlags = append(delta.RemovedFlags, arg)
			i++
			continue
		}
		if hostDropExact[arg] {
			if arg != "-c" && arg != "-S" && arg != "-E" && arg != "-fsyntax-only" {
				delta.RemovedFlags = append(delta.RemovedFlags, arg)
			}
			continue
		}
		if isCompileSourceArg(arg, command.File, command.Directory) {
			continue
		}
		drop := false
		for _, prefix := range hostDropPrefixes {
			if strings.HasPrefix(arg, prefix) && arg != prefix {
				drop = true
				break
			}
		}
		if drop {
			delta.RemovedFlags = append(delta.RemovedFlags, arg)
			continue
		}
		switch arg {
		case "-mthumb", "-marm", "-mfloat-abi", "-mcpu", "-mfpu", "-mabi", "-march":
			delta.RemovedFlags = append(delta.RemovedFlags, arg)
			i++
			continue
		}
		flags = append(flags, arg)
	}
	flags = append(flags, "-I", cfg.Root)
	flags = append(flags, cfg.File.Host.ExtraCFlags...)
	flags = append(flags, "-Wno-unused-command-line-argument")
	delta.RemovedFlags = uniqueSorted(delta.RemovedFlags)
	delta.AddedFlags = append([]string{}, cfg.File.Host.ExtraCFlags...)
	return flags, delta
}

func isCompileSourceArg(arg, source, directory string) bool {
	if arg == source || arg == filepath.Base(source) {
		return true
	}
	if strings.HasPrefix(arg, "-") {
		return false
	}
	if !filepath.IsAbs(arg) {
		arg = filepath.Join(directory, arg)
	}
	return filepath.Clean(arg) == source
}

func mergeDelta(dst *BuildDelta, src BuildDelta) {
	dst.RemovedFlags = uniqueSorted(append(dst.RemovedFlags, src.RemovedFlags...))
	dst.AddedFlags = uniqueSorted(append(dst.AddedFlags, src.AddedFlags...))
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	// Stable insertion sort keeps this package dependency-free and output
	// deterministic.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
