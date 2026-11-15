// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package compdb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
)

type fileAPIIndex struct {
	Objects []struct {
		JSONFile string `json:"jsonFile"`
		Kind     string `json:"kind"`
		Version  struct {
			Major int `json:"major"`
		} `json:"version"`
	} `json:"objects"`
	Reply map[string]struct {
		JSONFile string `json:"jsonFile"`
	} `json:"reply"`
}

func (index fileAPIIndex) jsonFile(kind string) string {
	best := ""
	bestMajor := -1
	for _, object := range index.Objects {
		if object.Kind == kind && object.Version.Major > bestMajor {
			best = object.JSONFile
			bestMajor = object.Version.Major
		}
	}
	if best != "" {
		return best
	}
	return index.Reply[kind+"-v2"].JSONFile
}

type fileAPICodemodel struct {
	Configurations []struct {
		Name    string `json:"name"`
		Targets []struct {
			Name     string `json:"name"`
			JSONFile string `json:"jsonFile"`
		} `json:"targets"`
	} `json:"configurations"`
}

type fileAPITarget struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	CompileGroups []struct {
		Language                string `json:"language"`
		SourceIndexes           []int  `json:"sourceIndexes"`
		CompileCommandFragments []struct {
			Fragment string `json:"fragment"`
		} `json:"compileCommandFragments"`
		Includes []struct {
			Path     string `json:"path"`
			IsSystem bool   `json:"isSystem"`
		} `json:"includes"`
		Defines []struct {
			Define string `json:"define"`
		} `json:"defines"`
	} `json:"compileGroups"`
	Sources []struct {
		Path              string `json:"path"`
		CompileGroupIndex *int   `json:"compileGroupIndex"`
	} `json:"sources"`
	Paths struct {
		Source string `json:"source"`
		Build  string `json:"build"`
	} `json:"paths"`
}

type fileAPICache struct {
	Entries []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"entries"`
}

// LoadCMakeFileAPI reads a CMake File API codemodel reply and converts it into
// the same normalized command model as compile_commands.json. It is a fallback
// for projects that do not export a compilation database.
func LoadCMakeFileAPI(ctx context.Context, buildDir, root string) (*Database, error) {
	replyDir := filepath.Join(buildDir, ".cmake", "api", "v1", "reply")
	indexes, _ := filepath.Glob(filepath.Join(replyDir, "index-*.json"))
	if len(indexes) == 0 {
		return nil, &diag.Error{
			Code:     diag.ECompDBMissing,
			Message:  fmt.Sprintf("no CMake File API reply found under %s", replyDir),
			ExitCode: exitcode.Usage,
			Remediation: "Configure without compile_commands.json using a CMake File API query for " +
				"codemodel-v2, or export compile_commands.json with -DCMAKE_EXPORT_COMPILE_COMMANDS=ON.",
		}
	}
	sort.Strings(indexes)
	indexPath := indexes[len(indexes)-1]
	var index fileAPIIndex
	if err := readFileAPIJSON(indexPath, &index); err != nil {
		return nil, err
	}
	codemodelFile := index.jsonFile("codemodel")
	if codemodelFile == "" {
		return nil, &diag.Error{
			Code:        diag.ECompDBInvalid,
			Message:     "CMake File API reply has no codemodel-v2 object",
			ExitCode:    exitcode.Usage,
			Remediation: "Request codemodel-v2 in the CMake File API query.",
		}
	}
	var codemodel fileAPICodemodel
	if err := readFileAPIJSON(filepath.Join(replyDir, codemodelFile), &codemodel); err != nil {
		return nil, err
	}
	compilers := map[string]string{}
	if cacheFile := index.jsonFile("cache"); cacheFile != "" {
		var cache fileAPICache
		if err := readFileAPIJSON(filepath.Join(replyDir, cacheFile), &cache); err == nil {
			for _, entry := range cache.Entries {
				switch entry.Name {
				case "CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER":
					if entry.Value != "" && !strings.HasSuffix(entry.Value, "-NOTFOUND") {
						compilers[entry.Name] = entry.Value
					}
				}
			}
		}
	}
	var entries []Entry
	for _, configuration := range codemodel.Configurations {
		for _, targetRef := range configuration.Targets {
			var target fileAPITarget
			if err := readFileAPIJSON(filepath.Join(replyDir, targetRef.JSONFile), &target); err != nil {
				return nil, err
			}
			if target.Type == "INTERFACE_LIBRARY" {
				continue
			}
			groupForSource := map[int]int{}
			for groupIndex, group := range target.CompileGroups {
				for _, sourceIndex := range group.SourceIndexes {
					groupForSource[sourceIndex] = groupIndex
				}
			}
			for sourceIndex, source := range target.Sources {
				groupIndex := -1
				if source.CompileGroupIndex != nil {
					groupIndex = *source.CompileGroupIndex
				} else if index, ok := groupForSource[sourceIndex]; ok {
					groupIndex = index
				}
				if groupIndex < 0 || groupIndex >= len(target.CompileGroups) {
					continue
				}
				group := target.CompileGroups[groupIndex]
				language := strings.ToUpper(group.Language)
				compiler := compilers["CMAKE_C_COMPILER"]
				if language == "CXX" {
					compiler = compilers["CMAKE_CXX_COMPILER"]
				}
				if compiler == "" {
					if language == "CXX" {
						compiler = "c++"
					} else {
						compiler = "cc"
					}
				}
				sourcePath := source.Path
				if !filepath.IsAbs(sourcePath) {
					sourcePath = filepath.Join(target.Paths.Build, sourcePath)
					if _, err := os.Stat(sourcePath); err != nil {
						sourcePath = filepath.Join(root, source.Path)
					}
				}
				args := []string{compiler}
				for _, fragment := range group.CompileCommandFragments {
					if strings.TrimSpace(fragment.Fragment) != "" {
						args = append(args, splitFragment(fragment.Fragment)...)
					}
				}
				for _, include := range group.Includes {
					flag := "-I"
					if include.IsSystem {
						flag = "-isystem"
					}
					args = append(args, flag+include.Path)
				}
				for _, define := range group.Defines {
					args = append(args, "-D"+define.Define)
				}
				directory := target.Paths.Build
				if directory == "" {
					directory = buildDir
				}
				entries = append(entries, Entry{
					Directory: directory,
					File:      sourcePath,
					Arguments: args,
				})
			}
		}
	}
	if len(entries) == 0 {
		return nil, &diag.Error{
			Code:        diag.ECompDBInvalid,
			Message:     "CMake File API codemodel produced no compiling sources",
			ExitCode:    exitcode.Usage,
			Remediation: "Check the CMake File API query includes codemodel-v2 and the project builds at least one translation unit.",
		}
	}
	hash, _ := fsutil.HashJSON(entries)
	return buildDatabase(ctx, entries, indexPath, root, hash)
}

func readFileAPIJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return &diag.Error{
			Code:     diag.ECompDBInvalid,
			Message:  fmt.Sprintf("cannot read CMake File API object %s: %v", path, err),
			ExitCode: exitcode.Usage,
		}
	}
	if err := json.Unmarshal(data, target); err != nil {
		return &diag.Error{
			Code:     diag.ECompDBInvalid,
			Message:  fmt.Sprintf("invalid CMake File API JSON %s: %v", path, err),
			ExitCode: exitcode.Usage,
		}
	}
	return nil
}

func splitFragment(fragment string) []string {
	// File API fragments are usually single shell-like tokens. Keep quoted
	// spaces together without invoking a shell.
	var out []string
	var current strings.Builder
	quote := rune(0)
	for _, r := range fragment {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			if current.Len() > 0 {
				out = append(out, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}
