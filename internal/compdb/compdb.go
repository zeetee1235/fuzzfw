// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package compdb parses Clang JSON compilation databases.
//
// A compilation database describes individual compiler invocations, not final
// link inputs. The manifest records that limitation explicitly.
package compdb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/exitcode"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/proc"
)

// Entry is one raw JSON compilation database record.
type Entry struct {
	Directory string   `json:"directory"`
	File      string   `json:"file"`
	Arguments []string `json:"arguments"`
	Command   string   `json:"command"`
	Output    string   `json:"output"`
}

// Command is a normalized compiler invocation.
type Command struct {
	Directory      string   `json:"directory"`
	File           string   `json:"file"`
	Compiler       string   `json:"compiler"`
	Language       string   `json:"language"`
	VariantID      string   `json:"variant_id"`
	TargetTriple   string   `json:"target_triple,omitempty"`
	Arguments      []string `json:"arguments"`
	Normalized     []string `json:"normalized_arguments"`
	IncludeDirs    []string `json:"include_dirs,omitempty"`
	ForcedIncludes []string `json:"forced_includes,omitempty"`
	Defines        []string `json:"defines,omitempty"`
	Undefines      []string `json:"undefines,omitempty"`
	Standard       string   `json:"standard,omitempty"`
}

// Database is a validated compilation database.
type Database struct {
	Path        string            `json:"path"`
	Root        string            `json:"root"`
	SHA256      string            `json:"sha256"`
	Commands    []Command         `json:"commands"`
	Diagnostics []diag.Diagnostic `json:"diagnostics,omitempty"`
}

// SourceFiles returns unique source paths.
func (d *Database) SourceFiles() []string {
	seen := map[string]bool{}
	var files []string
	for _, command := range d.Commands {
		if !seen[command.File] {
			seen[command.File] = true
			files = append(files, command.File)
		}
	}
	return files
}

// ByFile groups commands by source path.
func (d *Database) ByFile() map[string][]Command {
	out := map[string][]Command{}
	for _, command := range d.Commands {
		out[command.File] = append(out[command.File], command)
	}
	return out
}

// CommandFor returns the command for a source file, optionally filtered by
// build variant.
func (d *Database) CommandFor(file, variant string) (Command, bool) {
	for _, command := range d.Commands {
		if command.File != file {
			continue
		}
		if variant == "" || command.VariantID == variant {
			return command, true
		}
	}
	return Command{}, false
}

// Load validates and normalizes a compilation database.
func Load(ctx context.Context, path, root string) (*Database, error) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, &diag.Error{
			Code:     diag.ECompDBMissing,
			Message:  fmt.Sprintf("compilation database not found: %s", path),
			ExitCode: exitcode.Usage,
			Remediation: "Generate one with CMake: cmake -S . -B build " +
				"-DCMAKE_EXPORT_COMPILE_COMMANDS=ON, or enable a CMake File API " +
				"codemodel-v2 query in the build directory, then set project.compdb.",
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read compilation database: %w", err)
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, &diag.Error{
			Code:     diag.ECompDBInvalid,
			Message:  fmt.Sprintf("invalid JSON in compilation database %s: %v", path, err),
			ExitCode: exitcode.Usage,
		}
	}
	if entries == nil {
		return nil, &diag.Error{
			Code:     diag.ECompDBInvalid,
			Message:  "compilation database root must be an array",
			ExitCode: exitcode.Usage,
		}
	}
	return buildDatabase(ctx, entries, path, root, fsutil.HashString(string(data)))
}

// buildDatabase validates and normalizes raw entries. It is shared by the
// compile_commands.json loader and the CMake File API fallback.
func buildDatabase(ctx context.Context, entries []Entry, path, root, sha string) (*Database, error) {
	db := &Database{
		Path:   path,
		Root:   root,
		SHA256: sha,
	}
	tripleCache := map[string]string{}
	seen := map[string]bool{}
	for index, entry := range entries {
		directory := entry.Directory
		if directory == "" {
			db.Diagnostics = append(db.Diagnostics, diag.Newf(diag.ECompDBInvalid, "entry %d is missing directory", index))
			continue
		}
		directory = fsutil.Resolve(root, directory)
		file := entry.File
		if file == "" {
			db.Diagnostics = append(db.Diagnostics, diag.Newf(diag.ECompDBInvalid, "entry %d is missing file", index))
			continue
		}
		if !filepath.IsAbs(file) {
			file = filepath.Join(directory, file)
		}
		file = filepath.Clean(file)
		if info, err := os.Stat(file); err != nil || info.IsDir() {
			db.Diagnostics = append(db.Diagnostics, diag.Newf(diag.ESourceMissing, "source file not found: %s", file).WithTarget(file))
			continue
		}

		args := entry.Arguments
		if len(args) > 0 && entry.Command != "" {
			db.Diagnostics = append(db.Diagnostics, diag.Newf(
				diag.ECompDBInvalid, "entry %d has both arguments and command; arguments used", index,
			).Warning())
		}
		if len(args) == 0 {
			if entry.Command == "" {
				db.Diagnostics = append(db.Diagnostics, diag.Newf(
					diag.ECompDBInvalid, "entry %d has neither arguments nor command", index,
				))
				continue
			}
			parsed, err := splitCommand(entry.Command)
			if err != nil {
				db.Diagnostics = append(db.Diagnostics, diag.Newf(
					diag.ECompDBInvalid, "entry %d command cannot be parsed: %v", index, err,
				))
				continue
			}
			args = parsed
		}
		if len(args) == 0 {
			db.Diagnostics = append(db.Diagnostics, diag.Newf(diag.ECompDBInvalid, "entry %d has an empty compiler command", index))
			continue
		}

		language := languageOf(file, args)
		normalized := Normalize(args, file, language, root, directory)
		variantSource := struct {
			File      string   `json:"file"`
			Language  string   `json:"language"`
			Arguments []string `json:"arguments"`
		}{
			File:      fsutil.Rel(root, file),
			Language:  language,
			Arguments: normalized,
		}
		variantHash, err := fsutil.HashJSON(variantSource)
		if err != nil {
			return nil, err
		}
		variant := variantHash[:20]
		key := file + "\x00" + variant
		if seen[key] {
			db.Diagnostics = append(db.Diagnostics, diag.Newf(
				diag.ECompDBInvalid, "duplicate compilation entry ignored: %s", file,
			).Warning())
			continue
		}
		seen[key] = true

		compiler := args[0]
		triple := targetTripleFromArgs(args)
		if triple == "" {
			if cached, ok := tripleCache[compiler]; ok {
				triple = cached
			} else {
				triple = probeTargetTriple(ctx, compiler, directory)
				tripleCache[compiler] = triple
			}
		}
		includes, forced, defines, undefines, standard := extractOptions(args, directory)
		db.Commands = append(db.Commands, Command{
			Directory:      directory,
			File:           file,
			Compiler:       compiler,
			Language:       language,
			VariantID:      variant,
			TargetTriple:   triple,
			Arguments:      append([]string(nil), args...),
			Normalized:     normalized,
			IncludeDirs:    includes,
			ForcedIncludes: forced,
			Defines:        defines,
			Undefines:      undefines,
			Standard:       standard,
		})
	}
	if len(db.Commands) == 0 {
		db.Diagnostics = append(db.Diagnostics, diag.New(diag.ECompDBInvalid, "compilation database contains no usable translation units"))
	}
	return db, nil
}

var dropWithValue = map[string]bool{
	"-o": true, "-MF": true, "-MT": true, "-MQ": true, "-MJ": true, "--output": true, "-x": true,
}

var dropExact = map[string]bool{
	"-c": true, "-S": true, "-E": true, "-M": true, "-MM": true, "-MD": true, "-MMD": true,
	"-MP": true, "-MG": true, "-Winvalid-pch": true, "-fsyntax-only": true, "--no-warnings": true,
}

var dropPrefixes = []string{"-o", "-MF", "-MT", "-MQ", "-MJ"}

// Normalize removes output/dependency flags and stabilizes path spelling for a
// build-variant identity. It never removes preprocessor definitions or include
// paths from the compile arguments.
func Normalize(args []string, sourceFile, language, root, directory string) []string {
	out := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if index == 0 {
			out = append(out, filepath.Base(arg))
			continue
		}
		if dropWithValue[arg] {
			index++
			continue
		}
		if dropExact[arg] {
			continue
		}
		drop := false
		for _, prefix := range dropPrefixes {
			if strings.HasPrefix(arg, prefix) && arg != prefix {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		if sameSourceArg(arg, sourceFile, directory) {
			out = append(out, "<source>")
			continue
		}
		if strings.HasPrefix(arg, "-I") && len(arg) > 2 {
			out = append(out, "-I"+stablePath(arg[2:], root, directory))
			continue
		}
		if strings.HasPrefix(arg, "-isystem") && len(arg) > len("-isystem") {
			out = append(out, "-isystem"+stablePath(arg[len("-isystem"):], root, directory))
			continue
		}
		out = append(out, arg)
	}
	return out
}

func sameSourceArg(arg, sourceFile, directory string) bool {
	if arg == sourceFile || arg == filepath.Base(sourceFile) {
		return true
	}
	if !filepath.IsAbs(arg) {
		arg = filepath.Join(directory, arg)
	}
	return filepath.Clean(arg) == sourceFile
}

func stablePath(value, root, directory string) string {
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(directory, path)
	}
	path = filepath.Clean(path)
	if fsutil.Within(root, path) {
		return fsutil.Rel(root, path)
	}
	return path
}

func languageOf(file string, args []string) string {
	for i, arg := range args {
		if arg == "-x" && i+1 < len(args) {
			return normalizeLanguage(args[i+1])
		}
		if strings.HasPrefix(arg, "-x") && len(arg) > 2 {
			return normalizeLanguage(arg[2:])
		}
	}
	switch strings.ToLower(filepath.Ext(file)) {
	case ".c", ".h":
		return "c"
	case ".cc", ".cp", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h++":
		return "c++"
	case ".m":
		return "objective-c"
	case ".mm":
		return "objective-c++"
	default:
		return "unknown"
	}
}

func normalizeLanguage(value string) string {
	switch value {
	case "c", "c-header":
		return "c"
	case "c++", "c++-header":
		return "c++"
	case "objective-c", "objective-c-header":
		return "objective-c"
	case "objective-c++", "objective-c++-header":
		return "objective-c++"
	default:
		return value
	}
}

var pathOptions = map[string]bool{
	"-I": true, "-isystem": true, "-iquote": true, "-idirafter": true,
	"-include": true, "-imacros": true, "-include-pch": true,
}

func extractOptions(args []string, directory string) ([]string, []string, []string, []string, string) {
	var includes, forced, defines, undefines []string
	var standard string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if pathOptions[arg] && index+1 < len(args) {
			index++
			value := resolveOptionPath(args[index], directory)
			switch arg {
			case "-include", "-imacros", "-include-pch":
				forced = append(forced, value)
			default:
				includes = append(includes, value)
			}
			continue
		}
		switch {
		case strings.HasPrefix(arg, "-I") && len(arg) > 2:
			includes = append(includes, resolveOptionPath(arg[2:], directory))
		case strings.HasPrefix(arg, "-isystem") && len(arg) > len("-isystem"):
			includes = append(includes, resolveOptionPath(arg[len("-isystem"):], directory))
		case strings.HasPrefix(arg, "-D") && len(arg) > 2:
			defines = append(defines, arg[2:])
		case arg == "-D" && index+1 < len(args):
			index++
			defines = append(defines, args[index])
		case strings.HasPrefix(arg, "-U") && len(arg) > 2:
			undefines = append(undefines, arg[2:])
		case arg == "-U" && index+1 < len(args):
			index++
			undefines = append(undefines, args[index])
		case strings.HasPrefix(arg, "-std="):
			standard = strings.TrimPrefix(arg, "-std=")
		}
	}
	return unique(includes), unique(forced), unique(defines), unique(undefines), standard
}

func resolveOptionPath(value, directory string) string {
	if !filepath.IsAbs(value) {
		value = filepath.Join(directory, value)
	}
	return filepath.Clean(value)
}

func targetTripleFromArgs(args []string) string {
	for i, arg := range args {
		switch {
		case (arg == "--target" || arg == "-target") && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(arg, "--target="):
			return strings.TrimPrefix(arg, "--target=")
		case strings.HasPrefix(arg, "-target="):
			return strings.TrimPrefix(arg, "-target=")
		}
	}
	return ""
}

func probeTargetTriple(ctx context.Context, compiler, directory string) string {
	resolved, err := proc.LookPath(compiler)
	if err != nil {
		return ""
	}
	result, err := proc.RunSimple(ctx, directory, 10*time.Second, resolved, "-dumpmachine")
	if err != nil || result == nil || !result.OK() {
		return ""
	}
	return strings.TrimSpace(result.Stdout)
}

func unique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// splitCommand implements the minimal POSIX-like quoting needed for legacy
// compilation database "command" fields. It performs no shell expansion.
func splitCommand(command string) ([]string, error) {
	var args []string
	var current strings.Builder
	inSingle, inDouble, escaped, hasToken := false, false, false, false
	flush := func() {
		if hasToken {
			args = append(args, current.String())
			current.Reset()
			hasToken = false
		}
	}
	for _, r := range command {
		if escaped {
			current.WriteRune(r)
			hasToken = true
			escaped = false
			continue
		}
		if inSingle {
			if r == '\'' {
				inSingle = false
			} else {
				current.WriteRune(r)
			}
			hasToken = true
			continue
		}
		if inDouble {
			switch r {
			case '"':
				inDouble = false
			case '\\':
				escaped = true
			default:
				current.WriteRune(r)
			}
			hasToken = true
			continue
		}
		switch r {
		case '\\':
			escaped = true
			hasToken = true
		case '\'':
			inSingle = true
			hasToken = true
		case '"':
			inDouble = true
			hasToken = true
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			current.WriteRune(r)
			hasToken = true
		}
	}
	if escaped || inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote or escape")
	}
	flush()
	return args, nil
}
