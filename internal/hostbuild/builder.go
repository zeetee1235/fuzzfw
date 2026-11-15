// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package hostbuild

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fuzzfw/fuzzfw/internal/compdb"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/harness"
	"github.com/fuzzfw/fuzzfw/internal/planner"
	"github.com/fuzzfw/fuzzfw/internal/proc"
	eventsruntime "github.com/fuzzfw/fuzzfw/runtime/events"
	runtimereplay "github.com/fuzzfw/fuzzfw/runtime/replay"
)

// Build compiles and self-tests one target. Expected build failures are returned
// as Result diagnostics; Go errors are reserved for I/O and internal failures.
func (b *Builder) Build(target planner.TargetPlan, hp *harness.Plan) (*Result, error) {
	if b.Ctx == nil {
		b.Ctx = context.Background()
	}
	if b.Workspace == nil {
		return nil, fmt.Errorf("hostbuild: nil workspace")
	}
	if err := b.Workspace.Ensure(); err != nil {
		return nil, err
	}
	generatedDir := b.Workspace.TargetGenerated(target.Name)
	buildDir := b.Workspace.TargetBuild(target.Name)
	if err := os.MkdirAll(generatedDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return nil, err
	}
	logPath := filepath.Join(buildDir, "build.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()

	result := &Result{
		Target:         target.Name,
		Classification: target.Classification,
		Engine:         b.Engine,
		HarnessID:      hp.HarnessID,
		EntrySymbol:    firstNonEmptyString(hp.Target.LinkSymbol, hp.Target.CallSymbol),
		BuildLog:       logPath,
		Adapters:       append([]planner.AdapterBinding(nil), target.Adapters...),
		Dependencies:   append([]string(nil), target.Dependencies...),
	}
	if target.Classification == planner.Blocked {
		result.Status = StatusBlocked
		result.Diagnostics = append(result.Diagnostics, diag.New(diag.EHarnessSource,
			"target is blocked by static planning; build was not attempted",
		).WithTarget(target.Name))
		return result, nil
	}
	if target.Classification == planner.Adaptable && target.Wrapper == nil {
		result.Status = StatusNotFuzzable
		result.Diagnostics = append(result.Diagnostics, diag.New(diag.EContextUnknown,
			"target is adaptable, not ready: provide a user wrapper or verified context before building",
		).WithTarget(target.Name))
		return result, nil
	}

	planPath := filepath.Join(generatedDir, "harness_plan.json")
	if err := fsutil.WriteJSON(planPath, hp, true); err != nil {
		return nil, err
	}
	result.HarnessPlanPath = planPath
	if len(target.Dictionary) > 0 {
		dictionaryPath := filepath.Join(generatedDir, "dictionary.txt")
		if err := fsutil.WriteFileAtomic(dictionaryPath, []byte(strings.Join(target.Dictionary, "\n")+"\n"), 0o644); err != nil {
			return nil, err
		}
		result.DictionaryPath = dictionaryPath
	}
	source, extension, err := harness.Emit(hp, b.Cfg)
	if err != nil {
		result.Status = StatusHarnessBuildFailed
		result.Diagnostics = append(result.Diagnostics, diag.Newf(diag.EHarnessBuild,
			"cannot emit harness: %v", err).WithTarget(target.Name))
		return result, nil
	}
	harnessPath := filepath.Join(generatedDir, "harness"+extension)
	if err := fsutil.WriteFileAtomic(harnessPath, []byte(source), 0o644); err != nil {
		return nil, err
	}
	result.HarnessSourcePath = harnessPath
	result.HarnessSHA256 = fsutil.HashString(source)

	if err := b.runHostBuildCommand(logFile); err != nil {
		result.Status = StatusHarnessBuildFailed
		result.Diagnostics = append(result.Diagnostics, *err)
		return result, nil
	}

	selftestProfile, fuzzProfile, profileDiags := b.profiles(target)
	result.Diagnostics = append(result.Diagnostics, profileDiags...)
	objects, delta, compileDiags, ok := b.compileTarget(target, hp, harnessPath, selftestProfile, logFile)
	result.Delta = delta
	result.Objects = objects
	result.Diagnostics = append(result.Diagnostics, compileDiags...)
	if !ok {
		result.Status = StatusHarnessBuildFailed
		return result, nil
	}
	selftestBinary := filepath.Join(buildDir, "selftest")
	if diag := b.link(target, selftestProfile, objects, selftestBinary, logFile); diag != nil {
		result.Diagnostics = append(result.Diagnostics, *diag)
		result.Status = StatusHarnessBuildFailed
		return result, nil
	}
	result.SelftestBinary = selftestBinary
	if hash, err := fsutil.HashFile(selftestBinary); err == nil {
		result.SelftestSHA256 = hash
	}

	selftest, selftestDiags := b.runSelftest(target, hp, selftestBinary, buildDir)
	result.Selftest = selftest
	result.Diagnostics = append(result.Diagnostics, selftestDiags...)
	switch {
	case selftest.CrashCount > 0:
		result.Status = StatusSmokeCrashed
	case selftest.EntryUnknown:
		result.Status = StatusNotFuzzable
		result.Diagnostics = append(result.Diagnostics, diag.New(diag.EEntryUnreached,
			"entry reachability is unknown because coverage instrumentation is disabled",
		).WithTarget(target.Name))
	case !selftest.EntryHit:
		result.Status = StatusEntryUnreached
		result.Diagnostics = append(result.Diagnostics, diag.New(diag.EEntryUnreached,
			"target entry symbol was not observed during self-test",
		).WithTarget(target.Name))
	case !selftest.Stable:
		result.Status = StatusStateLeak
		result.Diagnostics = append(result.Diagnostics, diag.New(diag.EStateLeak,
			"repeated isolated executions produced different coverage/exit results",
		).WithTarget(target.Name))
	default:
		result.Status = StatusSelftestPassed
	}

	if fuzzProfile != nil {
		fuzzObjects, fuzzDelta, fuzzDiags, fuzzOK := b.compileTarget(target, hp, harnessPath, *fuzzProfile, logFile)
		mergeDelta(&result.Delta, fuzzDelta)
		result.Diagnostics = append(result.Diagnostics, fuzzDiags...)
		if fuzzOK {
			fuzzBinary := filepath.Join(buildDir, "fuzz_target")
			if linkDiag := b.link(target, *fuzzProfile, fuzzObjects, fuzzBinary, logFile); linkDiag != nil {
				result.Diagnostics = append(result.Diagnostics, *linkDiag)
			} else {
				result.FuzzBinary = fuzzBinary
				if hash, err := fsutil.HashFile(fuzzBinary); err == nil {
					result.FuzzSHA256 = hash
				}
			}
		}
	}
	result.Delta.Sanitizers = append([]string(nil), b.Cfg.File.Host.Sanitizers...)
	result.Delta.AddedFlags = uniqueSorted(append(result.Delta.AddedFlags,
		selftestProfile.CompileFlags...))
	if result.Selftest.EntryHit && result.Selftest.CrashCount == 0 && result.Selftest.Stable {
		if b.Engine == "replay" {
			result.Status = StatusSelftestPassed
		} else if result.FuzzBinary != "" {
			result.Status = StatusFuzzable
		} else {
			result.Status = StatusNotFuzzable
			result.Diagnostics = append(result.Diagnostics, diag.New(diag.EEngineUnavailable,
				"self-test passed but no engine-specific fuzz binary is available",
			).WithTarget(target.Name))
		}
	}
	return result, nil
}

func (b *Builder) runHostBuildCommand(logFile *os.File) *diag.Diagnostic {
	if len(b.Cfg.File.Host.BuildCommand) == 0 {
		return nil
	}
	argv := b.Cfg.File.Host.BuildCommand
	_, _ = fmt.Fprintf(logFile, "$ (host.build_command) %s\n", proc.Display(argv))
	result, err := (proc.Runner{Timeout: 30 * time.Minute}).Run(b.Ctx, b.Cfg.Root, argv...)
	if err != nil {
		d := diag.Wrap(diag.EHarnessBuild, "host.build_command failed to start", err)
		dd := d.Diagnostic()
		return &dd
	}
	_, _ = fmt.Fprint(logFile, result.Stdout)
	_, _ = fmt.Fprint(logFile, result.Stderr)
	if !result.OK() {
		d := diag.Newf(diag.EHarnessBuild,
			"host.build_command failed with exit %d", result.ExitCode,
		).WithEvidence(result.Stderr)
		return &d
	}
	return nil
}

func (b *Builder) compileTarget(
	target planner.TargetPlan,
	hp *harness.Plan,
	harnessPath string,
	profile buildProfile,
	logFile *os.File,
) ([]string, BuildDelta, []diag.Diagnostic, bool) {
	var objects []string
	var diagnostics []diag.Diagnostic
	delta := BuildDelta{Compiler: profile.CompilerC}
	objDir := filepath.Join(b.Workspace.TargetBuild(target.Name), "objects", profile.Name)
	runtimeDir := filepath.Join(b.Workspace.TargetBuild(target.Name), "runtime")
	if err := os.MkdirAll(objDir, 0o755); err != nil {
		diagnostics = append(diagnostics, diag.Newf(diag.EInternal, "cannot create object dir: %v", err).WithTarget(target.Name))
		return nil, delta, diagnostics, false
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		diagnostics = append(diagnostics, diag.Newf(diag.EInternal, "cannot create runtime dir: %v", err).WithTarget(target.Name))
		return nil, delta, diagnostics, false
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(runtimeDir, "fuzzfw_events.h"), eventsruntime.HeaderSource, 0o644); err != nil {
		return nil, delta, []diag.Diagnostic{diag.Newf(diag.EInternal, "cannot write event header: %v", err).WithTarget(target.Name)}, false
	}
	eventsSource := filepath.Join(runtimeDir, "fuzzfw_events.c")
	if err := fsutil.WriteFileAtomic(eventsSource, eventsruntime.Source, 0o644); err != nil {
		return nil, delta, []diag.Diagnostic{diag.Newf(diag.EInternal, "cannot write event runtime: %v", err).WithTarget(target.Name)}, false
	}

	targetCommand, commandOK := b.commandForTarget(target)
	for _, dependency := range b.buildSources(target) {
		command, ok := b.commandForSource(dependency, target.VariantID)
		var flags []string
		language := "c"
		if ok {
			projectFlags, commandDelta := hostFlags(b.Cfg, command)
			flags = projectFlags
			mergeDelta(&delta, commandDelta)
			language = command.Language
		} else {
			flags = []string{"-I", b.Cfg.Root, "-I", runtimeDir}
		}
		flags = append(flags, "-I", runtimeDir)
		if commandOK && !ok && targetCommand.File != "" {
			projectFlags, commandDelta := hostFlags(b.Cfg, targetCommand)
			flags = projectFlags
			mergeDelta(&delta, commandDelta)
		}
		object, d := b.compileOne(profile, language, dependency, flags, objDir, logFile)
		if d != nil {
			d.Target = target.Name
			diagnostics = append(diagnostics, *d)
			return objects, delta, diagnostics, false
		}
		objects = append(objects, object)
	}

	for _, adapter := range target.Adapters {
		source := absJoin(b.Cfg.Root, adapter.ReplacementSource)
		flags := append([]string{"-I", b.Cfg.Root, "-I", runtimeDir}, b.defaultIncludeFlags(target)...)
		language := "c"
		if strings.HasSuffix(strings.ToLower(adapter.ReplacementSource), ".cpp") ||
			strings.HasSuffix(strings.ToLower(adapter.ReplacementSource), ".cc") {
			language = "c++"
		}
		if commandOK {
			var commandDelta BuildDelta
			projectFlags, commandDelta := hostFlags(b.Cfg, targetCommand)
			flags = append(projectFlags, b.defaultIncludeFlags(target)...)
			flags = append(flags, "-I", runtimeDir)
			mergeDelta(&delta, commandDelta)
		}
		object, d := b.compileOne(profile, language, source, flags, objDir, logFile)
		if d != nil {
			d.Target = target.Name
			diagnostics = append(diagnostics, *d)
			return objects, delta, diagnostics, false
		}
		objects = append(objects, object)
	}
	if target.Wrapper != nil {
		wrapperSource := absJoin(b.Cfg.Root, target.Wrapper.Source)
		flags := append([]string{"-I", b.Cfg.Root, "-I", runtimeDir}, b.defaultIncludeFlags(target)...)
		language := "c"
		if commandOK {
			var commandDelta BuildDelta
			projectFlags, commandDelta := hostFlags(b.Cfg, targetCommand)
			flags = append(projectFlags, b.defaultIncludeFlags(target)...)
			flags = append(flags, "-I", runtimeDir)
			mergeDelta(&delta, commandDelta)
		}
		if strings.HasSuffix(strings.ToLower(wrapperSource), ".cpp") ||
			strings.HasSuffix(strings.ToLower(wrapperSource), ".cc") {
			language = "c++"
		}
		object, d := b.compileOne(profile, language, wrapperSource, flags, objDir, logFile)
		if d != nil {
			d.Target = target.Name
			diagnostics = append(diagnostics, *d)
			return objects, delta, diagnostics, false
		}
		objects = append(objects, object)
	}

	harnessLanguage := hp.Target.Language
	if harnessLanguage != "c++" {
		harnessLanguage = "c"
	}
	flags := append([]string{"-I", b.Cfg.Root, "-I", runtimeDir}, b.defaultIncludeFlags(target)...)
	if commandOK {
		var commandDelta BuildDelta
		projectFlags, commandDelta := hostFlags(b.Cfg, targetCommand)
		flags = append(projectFlags, b.defaultIncludeFlags(target)...)
		flags = append(flags, "-I", runtimeDir)
		mergeDelta(&delta, commandDelta)
	}
	object, d := b.compileOne(profile, harnessLanguage, harnessPath, flags, objDir, logFile)
	if d != nil {
		d.Target = target.Name
		diagnostics = append(diagnostics, *d)
		return objects, delta, diagnostics, false
	}
	objects = append(objects, object)

	eventProfile := profile
	eventProfile.CompileFlags = withoutCoverage(profile.CompileFlags)
	eventObject, eventDiag := b.compileOne(eventProfile, "c", eventsSource, []string{"-I", runtimeDir}, objDir, logFile)
	if eventDiag != nil {
		eventDiag.Target = target.Name
		diagnostics = append(diagnostics, *eventDiag)
		return objects, delta, diagnostics, false
	}
	objects = append(objects, eventObject)

	if profile.NeedReplay {
		driverSource := filepath.Join(objDir, "replay_driver.c")
		if err := fsutil.WriteFileAtomic(driverSource, runtimereplay.DriverSource, 0o644); err != nil {
			return objects, delta, []diag.Diagnostic{diag.Newf(diag.EInternal, "cannot write replay driver: %v", err).WithTarget(target.Name)}, false
		}
		driverFlags := append([]string{"-I", b.Cfg.Root}, sanitizerFlags(b.Cfg)...)
		driverFlags = append(driverFlags, b.Cfg.File.Host.Optimization, "-g", "-fno-omit-frame-pointer")
		driverProfile := profile
		driverProfile.CompileFlags = withoutCoverage(profile.CompileFlags)
		driver, d := b.compileOne(driverProfile, "c", driverSource, driverFlags, objDir, logFile)
		if d != nil {
			d.Target = target.Name
			diagnostics = append(diagnostics, *d)
			return objects, delta, diagnostics, false
		}
		objects = append(objects, driver)
	}
	return objects, delta, diagnostics, true
}

func (b *Builder) buildSources(target planner.TargetPlan) []string {
	seen := map[string]bool{}
	var out []string
	for _, dependency := range target.Dependencies {
		path := absJoin(b.Cfg.Root, dependency)
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	if target.Wrapper != nil && target.Source != "" {
		path := absJoin(b.Cfg.Root, target.Source)
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	if len(out) == 0 && target.Function != nil {
		path := absJoin(b.Cfg.Root, target.Function.TranslationUnit)
		if !seen[path] {
			out = append(out, path)
		}
	}
	return out
}

func (b *Builder) commandForTarget(target planner.TargetPlan) (compdb.Command, bool) {
	if target.Function != nil {
		if command, ok := b.commandForSource(absJoin(b.Cfg.Root, target.Function.TranslationUnit), target.VariantID); ok {
			return command, true
		}
	}
	if target.Source != "" {
		if command, ok := b.commandForSource(absJoin(b.Cfg.Root, target.Source), target.VariantID); ok {
			return command, true
		}
	}
	for _, dependency := range target.Dependencies {
		if command, ok := b.commandForSource(absJoin(b.Cfg.Root, dependency), target.VariantID); ok {
			return command, true
		}
	}
	return compdb.Command{}, false
}

func (b *Builder) commandForSource(source, variant string) (compdb.Command, bool) {
	source = filepath.Clean(source)
	var fallback *compdb.Command
	for i := range b.DB.Commands {
		command := &b.DB.Commands[i]
		if filepath.Clean(command.File) != source {
			continue
		}
		if variant != "" && command.VariantID == variant {
			return *command, true
		}
		if fallback == nil {
			fallback = command
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return compdb.Command{}, false
}

func (b *Builder) compileOne(
	profile buildProfile,
	language string,
	source string,
	extraFlags []string,
	objDir string,
	logFile *os.File,
) (string, *diag.Diagnostic) {
	compiler := compilerFor(profile, language)
	extension := ".o"
	object := filepath.Join(objDir, fsutil.SafeName(filepath.Base(source), "source")+"-"+fsutil.HashString(source + strings.Join(extraFlags, "\x00") + profile.Name)[:12]+extension)
	flags := append([]string{}, extraFlags...)
	flags = append(flags, profile.CompileFlags...)
	argv := append([]string{compiler}, flags...)
	argv = append(argv, "-c", source, "-o", object)
	_, _ = fmt.Fprintf(logFile, "$ %s\n", proc.Display(argv))
	result, err := (proc.Runner{Timeout: time.Duration(b.Cfg.File.Host.TimeoutSeconds) * time.Second}).Run(b.Ctx, b.Cfg.Root, argv...)
	if err != nil {
		d := diag.Wrap(diag.EHarnessBuild, fmt.Sprintf("cannot start compiler for %s", source), err)
		dd := d.Diagnostic()
		return "", &dd
	}
	_, _ = fmt.Fprint(logFile, result.Stdout)
	_, _ = fmt.Fprint(logFile, result.Stderr)
	if !result.OK() {
		message := fmt.Sprintf("host compile failed for %s (exit %d)", fsutil.Rel(b.Cfg.Root, source), result.ExitCode)
		if result.TimedOut {
			message = fmt.Sprintf("host compile timed out for %s", fsutil.Rel(b.Cfg.Root, source))
		}
		d := diag.New(diag.EHarnessBuild, message).WithEvidence(firstLines(result.Stderr, 8)...)
		return "", &d
	}
	return object, nil
}

func (b *Builder) link(target planner.TargetPlan, profile buildProfile, objects []string, output string, logFile *os.File) *diag.Diagnostic {
	language := "c"
	if b.usesCXX(target) {
		language = "c++"
	}
	compiler := compilerFor(profile, language)
	argv := []string{compiler}
	argv = append(argv, profile.LinkFlags...)
	argv = append(argv, objects...)
	argv = append(argv, "-o", output)
	argv = append(argv, "-ldl", "-lm", "-pthread")
	argv = append(argv, b.Cfg.File.Host.ExtraLDFlags...)
	for _, library := range b.Cfg.File.Host.LinkLibraries {
		if strings.HasPrefix(library, "-l") {
			argv = append(argv, library)
		} else {
			argv = append(argv, "-l"+library)
		}
	}
	for _, path := range b.Cfg.File.Host.LinkObjects {
		argv = append(argv, absJoin(b.Cfg.Root, path))
	}
	for _, path := range b.Cfg.File.Host.Libraries {
		argv = append(argv, absJoin(b.Cfg.Root, path))
	}
	_, _ = fmt.Fprintf(logFile, "$ %s\n", proc.Display(argv))
	result, err := (proc.Runner{Timeout: time.Duration(b.Cfg.File.Host.TimeoutSeconds) * time.Second}).Run(b.Ctx, b.Cfg.Root, argv...)
	if err != nil {
		d := diag.Wrap(diag.EHarnessBuild, "cannot start linker", err)
		dd := d.Diagnostic()
		return &dd
	}
	_, _ = fmt.Fprint(logFile, result.Stdout)
	_, _ = fmt.Fprint(logFile, result.Stderr)
	if !result.OK() {
		d := diag.Newf(diag.ELinkGraphUnknown,
			"link failed (exit %d); check host libraries, host.build_command, and adapters", result.ExitCode,
		).WithEvidence(firstLines(result.Stderr, 10)...)
		return &d
	}
	return nil
}

func (b *Builder) usesCXX(target planner.TargetPlan) bool {
	if target.Language == "c++" {
		return true
	}
	if target.Wrapper != nil && (strings.HasSuffix(strings.ToLower(target.Wrapper.Source), ".cpp") || strings.HasSuffix(strings.ToLower(target.Wrapper.Source), ".cc")) {
		return true
	}
	for _, adapter := range target.Adapters {
		if strings.HasSuffix(strings.ToLower(adapter.ReplacementSource), ".cpp") || strings.HasSuffix(strings.ToLower(adapter.ReplacementSource), ".cc") {
			return true
		}
	}
	return false
}

func (b *Builder) defaultIncludeFlags(target planner.TargetPlan) []string {
	var flags []string
	seen := map[string]bool{}
	add := func(dir string) {
		if dir == "" || seen[dir] {
			return
		}
		seen[dir] = true
		flags = append(flags, "-I", dir)
	}
	add(b.Cfg.Root)
	if target.Header != "" {
		add(filepath.Dir(absJoin(b.Cfg.Root, target.Header)))
	}
	for _, dependency := range target.Dependencies {
		if command, ok := b.commandForSource(absJoin(b.Cfg.Root, dependency), target.VariantID); ok {
			for _, include := range command.IncludeDirs {
				add(include)
			}
		}
	}
	return flags
}

func firstLines(text string, limit int) []string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > limit {
		lines = lines[:limit]
	}
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func withoutCoverage(flags []string) []string {
	out := make([]string, 0, len(flags))
	for _, flag := range flags {
		if strings.HasPrefix(flag, "-fsanitize-coverage=") {
			continue
		}
		out = append(out, flag)
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
