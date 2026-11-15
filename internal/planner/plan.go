// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package planner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/version"
)

// Build plans configured targets, or selected functions, from analysis.
func Build(cfg *config.Config, analysis *analyzer.Analysis, analysisSHA string, selected []string) (*Plan, error) {
	plan := &Plan{
		SchemaVersion:     PlanSchemaVersion,
		Generator:         "fuzzfw-plan/" + version.Version,
		Project:           Project{Name: analysis.Project.Name, Root: cfg.Root, SourceRevision: analysis.Project.SourceRevision},
		ConfigFingerprint: cfg.Fingerprint,
		AnalysisSHA256:    analysisSHA,
	}
	adapterCache := map[string]AdapterBinding{}
	adapterErrors := map[string]diag.Diagnostic{}
	irByFunction := map[string]*analyzer.IRFunctionFact{}
	irBySymbol := map[string]*analyzer.IRFunctionFact{}
	irFlagsByFunction := map[string][]string{}
	for i := range analysis.IRFacts {
		fact := &analysis.IRFacts[i]
		if fact.FunctionID != "" {
			irByFunction[fact.FunctionID] = fact
			irFlagsByFunction[fact.FunctionID] = append([]string(nil), fact.HardwareFlags...)
		}
		irBySymbol[fact.LinkSymbol] = fact
	}

	type selection struct {
		name   string
		target *config.Target
		fn     *analyzer.Function
	}
	var selections []selection
	if len(selected) > 0 {
		for _, name := range selected {
			if target, ok := cfg.Target(name); ok {
				fn := matchFunction(analysis, target)
				selections = append(selections, selection{name: target.Name, target: &target, fn: fn})
				continue
			}
			matches := findFunctions(analysis, name, "", "")
			if len(matches) == 0 {
				selections = append(selections, selection{name: name})
				continue
			}
			for _, fn := range matches {
				selections = append(selections, selection{name: fn.Name, fn: fn})
			}
		}
	} else if len(cfg.Targets) > 0 {
		for i := range cfg.Targets {
			target := cfg.Targets[i]
			selections = append(selections, selection{name: target.Name, target: &target, fn: matchFunction(analysis, target)})
		}
	} else {
		seen := map[string]bool{}
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			if !fn.Definition || fn.Name == "main" || fn.Name == "" || len(fn.Params) == 0 {
				continue
			}
			key := fn.Source + "\x00" + fn.QualifiedName + "\x00" + fn.Signature
			if seen[key] {
				continue
			}
			seen[key] = true
			selections = append(selections, selection{name: fn.Name, fn: fn})
		}
	}

	nameCounter := map[string]int{}
	usedNames := map[string]bool{}
	for _, item := range selections {
		target := config.Target{Name: item.name, Symbol: item.name}
		if item.target != nil {
			target = *item.target
		}
		if item.fn != nil {
			target.Symbol = item.fn.Name
		}
		name := target.Name
		if name == "" {
			name = target.Symbol
		}
		if usedNames[name] {
			nameCounter[name]++
			name = fmt.Sprintf("%s_%d", name, nameCounter[name])
		}
		usedNames[name] = true
		target.Name = name

		var tp TargetPlan
		switch {
		case item.target == nil && item.fn == nil:
			tp = missingTargetPlan(cfg, target)
		case target.WrapperSource != "":
			tp = wrapperTargetPlan(cfg, analysis, target)
		case item.fn == nil:
			tp = missingTargetPlan(cfg, target)
		default:
			fact := irByFunction[item.fn.ID]
			if fact == nil {
				fact = irBySymbol[item.fn.MangledName]
			}
			tp = functionTargetPlan(cfg, analysis, target, item.fn, fact, irFlagsByFunction, adapterCache, adapterErrors)
		}
		plan.Targets = append(plan.Targets, tp)
	}
	if len(plan.Targets) == 0 {
		plan.Diagnostics = append(plan.Diagnostics, diag.New(diag.EConfigInvalid,
			"no targets selected; configure [[targets]] or pass --target",
		))
	}
	if err := plan.Finalize(); err != nil {
		return nil, err
	}
	return plan, nil
}

func functionTargetPlan(
	cfg *config.Config,
	analysis *analyzer.Analysis,
	target config.Target,
	fn *analyzer.Function,
	fact *analyzer.IRFunctionFact,
	irFlagsByFunction map[string][]string,
	adapterCache map[string]AdapterBinding,
	adapterErrors map[string]diag.Diagnostic,
) TargetPlan {
	maxInput := cfg.EffectiveMaxInputBytes(target)
	tp := TargetPlan{
		Name:           target.Name,
		Symbol:         fn.Name,
		FunctionID:     fn.ID,
		QualifiedName:  fn.QualifiedName,
		Signature:      fn.Signature,
		MangledName:    fn.MangledName,
		Source:         fn.Source,
		Header:         fn.Header,
		Language:       fn.Language,
		VariantID:      fn.VariantID,
		Required:       target.Required,
		Status:         "planned",
		Classification: ReadyCandidate,
		MaxInputBytes:  maxInput,
		Function:       fn,
		InputModel:     InputModel{Kind: "bytes_length", BufferArg: -1, LengthArg: -1, CapacityArg: -1},
		Context: ContextPlan{
			Setup:       nonEmpty(target.Setup),
			Teardown:    nonEmpty(target.Teardown),
			ResetPolicy: "isolated",
			Provenance:  []string{"project_config"},
		},
		Analysis: AnalysisEvidence{
			AST:        "resolved",
			IR:         "unavailable",
			Provenance: []string{"ast", "project_build"},
		},
	}
	if target.Header != "" {
		tp.Header = fsutil.Rel(cfg.Root, target.Header)
	}
	tp.Seeds = expandSeeds(cfg.Root, target.Seeds)
	tp.Dictionary = BuildDictionary(fn, fact)
	if target.Context != nil {
		contextObject, contextDiags := buildContextPlan(analysis, target)
		tp.Diagnostics = append(tp.Diagnostics, contextDiags...)
		if contextObject == nil {
			tp.Classification = Blocked
			tp.Reasons = append(tp.Reasons, "C context lifecycle could not be validated")
		} else {
			tp.ContextObject = contextObject
			tp.Context.Provenance = append(tp.Context.Provenance, "explicit_context")
			tp.Reasons = append(tp.Reasons, "C context allocated and initialized by explicit lifecycle")
		}
	}
	for _, event := range target.Events {
		tp.Events = append(tp.Events, EventHook{Symbol: event.Symbol, Phase: event.Phase})
		if !hasVoidFunction(analysis, event.Symbol) {
			tp.Classification = Blocked
			tp.Reasons = append(tp.Reasons, "event hook lacks a visible void(void) declaration: "+event.Symbol)
			tp.Diagnostics = append(tp.Diagnostics, diag.Newf(diag.EContextInvalid,
				"event hook %s must have a visible void(void) declaration", event.Symbol,
			).WithTarget(target.Name))
		}
	}
	if target.StateProbe != "" {
		if diagnostic := validateStateProbe(analysis, target); diagnostic != nil {
			tp.Classification = Blocked
			tp.Diagnostics = append(tp.Diagnostics, *diagnostic)
			tp.Reasons = append(tp.Reasons, "state_probe signature is invalid")
		} else {
			tp.Context.Provenance = append(tp.Context.Provenance, "state_probe")
		}
	}
	if target.FrameReset != "" {
		if diagnostic := validateFrameReset(analysis, target); diagnostic != nil {
			tp.Classification = Blocked
			tp.Diagnostics = append(tp.Diagnostics, *diagnostic)
			tp.Reasons = append(tp.Reasons, "frame_reset signature is invalid")
		} else {
			tp.Context.Provenance = append(tp.Context.Provenance, "frame_reset")
		}
	}
	if target.InvariantCheck != "" {
		diagnostic, arity := validateInvariantCheck(analysis, target, fn)
		if diagnostic != nil {
			tp.Classification = Blocked
			tp.Diagnostics = append(tp.Diagnostics, *diagnostic)
			tp.Reasons = append(tp.Reasons, "invariant_check signature is invalid")
		} else {
			tp.InvariantCheck = target.InvariantCheck
			tp.InvariantArgs = arity
			tp.Context.Provenance = append(tp.Context.Provenance, "invariant_check")
		}
	}
	tp.Platform.HostTriple, tp.Platform.TargetTriple = variantTriples(analysis, fn.VariantID)
	if fact != nil {
		var merged bool
		fact, merged = mergeInterproceduralFact(analysis, fn, fact)
		if merged {
			tp.Analysis.Provenance = append(tp.Analysis.Provenance, "interprocedural_ir")
			tp.Reasons = append(tp.Reasons, "IR argument uses propagated through local callees")
		}
		tp.Analysis.IR = "observed"
		tp.Analysis.Provenance = append(tp.Analysis.Provenance, "llvm_ir")
		tp.Analysis.IRDataDependent = fact.DataDependent
		tp.Analysis.IRAliasFacts = append(tp.Analysis.IRAliasFacts, fact.AliasFacts...)
		tp.Analysis.IRMemorySSAAccesses = fact.MemorySSAAccesses
		tp.Analysis.Unknowns = append(tp.Analysis.Unknowns, fact.Unknowns...)
		copy := *fn
		copy.HardwareFlags = uniqueSorted(append(append([]string{}, copy.HardwareFlags...), fact.HardwareFlags...))
		for _, effect := range fact.GlobalEffects {
			if strings.HasPrefix(effect, "write:") {
				copy.GlobalWrites = uniqueSorted(append(copy.GlobalWrites, strings.TrimPrefix(effect, "write:")))
			}
		}
		fn = &copy
		tp.Function = fn
	}
	tp.DirectCallees = append(tp.DirectCallees, fn.DirectCallees...)

	if target.Input == "existing_harness" {
		tp.Classification = Blocked
		tp.Reasons = append(tp.Reasons, "existing_harness reuse is not implemented in P0")
		tp.Diagnostics = append(tp.Diagnostics, diag.New(diag.EHarnessSource,
			"existing harness reuse requires an explicit wrapper_source in P0",
		).WithTarget(target.Name))
		return tp
	}

	roles := inferRoles(fn, fact, target, maxInput)
	tp.CommandConstants = BuildCommandConstants(fn, fact, roles.input.LengthArg, roles.input.CapacityArg)
	tp.InputModel = roles.input
	if target.Input != "" {
		tp.InputModel.Kind = target.Input
	}
	tp.OutputBytes = target.OutputBytes
	tp.MaxFrames = target.MaxFrames
	tp.StateProbe = target.StateProbe
	tp.FrameReset = target.FrameReset
	tp.Roles = roles.roles
	tp.Constraints = roles.constraints
	tp.Reasons = append(tp.Reasons, roles.reasons...)
	tp.Diagnostics = append(tp.Diagnostics, roles.diagnostics...)
	if roles.blocked {
		tp.Classification = Blocked
	} else if roles.ambiguous {
		tp.Classification = Adaptable
	}
	if target.Context != nil {
		hasContextRole := false
		for _, role := range roles.roles {
			if role.Role == RoleContext {
				hasContextRole = true
			}
		}
		if !hasContextRole {
			tp.Classification = Blocked
			tp.Reasons = append(tp.Reasons, "targets.context is configured but no CONTEXT role was bound")
			tp.Diagnostics = append(tp.Diagnostics, diag.New(diag.EContextInvalid,
				"targets.context requires a distinct context pointer argument").WithTarget(target.Name))
		}
	}

	if fn.Name == "main" {
		tp.Classification = Blocked
		tp.Reasons = append(tp.Reasons, "main() is a process entry point, not an input boundary")
	}
	if fn.Variadic {
		tp.Classification = Blocked
		tp.Reasons = append(tp.Reasons, "variadic functions are not supported in P0")
	}
	if fn.IsMethod {
		if fn.IsStaticMethod && target.Factory != "" {
			tp.Classification = Blocked
			tp.Reasons = append(tp.Reasons, "static method does not require an object factory")
			tp.Diagnostics = append(tp.Diagnostics, diag.New(diag.EContextInvalid,
				"targets.factory must not be set for a static member function").WithTarget(target.Name))
		} else if fn.IsStaticMethod && target.Factory == "" {
			tp.IsStaticMethod = true
			tp.Reasons = append(tp.Reasons, "static C++ method has no object lifetime; called directly")
			tp.Context.Provenance = append(tp.Context.Provenance, "static_method")
		} else {
			factory, factoryDiags := resolveFactory(analysis, fn, target)
			tp.Diagnostics = append(tp.Diagnostics, factoryDiags...)
			if factory == nil {
				tp.Classification = Blocked
				tp.Reasons = append(tp.Reasons, "C++ method requires a validated factory/RAII path")
			} else {
				tp.Factory = factory
				tp.Context.Provenance = append(tp.Context.Provenance, "explicit_factory")
				tp.Reasons = append(tp.Reasons, "C++ object constructed by "+factoryDescription(factory))
			}
		}
	} else if target.Factory != "" {
		tp.Classification = Blocked
		tp.Reasons = append(tp.Reasons, "targets.factory is only valid for a C++ member function")
		tp.Diagnostics = append(tp.Diagnostics, diag.New(diag.EContextInvalid,
			"targets.factory requires a C++ member function target").WithTarget(target.Name))
	}
	if fn.InternalLinkage && !isHeader(fn.Source) {
		tp.Classification = Blocked
		tp.Reasons = append(tp.Reasons, "static/internal function in a non-header translation unit cannot be linked directly")
		tp.Diagnostics = append(tp.Diagnostics, diag.New(diag.ELinkGraphUnknown,
			"internal-linkage function cannot be called from a separate harness TU without modifying source or build",
		).WithTarget(target.Name))
	}
	if tp.Header == "" {
		tp.Classification = Blocked
		tp.Reasons = append(tp.Reasons, "no unique project header declares the target; configure targets.header")
		tp.Diagnostics = append(tp.Diagnostics, diag.New(diag.EContextUnknown,
			"no header declaration was found for the target; automatic prototype redeclaration is refused",
		).WithTarget(target.Name))
	}
	for _, symbol := range []string{target.Setup, target.Teardown} {
		if symbol == "" {
			continue
		}
		if !hasVoidFunction(analysis, symbol) {
			tp.Classification = Blocked
			tp.Reasons = append(tp.Reasons, "setup/teardown symbol lacks a visible void(void) declaration: "+symbol)
			tp.Diagnostics = append(tp.Diagnostics, diag.Newf(diag.EContextInvalid,
				"setup/teardown symbol %s must have a visible void(void) declaration", symbol,
			).WithTarget(target.Name))
		}
	}

	deps := resolveDependencies(cfg, analysis, fn, irFlagsByFunction, adapterCache, adapterErrors, len(tp.Events))
	tp.Dependencies = deps.translationUnits
	tp.Adapters = deps.adapters
	tp.Diagnostics = append(tp.Diagnostics, deps.diagnostics...)
	tp.Reasons = append(tp.Reasons, deps.reasons...)
	if deps.blocked {
		tp.Classification = Blocked
	} else if deps.adaptable && tp.Classification == ReadyCandidate {
		tp.Classification = Adaptable
	}

	if len(fn.GlobalWrites) > 0 || contains(fn.HardwareFlags, "INIT_REQUIRED") {
		if len(tp.Context.Setup) == 0 {
			tp.Classification = Adaptable
			tp.Reasons = append(tp.Reasons, "global state is written; verified setup/reset is required for persistent execution")
			tp.Context.Unknowns = append(tp.Context.Unknowns, "global initialization/reset order is not proven")
			tp.Diagnostics = append(tp.Diagnostics, diag.New(diag.EContextUnknown,
				"target writes global state without an explicit setup path",
			).WithTarget(target.Name))
		} else {
			tp.Context.Provenance = append(tp.Context.Provenance, "explicit_setup")
		}
	}
	if containsAny(fn.HardwareFlags, "INDIRECT_UNKNOWN") {
		if tp.Classification == ReadyCandidate {
			tp.Classification = Adaptable
		}
		tp.Reasons = append(tp.Reasons, "indirect call targets are unresolved; wrapper may be required")
	}
	if containsAny(fn.HardwareFlags, "ABI_LAYOUT") {
		if tp.Classification == ReadyCandidate {
			tp.Classification = Adaptable
		}
		tp.Platform.ABIGuards = append(tp.Platform.ABIGuards, "packed_or_bitfield_layout_review")
		tp.Reasons = append(tp.Reasons, "packed/bitfield layout is used; target ABI must be reviewed")
	}

	applyABIGuards(&tp)
	if tp.Classification != Blocked {
		tp.Reasons = append(tp.Reasons, "static plan accepted; build, reachability, input-use, and stability gates still apply")
	}
	tp.Reasons = uniqueSorted(tp.Reasons)
	return tp
}

func wrapperTargetPlan(cfg *config.Config, analysis *analyzer.Analysis, target config.Target) TargetPlan {
	projectSource := ""
	if target.Source != "" {
		projectSource = fsutil.Rel(cfg.Root, target.Source)
	}
	tp := TargetPlan{
		Name:           target.Name,
		Symbol:         target.WrapperSymbol,
		Source:         projectSource,
		Required:       target.Required,
		Status:         "planned",
		Classification: ReadyCandidate,
		MaxInputBytes:  cfg.EffectiveMaxInputBytes(target),
		InputModel:     InputModel{Kind: "manual_wrapper", BufferArg: 0, LengthArg: 1, CapacityArg: -1},
		Context: ContextPlan{
			ResetPolicy: "isolated",
			Provenance:  []string{"user_wrapper"},
		},
		Platform: PlatformPlan{},
		Analysis: AnalysisEvidence{
			AST:        "user_wrapper",
			IR:         "not_applicable",
			Provenance: []string{"explicit_config"},
		},
		Wrapper: &WrapperPlan{Symbol: target.WrapperSymbol, Source: fsutil.Rel(cfg.Root, target.WrapperSource)},
		Reasons: []string{"explicit user wrapper preserves original code; build and self-test gates still apply"},
	}
	tp.Seeds = expandSeeds(cfg.Root, target.Seeds)
	for _, event := range target.Events {
		tp.Events = append(tp.Events, EventHook{Symbol: event.Symbol, Phase: event.Phase})
		if !hasVoidFunction(analysis, event.Symbol) {
			tp.Classification = Blocked
			tp.Reasons = append(tp.Reasons, "event hook lacks a visible void(void) declaration: "+event.Symbol)
			tp.Diagnostics = append(tp.Diagnostics, diag.Newf(diag.EContextInvalid,
				"event hook %s must have a visible void(void) declaration", event.Symbol,
			).WithTarget(target.Name))
		}
	}
	if target.StateProbe != "" {
		if diagnostic := validateStateProbe(analysis, target); diagnostic != nil {
			tp.Classification = Blocked
			tp.Diagnostics = append(tp.Diagnostics, *diagnostic)
			tp.Reasons = append(tp.Reasons, "state_probe signature is invalid")
		} else {
			tp.Context.Provenance = append(tp.Context.Provenance, "state_probe")
		}
	}
	if target.FrameReset != "" {
		if diagnostic := validateFrameReset(analysis, target); diagnostic != nil {
			tp.Classification = Blocked
			tp.Diagnostics = append(tp.Diagnostics, *diagnostic)
			tp.Reasons = append(tp.Reasons, "frame_reset signature is invalid")
		} else {
			tp.Context.Provenance = append(tp.Context.Provenance, "frame_reset")
		}
	}
	tp.Constraints = []Constraint{{
		Expr: fmt.Sprintf("size <= %d", tp.MaxInputBytes), Basis: "configured_engine_limit",
		Evidence: []string{"harness.max_input_bytes"},
	}}
	if target.Header != "" {
		tp.Header = fsutil.Rel(cfg.Root, target.Header)
	}
	if len(target.Seeds) == 0 {
		tp.Context.Unknowns = append(tp.Context.Unknowns, "no seed corpus configured")
	}
	if analysis != nil {
		tp.Platform.HostTriple = firstVariantHost(analysis)
	}
	return tp
}

func missingTargetPlan(cfg *config.Config, target config.Target) TargetPlan {
	tp := TargetPlan{
		Name:           target.Name,
		Symbol:         target.Symbol,
		Required:       target.Required,
		Status:         "planned",
		Classification: Blocked,
		MaxInputBytes:  cfg.EffectiveMaxInputBytes(target),
		InputModel:     InputModel{Kind: "bytes_length", BufferArg: -1, LengthArg: -1, CapacityArg: -1},
		Context:        ContextPlan{ResetPolicy: "isolated"},
		Analysis:       AnalysisEvidence{AST: "missing", IR: "missing"},
		Reasons:        []string{"configured target symbol was not found in analysis"},
		Diagnostics: []diag.Diagnostic{diag.New(diag.ETargetNotFound,
			fmt.Sprintf("target %s (%s) was not found in analyzed translation units", target.Name, target.Symbol),
		).WithTarget(target.Name)},
	}
	return tp
}

func matchFunction(analysis *analyzer.Analysis, target config.Target) *analyzer.Function {
	matches := findFunctions(analysis, target.Symbol, target.Source, target.BuildVariant)
	if len(matches) == 0 {
		return nil
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Source != matches[j].Source {
			return matches[i].Source < matches[j].Source
		}
		return matches[i].VariantID < matches[j].VariantID
	})
	return matches[0]
}

func findFunctions(analysis *analyzer.Analysis, symbol, source, variant string) []*analyzer.Function {
	sourceRel := ""
	var out []*analyzer.Function
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if !fn.Definition {
			continue
		}
		if fn.Name != symbol && fn.QualifiedName != symbol && fn.MangledName != symbol {
			continue
		}
		if source != "" {
			sourceRel = fsutil.Rel(analysis.Project.Root, source)
			if fn.Source != sourceRel && fn.Header != sourceRel && fn.TranslationUnit != sourceRel {
				continue
			}
		}
		if variant != "" && fn.VariantID != variant {
			continue
		}
		out = append(out, fn)
	}
	return out
}

type dependencyResult struct {
	translationUnits []string
	adapters         []AdapterBinding
	unresolved       []string
	reasons          []string
	diagnostics      []diag.Diagnostic
	blocked          bool
	adaptable        bool
}

func resolveDependencies(
	cfg *config.Config,
	analysis *analyzer.Analysis,
	rootFn *analyzer.Function,
	irFlagsByFunction map[string][]string,
	adapterCache map[string]AdapterBinding,
	adapterErrors map[string]diag.Diagnostic,
	eventCount int,
) dependencyResult {
	result := dependencyResult{}
	byTU := map[string]map[string][]*analyzer.Function{}
	bySymbol := map[string][]*analyzer.Function{}
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if !fn.Definition {
			continue
		}
		if byTU[fn.TranslationUnit] == nil {
			byTU[fn.TranslationUnit] = map[string][]*analyzer.Function{}
		}
		symbol := firstNonEmpty(fn.MangledName, fn.Name)
		byTU[fn.TranslationUnit][symbol] = append(byTU[fn.TranslationUnit][symbol], fn)
		bySymbol[symbol] = append(bySymbol[symbol], fn)
		bySymbol[fn.Name] = append(bySymbol[fn.Name], fn)
	}
	tus := map[string]bool{rootFn.TranslationUnit: true}
	visited := map[string]bool{rootFn.ID: true}
	queue := []*analyzer.Function{rootFn}
	adapterSeen := map[string]bool{}
	flags := map[string]bool{}
	unresolved := map[string]bool{}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		for _, flag := range fn.HardwareFlags {
			flags[flag] = true
		}
		for _, flag := range irFlagsByFunction[fn.ID] {
			flags[flag] = true
		}
		if len(fn.GlobalWrites) > 0 {
			flags["INIT_REQUIRED"] = true
		}
		for _, call := range fn.DirectCallees {
			symbol := firstNonEmpty(call.Symbol, call.Name)
			if analyzer.AllowedExternalCall(symbol) || analyzer.AllowedExternalCall(call.Name) {
				continue
			}
			var resolved []*analyzer.Function
			if candidates := byTU[fn.TranslationUnit][symbol]; len(candidates) > 0 {
				resolved = candidates
			} else {
				for _, candidate := range bySymbol[symbol] {
					if !candidate.InternalLinkage {
						resolved = append(resolved, candidate)
					}
				}
			}
			if len(resolved) == 0 {
				for _, candidate := range bySymbol[call.Name] {
					if !candidate.InternalLinkage {
						resolved = append(resolved, candidate)
					}
				}
			}
			if len(resolved) > 0 {
				for _, candidate := range resolved {
					tus[candidate.TranslationUnit] = true
					if !visited[candidate.ID] {
						visited[candidate.ID] = true
						queue = append(queue, candidate)
					}
				}
				continue
			}
			adapterConfig, hasAdapter := cfg.Adapter(symbol)
			if !hasAdapter {
				adapterConfig, hasAdapter = cfg.Adapter(call.Name)
			}
			if hasAdapter {
				if !adapterSeen[adapterConfig.OriginalSymbol] {
					adapterSeen[adapterConfig.OriginalSymbol] = true
					if binding, ok := adapterCache[adapterConfig.OriginalSymbol]; ok {
						result.adapters = append(result.adapters, binding)
					} else if errDiag, exists := adapterErrors[adapterConfig.OriginalSymbol]; exists {
						result.diagnostics = append(result.diagnostics, errDiag)
						result.blocked = true
					} else if binding, errDiag := loadAdapterBinding(cfg, adapterConfig, analysis); errDiag != nil {
						errDiag.Target = rootFn.Name
						adapterErrors[adapterConfig.OriginalSymbol] = *errDiag
						result.diagnostics = append(result.diagnostics, *errDiag)
						result.blocked = true
					} else {
						adapterCache[adapterConfig.OriginalSymbol] = binding
						result.adapters = append(result.adapters, binding)
					}
				}
				continue
			}
			unresolved[symbol] = true
		}
	}
	unresolvedNames := make([]string, 0, len(unresolved))
	for symbol := range unresolved {
		unresolvedNames = append(unresolvedNames, symbol)
	}
	sort.Strings(unresolvedNames)
	for _, symbol := range unresolvedNames {
		result.unresolved = append(result.unresolved, symbol)
		result.reasons = append(result.reasons, "unresolved external symbol: "+symbol)
		if looksLikeHardwareCall(symbol) {
			result.blocked = true
			result.diagnostics = append(result.diagnostics, diag.Newf(diag.EHALUnmodeled,
				"hardware/external symbol %s has no approved adapter", symbol,
			).WithTarget(rootFn.Name).WithRemediation("Add an [[adapters]] entry with a validated contract."))
		} else {
			result.adaptable = true
			result.diagnostics = append(result.diagnostics, diag.Newf(diag.ELinkGraphUnknown,
				"external symbol %s is not defined in analyzed translation units and is not an approved libc call", symbol,
			).WithTarget(rootFn.Name))
		}
	}
	blocked, reasons, diagnostics := evaluateHardwareBoundaries(flags, result.adapters, eventCount)
	result.blocked = result.blocked || blocked
	result.reasons = append(result.reasons, reasons...)
	result.diagnostics = append(result.diagnostics, diagnostics...)
	if flags["INDIRECT_UNKNOWN"] {
		result.adaptable = true
		result.reasons = append(result.reasons, "indirect call target cannot be resolved statically")
	}
	if flags["ABI_LAYOUT"] {
		result.adaptable = true
		result.reasons = append(result.reasons, "target dependency path uses ABI-layout-sensitive types")
	}
	result.translationUnits = sortedStringSet(tus)
	result.reasons = uniqueSorted(result.reasons)
	return result
}

func applyABIGuards(tp *TargetPlan) {
	if tp.Platform.TargetTriple == "" {
		tp.Platform.ABIGuards = append(tp.Platform.ABIGuards, "target_triple_unknown")
		tp.Analysis.Unknowns = append(tp.Analysis.Unknowns, "target triple was not recorded")
		return
	}
	if tp.Platform.HostTriple == "" {
		tp.Platform.ABIGuards = append(tp.Platform.ABIGuards, "host_triple_unknown")
		return
	}
	if !sameArchitecture(tp.Platform.TargetTriple, tp.Platform.HostTriple) {
		tp.Platform.ABIGuards = append(tp.Platform.ABIGuards, "pointer_width_and_endianness_review")
		tp.Diagnostics = append(tp.Diagnostics, diag.Newf(diag.WABIHostOnly,
			"target triple %s differs from host %s; host findings are HOST_ONLY",
			tp.Platform.TargetTriple, tp.Platform.HostTriple,
		).Warning().WithTarget(tp.Name))
		if contains(tp.Function.HardwareFlags, "ABI_LAYOUT") {
			tp.Classification = Blocked
			tp.Reasons = append(tp.Reasons, "ABI-layout-sensitive path cannot be preserved across target/host triples")
			tp.Diagnostics = append(tp.Diagnostics, diag.New(diag.EABIMismatch,
				"packed/bitfield layout is critical and cannot be preserved on the host",
			).WithTarget(tp.Name))
		}
	} else {
		tp.Platform.ABIGuards = append(tp.Platform.ABIGuards, "pointer_width_reviewed")
	}
}

func variantTriples(analysis *analyzer.Analysis, variantID string) (host, target string) {
	for _, variant := range analysis.Variants {
		if variant.ID == variantID {
			return variant.HostTriple, variant.TargetTriple
		}
	}
	return "", ""
}

func sameArchitecture(target, host string) bool {
	target = strings.ToLower(target)
	host = strings.ToLower(host)
	arches := []string{"x86_64", "amd64", "aarch64", "arm64", "arm", "riscv64", "riscv32", "i386", "i686"}
	for _, arch := range arches {
		if strings.Contains(target, arch) && strings.Contains(host, arch) {
			return true
		}
	}
	return target == host
}

func expandSeeds(root string, seeds []string) []string {
	var out []string
	for _, seed := range seeds {
		info, err := os.Stat(seed)
		if err != nil {
			continue
		}
		if info.IsDir() {
			entries, err := os.ReadDir(seed)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				out = append(out, fsutil.Rel(root, filepath.Join(seed, entry.Name())))
			}
			continue
		}
		out = append(out, fsutil.Rel(root, seed))
	}
	sort.Strings(out)
	return out
}

func looksLikeHardwareCall(name string) bool {
	upper := strings.ToUpper(name)
	lower := strings.ToLower(name)
	return strings.HasPrefix(name, "HAL_") || strings.HasPrefix(name, "LL_") ||
		strings.HasPrefix(name, "DMA_") || strings.HasPrefix(lower, "dma_") ||
		strings.Contains(upper, "IRQ") || strings.Contains(upper, "ISR") ||
		strings.HasSuffix(upper, "_HANDLER") || strings.HasPrefix(name, "NVIC_") ||
		strings.HasPrefix(name, "xTask") || strings.HasPrefix(name, "vTask") ||
		strings.HasPrefix(name, "osThread") || strings.HasPrefix(name, "pthread_")
}

func isHeader(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".h", ".hh", ".hpp", ".hxx", ".h++", ".inc":
		return true
	default:
		return false
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsAny(values []string, wants ...string) bool {
	for _, want := range wants {
		if contains(values, want) {
			return true
		}
	}
	return false
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
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func nonEmpty(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func firstVariantHost(analysis *analyzer.Analysis) string {
	if len(analysis.Variants) > 0 {
		return analysis.Variants[0].HostTriple
	}
	return ""
}

func sortedStringSet(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func hasVoidFunction(analysis *analyzer.Analysis, name string) bool {
	valid := func(signature string) bool {
		compact := strings.ReplaceAll(signature, " ", "")
		return compact == "void(void)" || compact == "void()"
	}
	for _, declaration := range analysis.ExternalDeclarations {
		if declaration.Name == name && valid(declaration.Signature) {
			return true
		}
	}
	for _, function := range analysis.Functions {
		if function.Name == name && valid(function.Signature) {
			return true
		}
	}
	return false
}

func adapterByEventModel(adapters []AdapterBinding, model string) (AdapterBinding, bool) {
	for _, adapter := range adapters {
		if adapter.EventModel == model {
			return adapter, true
		}
	}
	return AdapterBinding{}, false
}

func evaluateHardwareBoundaries(flags map[string]bool, adapters []AdapterBinding, eventCount int) (bool, []string, []diag.Diagnostic) {
	blocked := false
	var reasons []string
	var diagnostics []diag.Diagnostic
	if flags["MMIO_DIRECT"] || flags["ARCH_ASM"] {
		blocked = true
		for _, flag := range []string{"MMIO_DIRECT", "ARCH_ASM"} {
			if flags[flag] {
				reasons = append(reasons, "hardware dependency: "+flag)
			}
		}
		diagnostics = append(diagnostics, diag.New(diag.EHALUnmodeled,
			"target dependency path crosses a direct MMIO/inline-assembly boundary",
		))
	}
	if flags["DMA_ASYNC"] {
		dmaAdapter, ok := adapterByEventModel(adapters, "dma_completion")
		switch {
		case !ok:
			blocked = true
			reasons = append(reasons, "DMA path has no adapter with event_model=dma_completion")
			diagnostics = append(diagnostics, diag.New(diag.EDMAUnmodeled,
				"DMA transfer is not modeled by an approved adapter contract"))
		case dmaAdapter.Completion == "deferred" && eventCount == 0:
			blocked = true
			diagnostics = append(diagnostics, diag.New(diag.EDMAUnmodeled,
				"deferred DMA completion requires at least one explicit event hook"))
		default:
			reasons = append(reasons, "DMA boundary modeled by "+dmaAdapter.OriginalSymbol)
		}
	}
	if flags["ISR_ENTRY"] {
		_, isrAdapter := adapterByEventModel(adapters, "isr_callback")
		if !isrAdapter && eventCount == 0 {
			blocked = true
			reasons = append(reasons, "ISR path has no adapter event model or explicit event hook")
			diagnostics = append(diagnostics, diag.New(diag.EHALUnmodeled,
				"ISR callback path requires an approved event adapter or explicit event hook"))
		} else {
			reasons = append(reasons, "ISR boundary has an explicit event model")
		}
	}
	if flags["RTOS_CONTEXT"] {
		_, rtosAdapter := adapterByEventModel(adapters, "rtos_event")
		if !rtosAdapter || eventCount == 0 {
			blocked = true
			reasons = append(reasons, "RTOS path requires an rtos_event adapter and explicit event hooks")
			diagnostics = append(diagnostics, diag.New(diag.EContextUnknown,
				"RTOS/scheduler dependency requires an approved host event model and event hooks"))
		} else {
			reasons = append(reasons, "RTOS boundary has an explicit event model")
		}
	}
	return blocked, reasons, diagnostics
}
