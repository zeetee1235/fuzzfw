// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package planner

import (
	"github.com/fuzzfw/fuzzfw/internal/analyzer"
)

// mergeInterproceduralFact propagates conservative argument-use facts from
// locally defined callees to their caller. It uses AST call argument positions;
// expressions that are not direct parameter references remain unknown rather
// than being guessed.
func mergeInterproceduralFact(analysis *analyzer.Analysis, root *analyzer.Function, rootFact *analyzer.IRFunctionFact) (*analyzer.IRFunctionFact, bool) {
	if rootFact == nil || len(root.DirectCallees) == 0 {
		return rootFact, false
	}
	byID := map[string]*analyzer.Function{}
	bySymbol := map[string]*analyzer.Function{}
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		byID[fn.ID] = fn
		bySymbol[fn.MangledName] = fn
		bySymbol[fn.Name] = fn
		bySymbol[fn.QualifiedName] = fn
	}
	facts := map[string]*analyzer.IRFunctionFact{}
	for i := range analysis.IRFacts {
		fact := &analysis.IRFacts[i]
		if fact.FunctionID != "" {
			facts[fact.FunctionID] = fact
		}
		facts[fact.LinkSymbol] = fact
	}
	merged := cloneIRFact(rootFact)
	type frame struct {
		fn      *analyzer.Function
		mapping []int
	}
	identity := make([]int, len(root.Params))
	for i := range identity {
		identity[i] = i
	}
	queue := []frame{{fn: root, mapping: identity}}
	visited := map[string]bool{root.ID: true}
	changed := false
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, call := range current.fn.DirectCallees {
			callee := lookupFunction(bySymbol, call)
			if callee == nil || callee.ID == current.fn.ID {
				continue
			}
			calleeFact := facts[callee.ID]
			if calleeFact == nil {
				calleeFact = facts[callee.MangledName]
			}
			if calleeFact == nil {
				continue
			}
			for _, argument := range calleeFact.Arguments {
				if argument.Index < 0 || argument.Index >= len(call.Arguments) {
					continue
				}
				calleeParam := call.Arguments[argument.Index]
				if calleeParam < 0 || calleeParam >= len(current.mapping) {
					continue
				}
				rootParam := current.mapping[calleeParam]
				if rootParam < 0 || rootParam >= len(root.Params) {
					continue
				}
				if mergeArgumentUses(merged, rootParam, argument.ObservedUse) {
					changed = true
				}
				merged.DataDependent = merged.DataDependent || calleeFact.DataDependent
			}
			nextMapping := make([]int, len(callee.Params))
			for i := range nextMapping {
				nextMapping[i] = -1
				if i < len(call.Arguments) && call.Arguments[i] >= 0 && call.Arguments[i] < len(current.mapping) {
					nextMapping[i] = current.mapping[call.Arguments[i]]
				}
			}
			if !visited[callee.ID] {
				visited[callee.ID] = true
				queue = append(queue, frame{fn: callee, mapping: nextMapping})
			}
		}
	}
	if changed {
		merged.Evidence = append(merged.Evidence, analyzer.Evidence{
			Kind: "ir_interprocedural", Symbol: root.QualifiedName,
			Detail: "conservative callee argument-use propagation", Confidence: "observed",
		})
	}
	return merged, changed
}

func lookupFunction(bySymbol map[string]*analyzer.Function, call analyzer.CallRef) *analyzer.Function {
	for _, key := range []string{call.Symbol, call.Name} {
		if key != "" {
			if fn := bySymbol[key]; fn != nil {
				return fn
			}
		}
	}
	return nil
}

func cloneIRFact(fact *analyzer.IRFunctionFact) *analyzer.IRFunctionFact {
	if fact == nil {
		return nil
	}
	copyFact := *fact
	copyFact.Arguments = append([]analyzer.IRArgument(nil), fact.Arguments...)
	copyFact.GlobalEffects = append([]string(nil), fact.GlobalEffects...)
	copyFact.HardwareFlags = append([]string(nil), fact.HardwareFlags...)
	copyFact.Unknowns = append([]string(nil), fact.Unknowns...)
	copyFact.AliasFacts = append([]string(nil), fact.AliasFacts...)
	copyFact.Evidence = append([]analyzer.Evidence(nil), fact.Evidence...)
	return &copyFact
}

func mergeArgumentUses(fact *analyzer.IRFunctionFact, index int, uses []string) bool {
	for i := range fact.Arguments {
		if fact.Arguments[i].Index == index {
			before := len(fact.Arguments[i].ObservedUse)
			for _, use := range uses {
				found := false
				for _, existing := range fact.Arguments[i].ObservedUse {
					if existing == use {
						found = true
						break
					}
				}
				if !found {
					fact.Arguments[i].ObservedUse = append(fact.Arguments[i].ObservedUse, use)
				}
			}
			return len(fact.Arguments[i].ObservedUse) != before
		}
	}
	fact.Arguments = append(fact.Arguments, analyzer.IRArgument{Index: index, ObservedUse: append([]string(nil), uses...)})
	return len(uses) > 0
}
