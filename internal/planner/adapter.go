// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package planner

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/analyzer"
	"github.com/fuzzfw/fuzzfw/internal/config"
	"github.com/fuzzfw/fuzzfw/internal/diag"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
)

// ContractSchemaVersion is the adapter contract schema.
const ContractSchemaVersion = 1

// AdapterContract is the approved platform-boundary model.
type AdapterContract struct {
	SchemaVersion  int      `json:"schema_version"`
	OriginalSymbol string   `json:"original_symbol"`
	Prototype      string   `json:"prototype"`
	Model          string   `json:"model"`
	Effects        []string `json:"effects"`
	MaxWrite       string   `json:"max_write,omitempty"`
	ValidContext   string   `json:"valid_context"`
	Nondeterminism string   `json:"nondeterminism,omitempty"`
	EventModel     string   `json:"event_model,omitempty"`
	Completion     string   `json:"completion,omitempty"`
	Ownership      string   `json:"ownership,omitempty"`
	Limitations    []string `json:"limitations,omitempty"`
}

var validEffects = map[string]bool{
	"write_buffer": true, "read_buffer": true, "return_status": true,
	"set_state": true, "read_config": true, "wait": true, "none": true,
}

var validModels = map[string]bool{
	"input_source": true, "status_and_output": true, "status_only": true,
	"clock": true, "random": true, "io": true, "passthrough": true, "unknown": true,
}

var validNondeterminism = map[string]bool{
	"none": true, "time": true, "random": true, "io": true, "unknown": true,
}

var validEventModels = map[string]bool{
	"": true, "none": true, "uart_rx": true, "network_rx": true, "dma_completion": true,
	"isr_callback": true, "rtos_event": true,
}

func loadAdapterBinding(cfg *config.Config, adapterConfig config.Adapter, analysis *analyzer.Analysis) (AdapterBinding, *diag.Diagnostic) {
	data, err := os.ReadFile(adapterConfig.Contract)
	if err != nil {
		d := diag.Newf(diag.EAdapterInvalid, "cannot read adapter contract %s: %v", adapterConfig.Contract, err)
		return AdapterBinding{}, &d
	}
	var contract AdapterContract
	if err := json.Unmarshal(data, &contract); err != nil {
		d := diag.Newf(diag.EAdapterInvalid, "invalid JSON in adapter contract %s: %v", adapterConfig.Contract, err)
		return AdapterBinding{}, &d
	}
	if contract.SchemaVersion != ContractSchemaVersion {
		d := diag.Newf(diag.EAdapterInvalid,
			"adapter %s: unsupported contract schema_version %d", adapterConfig.OriginalSymbol, contract.SchemaVersion)
		return AdapterBinding{}, &d
	}
	if contract.OriginalSymbol != adapterConfig.OriginalSymbol {
		d := diag.Newf(diag.EAdapterInvalid,
			"adapter contract symbol %q does not match configuration symbol %q",
			contract.OriginalSymbol, adapterConfig.OriginalSymbol)
		return AdapterBinding{}, &d
	}
	if strings.TrimSpace(contract.Prototype) == "" {
		d := diag.Newf(diag.EAdapterInvalid, "adapter %s: prototype is required", contract.OriginalSymbol)
		return AdapterBinding{}, &d
	}
	if !validModels[contract.Model] {
		d := diag.Newf(diag.EAdapterInvalid,
			"adapter %s: model %q is not recognized", contract.OriginalSymbol, contract.Model)
		return AdapterBinding{}, &d
	}
	if len(contract.Effects) == 0 {
		d := diag.Newf(diag.EAdapterInvalid, "adapter %s: effects must not be empty", contract.OriginalSymbol)
		return AdapterBinding{}, &d
	}
	for _, effect := range contract.Effects {
		if !validEffects[effect] {
			d := diag.Newf(diag.EAdapterInvalid,
				"adapter %s: unknown effect %q", contract.OriginalSymbol, effect)
			return AdapterBinding{}, &d
		}
	}
	if strings.TrimSpace(contract.ValidContext) == "" {
		d := diag.Newf(diag.EAdapterInvalid, "adapter %s: valid_context is required", contract.OriginalSymbol)
		return AdapterBinding{}, &d
	}
	if contract.Nondeterminism != "" && !validNondeterminism[contract.Nondeterminism] {
		d := diag.Newf(diag.EAdapterInvalid,
			"adapter %s: unknown nondeterminism %q", contract.OriginalSymbol, contract.Nondeterminism)
		return AdapterBinding{}, &d
	}
	if len(contract.Limitations) == 0 {
		// This is a warning, not a failure: some adapters are exact models.
		// The report still records the empty list.
	}
	original := findDeclaration(analysis, adapterConfig.OriginalSymbol)
	if original != nil {
		if normalizePrototype(original.Signature) != normalizePrototype(contract.Prototype) {
			d := diag.Newf(diag.EAdapterInvalid,
				"adapter %s prototype mismatch: contract %q, declaration %q",
				adapterConfig.OriginalSymbol, contract.Prototype, original.Signature)
			d = d.WithEvidence("declaration:" + original.Source)
			return AdapterBinding{}, &d
		}
	}
	includeDirs := adapterIncludeDirs(analysis)
	definition, err := analyzer.CheckAdapterDefinition(context.Background(), cfg, adapterConfig.ReplacementSource, includeDirs, adapterDefines(analysis), adapterConfig.OriginalSymbol)
	if err != nil {
		d := diag.Newf(diag.EAdapterInvalid,
			"adapter %s definition check failed: %v", adapterConfig.OriginalSymbol, err)
		return AdapterBinding{}, &d
	}
	if normalizePrototype(definition.Signature) != normalizePrototype(contract.Prototype) {
		d := diag.Newf(diag.EAdapterInvalid,
			"adapter %s definition prototype mismatch: contract %q, definition %q",
			adapterConfig.OriginalSymbol, contract.Prototype, definition.Signature)
		return AdapterBinding{}, &d
	}
	claimsInput := contract.Model == "input_source" || containsEffect(contract.Effects, "write_buffer") || containsEffect(contract.Effects, "read_buffer")
	if definition.TrivialReturn && claimsInput {
		d := diag.Newf(diag.EAdapterTrivial,
			"adapter %s is a constant-return placeholder but claims an input_source/write_buffer model", adapterConfig.OriginalSymbol)
		return AdapterBinding{}, &d
	}
	hash, err := fsutil.HashFile(adapterConfig.Contract)
	if err != nil {
		d := diag.Newf(diag.EAdapterInvalid, "cannot hash adapter contract: %v", err)
		return AdapterBinding{}, &d
	}
	return AdapterBinding{
		OriginalSymbol:    adapterConfig.OriginalSymbol,
		ReplacementSource: fsutil.Rel(cfg.Root, adapterConfig.ReplacementSource),
		Contract:          fsutil.Rel(cfg.Root, adapterConfig.Contract),
		ContractSHA256:    hash,
		Prototype:         contract.Prototype,
		Model:             contract.Model,
		Effects:           append([]string(nil), contract.Effects...),
		EventModel:        contract.EventModel,
		Completion:        contract.Completion,
		Ownership:         contract.Ownership,
		Limitations:       append([]string(nil), contract.Limitations...),
	}, nil
}

func findDeclaration(analysis *analyzer.Analysis, symbol string) *analyzer.Declaration {
	for i := range analysis.ExternalDeclarations {
		if analysis.ExternalDeclarations[i].Name == symbol {
			return &analysis.ExternalDeclarations[i]
		}
	}
	for i := range analysis.Functions {
		if analysis.Functions[i].Name == symbol {
			return &analyzer.Declaration{
				Name:      analysis.Functions[i].Name,
				Signature: analysis.Functions[i].Signature,
				Source:    analysis.Functions[i].Source,
			}
		}
	}
	return nil
}

func normalizePrototype(value string) string {
	value = strings.ReplaceAll(value, "const ", "")
	value = strings.ReplaceAll(value, "volatile ", "")
	value = strings.ReplaceAll(value, "restrict ", "")
	value = strings.ReplaceAll(value, "std::", "")
	value = strings.ReplaceAll(value, " ", "")
	replacer := strings.NewReplacer(
		"uint8_t", "unsignedchar",
		"int8_t", "signedchar",
		"uint16_t", "unsignedshort",
		"int16_t", "short",
		"uint32_t", "unsignedint",
		"int32_t", "int",
		"uint64_t", "unsignedlong",
		"int64_t", "long",
		"size_t", "unsignedlong",
		"ssize_t", "long",
	)
	return replacer.Replace(value)
}

func adapterIncludeDirs(analysis *analyzer.Analysis) []string {
	seen := map[string]bool{}
	var dirs []string
	for _, variant := range analysis.Variants {
		for _, dir := range variant.IncludeDirs {
			if dir == "" || seen[dir] {
				continue
			}
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func containsEffect(effects []string, want string) bool {
	for _, effect := range effects {
		if effect == want {
			return true
		}
	}
	return false
}

func adapterDefines(analysis *analyzer.Analysis) []string {
	seen := map[string]bool{}
	var defines []string
	for _, variant := range analysis.Variants {
		for _, define := range variant.Defines {
			if define == "" || seen[define] {
				continue
			}
			seen[define] = true
			defines = append(defines, define)
		}
	}
	return defines
}
