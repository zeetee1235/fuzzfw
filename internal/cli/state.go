// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package cli

import (
	"fmt"
	"os"

	"github.com/fuzzfw/fuzzfw/internal/artifacts"
	"github.com/fuzzfw/fuzzfw/internal/fsutil"
	"github.com/fuzzfw/fuzzfw/internal/hostbuild"
	"github.com/fuzzfw/fuzzfw/internal/planner"
)

const buildStateSchemaVersion = 1
const lockSchemaVersion = 1

type targetBuild struct {
	Name   string           `json:"name"`
	Result hostbuild.Result `json:"result"`
}

type buildState struct {
	SchemaVersion       int           `json:"schema_version"`
	CreatedAt           string        `json:"created_at"`
	BuildManifestSHA256 string        `json:"build_manifest_sha256"`
	AnalysisSHA256      string        `json:"analysis_sha256"`
	ConfigFingerprint   string        `json:"config_fingerprint,omitempty"`
	PlanID              string        `json:"plan_id"`
	ToolchainHash       string        `json:"toolchain_hash,omitempty"`
	Targets             []targetBuild `json:"targets"`
}

// BuildStatePath is the workspace build record.
func buildStatePath(ws *artifacts.Workspace) string {
	return ws.Root + "/build_info.json"
}

func saveBuildState(ws *artifacts.Workspace, state *buildState, plan *planner.Plan) error {
	if err := fsutil.WriteJSON(buildStatePath(ws), state, true); err != nil {
		return err
	}
	lock := lockFile{
		SchemaVersion:       lockSchemaVersion,
		CreatedAt:           state.CreatedAt,
		ConfigFingerprint:   state.ConfigFingerprint,
		AnalysisSHA256:      state.AnalysisSHA256,
		BuildManifestSHA256: state.BuildManifestSHA256,
		PlanID:              state.PlanID,
		ToolchainHash:       state.ToolchainHash,
	}
	for _, target := range state.Targets {
		functionID := ""
		if plan != nil {
			if planned, ok := plan.Target(target.Name); ok {
				functionID = planned.FunctionID
			}
		}
		lock.Targets = append(lock.Targets, lockTarget{
			Name:           target.Name,
			FunctionID:     functionID,
			HarnessID:      target.Result.HarnessID,
			Classification: target.Result.Classification,
			Status:         target.Result.Status,
			SelftestSHA256: target.Result.SelftestSHA256,
			FuzzSHA256:     target.Result.FuzzSHA256,
			SelftestBinary: target.Result.SelftestBinary,
			FuzzBinary:     target.Result.FuzzBinary,
			Adapters:       adapterList(target.Result.Adapters),
			Dependencies:   target.Result.Dependencies,
		})
	}
	return fsutil.WriteJSON(ws.Lock, lock, true)
}

type lockFile struct {
	SchemaVersion       int          `json:"schema_version"`
	CreatedAt           string       `json:"created_at"`
	ConfigFingerprint   string       `json:"config_fingerprint,omitempty"`
	AnalysisSHA256      string       `json:"analysis_sha256"`
	BuildManifestSHA256 string       `json:"build_manifest_sha256"`
	PlanID              string       `json:"plan_id"`
	ToolchainHash       string       `json:"toolchain_hash,omitempty"`
	Targets             []lockTarget `json:"targets"`
}

type lockTarget struct {
	Name           string   `json:"name"`
	FunctionID     string   `json:"function_id,omitempty"`
	HarnessID      string   `json:"harness_id,omitempty"`
	Classification string   `json:"classification,omitempty"`
	Status         string   `json:"status"`
	SelftestSHA256 string   `json:"selftest_sha256,omitempty"`
	FuzzSHA256     string   `json:"fuzz_sha256,omitempty"`
	SelftestBinary string   `json:"selftest_binary,omitempty"`
	FuzzBinary     string   `json:"fuzz_binary,omitempty"`
	Adapters       []string `json:"adapters,omitempty"`
	Dependencies   []string `json:"dependencies,omitempty"`
}

func loadBuildState(ws *artifacts.Workspace) (*buildState, error) {
	path := buildStatePath(ws)
	var state buildState
	if err := fsutil.ReadJSON(path, &state); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no build state at %s; run fuzzfw build first", path)
		}
		return nil, err
	}
	if state.SchemaVersion != buildStateSchemaVersion {
		return nil, fmt.Errorf("unsupported build state schema %d", state.SchemaVersion)
	}
	return &state, nil
}

func (s *buildState) target(name string) (targetBuild, bool) {
	for _, target := range s.Targets {
		if target.Name == name {
			return target, true
		}
	}
	return targetBuild{}, false
}

func adapterList(adapters []planner.AdapterBinding) []string {
	var out []string
	for _, adapter := range adapters {
		out = append(out, adapter.OriginalSymbol+"="+adapter.ReplacementSource)
	}
	return out
}
