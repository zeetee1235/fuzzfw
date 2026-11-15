// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var fuzzfwBinary string
var repoRoot string

func TestMain(m *testing.M) {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	repoRoot = filepath.Clean(filepath.Join(cwd, "..", ".."))
	dir, err := os.MkdirTemp("", "fuzzfw-integration-*")
	if err != nil {
		panic(err)
	}
	fuzzfwBinary = filepath.Join(dir, "fuzzfw")
	build := exec.Command("go", "build", "-o", fuzzfwBinary, "./cmd/fuzzfw")
	build.Dir = repoRoot
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func fixture(name string) string {
	return filepath.Join(repoRoot, "tests", "fixtures", name)
}

func pilot(name string) string {
	return filepath.Join(repoRoot, "tests", "pilots", name)
}

func ensureBuild(t *testing.T, project string) {
	t.Helper()
	if _, err := exec.LookPath("cmake"); err != nil {
		t.Skip("cmake not available")
	}
	buildDir := filepath.Join(project, "build")
	if _, err := os.Stat(filepath.Join(buildDir, "compile_commands.json")); err != nil {
		cmd := exec.Command("cmake", "-S", ".", "-B", "build", "-G", "Ninja", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON")
		cmd.Dir = project
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cmake configure: %v\n%s", err, output)
		}
	}
	cmd := exec.Command("cmake", "--build", "build")
	cmd.Dir = project
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cmake build: %v\n%s", err, output)
	}
}

func runCLI(t *testing.T, project string, args ...string) (string, string, int) {
	return runCLIEnv(t, project, nil, args...)
}

func runCLIEnv(t *testing.T, project string, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(fuzzfwBinary, args...)
	cmd.Dir = project
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func readSummary(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatal(err)
	}
	return summary
}

func TestCleanTargetPasses(t *testing.T) {
	project := fixture("c_clean")
	ensureBuild(t, project)
	out := t.TempDir()
	stdout, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("check exit = %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	if summary["status"] != "pass" {
		t.Fatalf("summary status = %v", summary["status"])
	}
	metrics := summary["metrics"].(map[string]any)
	if metrics["new_findings_reproduced"].(float64) != 0 {
		t.Fatalf("unexpected finding: %v", metrics)
	}
	if _, err := os.Stat(filepath.Join(out, "junit.xml")); err != nil {
		t.Fatal("junit.xml missing")
	}
}

func TestCorpusFindingFailsCheckAndReplays(t *testing.T) {
	project := fixture("c_parser")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--no-minimize", "--quiet")
	if code != 1 {
		t.Fatalf("check exit = %d, want 1\nstderr:\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	findings := summary["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %v", findings)
	}
	finding := findings[0].(map[string]any)
	if finding["origin"] != "target_crash" {
		t.Fatalf("origin = %v", finding["origin"])
	}
	if finding["reproduction"].(map[string]any)["level"] != "R1_HOST_REPRODUCED" {
		t.Fatalf("reproduction = %v", finding["reproduction"])
	}
	findingDir := filepath.Join(out, "findings", finding["id"].(string))
	_, replayErr, replayCode := runCLI(t, project, "replay", findingDir)
	if replayCode != 1 {
		t.Fatalf("replay exit = %d, want 1\n%s", replayCode, replayErr)
	}
	for _, name := range []string{"input.bin", "finding.json", "sanitizer.log", "replay.sh", "repro.json"} {
		if _, err := os.Stat(filepath.Join(findingDir, name)); err != nil {
			t.Fatalf("missing artifact %s", name)
		}
	}
}

func TestBaselineBootstrap(t *testing.T) {
	project := fixture("c_parser")
	ensureBuild(t, project)
	out := t.TempDir()
	baseline := filepath.Join(t.TempDir(), "baseline.json")
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out,
		"--baseline", baseline, "--bootstrap-baseline", "--no-minimize", "--quiet")
	if code != 0 {
		t.Fatalf("bootstrap exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	findings := summary["findings"].([]any)
	if len(findings) != 1 || findings[0].(map[string]any)["new"].(bool) {
		t.Fatalf("bootstrap findings = %v", findings)
	}
	out2 := t.TempDir()
	_, stderr, code = runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out2,
		"--baseline", baseline, "--no-minimize", "--quiet")
	if code != 0 {
		t.Fatalf("baseline exit = %d\n%s", code, stderr)
	}
}

func TestHALAdapterPasses(t *testing.T) {
	project := fixture("c_hal")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("check exit = %d\n%s", code, stderr)
	}
	planData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	target := plan["targets"].([]any)[0].(map[string]any)
	adapters := target["adapters"].([]any)
	if len(adapters) != 1 || adapters[0].(map[string]any)["original_symbol"] != "HAL_GetStatus" {
		t.Fatalf("adapters = %v", adapters)
	}
}

func TestWrapperPasses(t *testing.T) {
	project := fixture("c_wrapper")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("wrapper check exit = %d\n%s", code, stderr)
	}
}

func TestNativeIRLoopBoundEvidence(t *testing.T) {
	project := fixture("c_clean")
	ensureBuild(t, project)
	_, stderr, code := runCLI(t, project, "scan", ".", "--quiet")
	if code != 0 {
		t.Fatalf("scan exit = %d\n%s", code, stderr)
	}
	analysisData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var analysis map[string]any
	if err := json.Unmarshal(analysisData, &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis["analysis_mode"] != "NATIVE_AST" {
		t.Skip("native analyzer not built; textual IR fallback does not claim loop-bound evidence")
	}
	found := false
	for _, raw := range analysis["ir_facts"].([]any) {
		fact := raw.(map[string]any)
		if fact["link_symbol"] != "checksum_loop" {
			continue
		}
		found = true
		if fact["data_dependent"] != true {
			t.Fatalf("data_dependent = %v", fact["data_dependent"])
		}
		args := fact["arguments"].([]any)
		if len(args) < 2 {
			t.Fatalf("arguments = %v", args)
		}
		arg1 := args[1].(map[string]any)
		uses := arg1["observed_use"].([]any)
		hasLoop := false
		for _, use := range uses {
			if use == "loop_bound" {
				hasLoop = true
			}
		}
		if !hasLoop {
			t.Fatalf("length argument lacks loop_bound evidence: %v", uses)
		}
	}
	if !found {
		t.Fatal("checksum_loop IR fact missing")
	}
	aliasFound := false
	for _, raw := range analysis["ir_facts"].([]any) {
		fact := raw.(map[string]any)
		if fact["link_symbol"] != "compare_buffers" {
			continue
		}
		aliasFound = true
		if fact["memory_ssa_accesses"].(float64) == 0 {
			t.Fatal("MemorySSA access count missing")
		}
		aliases := fact["alias_facts"].([]any)
		hasNoAlias := false
		for _, alias := range aliases {
			if alias == "no_alias:0:1" {
				hasNoAlias = true
			}
		}
		if !hasNoAlias {
			t.Fatalf("AA no_alias evidence missing: %v", aliases)
		}
	}
	if !aliasFound {
		t.Fatal("compare_buffers IR fact missing")
	}
}

func TestMemorySanitizerFinding(t *testing.T) {
	project := fixture("c_msan")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 1 {
		t.Fatalf("MSan check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	findings := summary["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("MSan finding missing")
	}
	finding := findings[0].(map[string]any)
	if finding["kind"] != "memory:use-of-uninitialized-value" || finding["origin"] != "target_crash" {
		t.Fatalf("unexpected MSan finding: %v", finding)
	}
	reproduction := finding["reproduction"].(map[string]any)
	if reproduction["level"] != "R1_HOST_REPRODUCED" {
		t.Fatalf("reproduction = %v", reproduction)
	}
	buildInfo, err := os.ReadFile(filepath.Join(out, "build-info.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(buildInfo, &document); err != nil {
		t.Fatal(err)
	}
	result := document["targets"].([]any)[0].(map[string]any)["result"].(map[string]any)
	sanitizers := result["build_delta"].(map[string]any)["sanitizers"].([]any)
	found := false
	for _, sanitizer := range sanitizers {
		if sanitizer == "memory" {
			found = true
		}
	}
	if !found {
		t.Fatalf("build delta sanitizers = %v", sanitizers)
	}
}

func TestCppMemorySanitizerFinding(t *testing.T) {
	project := fixture("cpp_msan")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 1 {
		t.Fatalf("C++ MSan check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	findings := summary["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("C++ MSan finding missing")
	}
	finding := findings[0].(map[string]any)
	if finding["kind"] != "memory:use-of-uninitialized-value" || finding["origin"] != "target_crash" {
		t.Fatalf("unexpected C++ MSan finding: %v", finding)
	}
}

func TestOutputCapacityOverrunDetected(t *testing.T) {
	project := fixture("c_output")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 1 {
		t.Fatalf("output overrun check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	findings := summary["findings"].([]any)
	if len(findings) == 0 || findings[0].(map[string]any)["origin"] != "target_crash" {
		t.Fatalf("unexpected findings: %v", findings)
	}
}

func TestLocalAliasInterprocedural(t *testing.T) {
	project := fixture("c_alias")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("alias check exit = %d\n%s", code, stderr)
	}
	analysisData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var analysis map[string]any
	if err := json.Unmarshal(analysisData, &analysis); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, raw := range analysis["functions"].([]any) {
		fn := raw.(map[string]any)
		if fn["name"] != "alias_handler" {
			continue
		}
		for _, rawCall := range fn["direct_callees"].([]any) {
			call := rawCall.(map[string]any)
			if call["name"] != "read_cursor" {
				continue
			}
			args := call["arguments"].([]any)
			if len(args) == 1 && args[0].(float64) == 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("local alias was not mapped to the caller parameter")
	}
}

func TestInterproceduralIRUses(t *testing.T) {
	project := fixture("c_interproc")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("interprocedural check exit = %d\n%s", code, stderr)
	}
	planData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	target := plan["targets"].([]any)[0].(map[string]any)
	provenance := target["analysis"].(map[string]any)["provenance"].([]any)
	found := false
	for _, item := range provenance {
		if item == "interprocedural_ir" {
			found = true
		}
	}
	if !found {
		t.Fatalf("interprocedural provenance missing: %v", provenance)
	}
}

func TestCommandDictionaryGenerated(t *testing.T) {
	project := fixture("c_commands")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("command dictionary check exit = %d\n%s", code, stderr)
	}
	data, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "generated", "handle_command", "dictionary.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\\x42") {
		t.Fatalf("command constant missing from dictionary: %s", data)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	target := summary["targets"].([]any)[0].(map[string]any)
	if got := target["command_constants"].(float64); got != 2 {
		t.Fatalf("command_constants = %v, want 2", got)
	}
	if got := target["commands_covered"].(float64); got != 1 {
		t.Fatalf("commands_covered = %v, want 1 for the benign command seed", got)
	}
	planData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	planned := plan["targets"].([]any)[0].(map[string]any)
	names, _ := planned["command_names"].([]any)
	foundName := false
	for _, name := range names {
		if name == "CMD_BUG" {
			foundName = true
		}
	}
	if !foundName {
		t.Fatalf("enum command name missing: %v", names)
	}
	if !strings.Contains(string(data), "CMD_BUG") {
		t.Fatalf("command name missing from dictionary: %s", data)
	}
}

func TestLengthPrefixedSequencePasses(t *testing.T) {
	project := fixture("c_sequence")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("sequence check exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	targetSummary := summary["targets"].([]any)[0].(map[string]any)
	for key, want := range map[string]float64{
		"corpus_inputs": 3, "inputs_with_frames": 2, "corpus_frames": 3,
		"distinct_states": 2, "distinct_transitions": 3,
	} {
		if got := targetSummary[key].(float64); got != want {
			t.Fatalf("%s = %v, want %v", key, got, want)
		}
	}
	if hashes := targetSummary["state_hashes"].([]any); len(hashes) != 2 {
		t.Fatalf("state_hashes = %v", hashes)
	}
	if transitions := targetSummary["transitions"].([]any); len(transitions) != 3 {
		t.Fatalf("transitions = %v", transitions)
	}
	buildInfo, err := os.ReadFile(filepath.Join(out, "build-info.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(buildInfo, &document); err != nil {
		t.Fatal(err)
	}
	target := document["targets"].([]any)[0].(map[string]any)["result"].(map[string]any)
	selftest := target["selftest"].(map[string]any)
	if frames := selftest["frames"].(float64); frames < 2 {
		t.Fatalf("frames = %v, want at least 2", frames)
	}
	if hash, _ := selftest["state_hash"].(string); hash == "" {
		t.Fatal("state_hash was not recorded")
	}
	if transitions := selftest["transitions"].([]any); len(transitions) != 3 {
		t.Fatalf("selftest transitions = %v", transitions)
	}
	planData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	planned := plan["targets"].([]any)[0].(map[string]any)
	if planned["state_probe"] != "sequence_state_probe" || planned["frame_reset"] != "sequence_state_frame_reset" {
		t.Fatalf("state/frame contract missing from plan: %v", planned)
	}
}

func TestExistingHarnessReused(t *testing.T) {
	project := fixture("c_existing_harness")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("existing harness check exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["status"] != "selftest_passed" || target["entry_hit"] != true {
		t.Fatalf("unexpected target: %v", target)
	}
	if _, err := os.Stat(filepath.Join(project, ".fuzzfw", "generated", "existing_harness", "harness.c")); err == nil {
		t.Fatal("existing harness was replaced by a generated harness")
	}
	buildInfo, err := os.ReadFile(filepath.Join(out, "build-info.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(buildInfo, &document); err != nil {
		t.Fatal(err)
	}
	result := document["targets"].([]any)[0].(map[string]any)["result"].(map[string]any)
	if source, _ := result["harness_source_path"].(string); !strings.HasSuffix(source, "existing_harness.c") {
		t.Fatalf("harness source = %v", result["harness_source_path"])
	}
}

func TestFrameAwareLibFuzzerMutator(t *testing.T) {
	project := fixture("c_sequence")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "libfuzzer",
		"--time", "2s", "--jobs", "1", "--output", out, "--no-minimize", "--quiet")
	if code == 2 || code == 3 {
		t.Skipf("libFuzzer toolchain not available: %s", stderr)
	}
	if code != 0 {
		t.Fatalf("frame mutator fuzz exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	if summary["metrics"].(map[string]any)["cases_fuzzed"].(float64) < 1 {
		t.Fatalf("frame mutator run did not execute: %v", summary["metrics"])
	}
	if _, err := os.Stat(filepath.Join(project, ".fuzzfw", "generated", "frame_value", "frame_mutator.c")); err != nil {
		t.Fatalf("frame mutator was not generated: %v", err)
	}
}

func TestMultiTargetParallelPasses(t *testing.T) {
	project := fixture("c_multi")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("parallel check exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	targets := summary["targets"].([]any)
	want := []string{"parse_alpha", "parse_beta", "parse_gamma"}
	if len(targets) != len(want) {
		t.Fatalf("targets = %v", targets)
	}
	for index, target := range targets {
		item := target.(map[string]any)
		if item["name"] != want[index] || item["status"] != "selftest_passed" {
			t.Fatalf("target %d = %v", index, item)
		}
	}
	_, stderr, code = runCLI(t, project, "fuzz", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("parallel fuzz exit = %d\n%s", code, stderr)
	}
}

func TestTLVFramingPasses(t *testing.T) {
	project := fixture("c_tlv")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("TLV check exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["corpus_frames"].(float64) != 2 {
		t.Fatalf("corpus_frames = %v", target["corpus_frames"])
	}
	harness, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "generated", "tlv_frame", "harness.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(harness), "fuzzfw_frame_len -= 2;") ||
		!strings.Contains(string(harness), "((uint64_t)input[fuzzfw_offset + 0] << 8)") {
		t.Fatalf("framing not emitted:\n%s", harness)
	}
}

func TestUARTAdapterStreamPasses(t *testing.T) {
	testAdapterStream(t, "c_uart", "uart_process", "uart_rx", "UART_Read")
}

func TestNetworkAdapterStreamPasses(t *testing.T) {
	testAdapterStream(t, "c_network", "network_process", "network_rx", "NET_Recv")
}

func testAdapterStream(t *testing.T, name, targetName, eventModel, symbol string) {
	t.Helper()
	project := fixture(name)
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("%s check exit = %d\n%s", name, code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["name"] != targetName || target["status"] != "selftest_passed" || target["entry_hit"] != true {
		t.Fatalf("unexpected target: %v", target)
	}
	planData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	planned := plan["targets"].([]any)[0].(map[string]any)
	if planned["input_model"].(map[string]any)["kind"] != "adapter_stream" {
		t.Fatalf("input model = %v", planned["input_model"])
	}
	adapters := planned["adapters"].([]any)
	if len(adapters) != 1 || adapters[0].(map[string]any)["event_model"] != eventModel ||
		adapters[0].(map[string]any)["original_symbol"] != symbol {
		t.Fatalf("adapters = %v", adapters)
	}
}

func TestUnitTestContextExtraction(t *testing.T) {
	project := fixture("c_unit_test")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("unit-test context check exit = %d\n%s", code, stderr)
	}
	planData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	target := plan["targets"].([]any)[0].(map[string]any)
	if target["unit_test_context"] != "tests/test_parser.c:test_parser" {
		t.Fatalf("unit_test_context = %v", target["unit_test_context"])
	}
	harness, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "generated", "parser_process", "harness.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(harness), "test_setup();") || !strings.Contains(string(harness), "test_teardown();") {
		t.Fatalf("extracted setup/teardown missing:\n%s", harness)
	}
}

func TestCppConstructorPasses(t *testing.T) {
	project := fixture("cpp_constructor")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("constructor check exit = %d\n%s", code, stderr)
	}
	harness, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "generated", "parser_feed_constructor", "harness.cpp"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(harness), "Parser fuzzfw_object(3);") {
		t.Fatalf("constructor call missing:\n%s", harness)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["status"] != "selftest_passed" || target["entry_hit"] != true {
		t.Fatalf("unexpected target: %v", target)
	}
}

func TestJSMNFirmwarePilotPasses(t *testing.T) {
	project := pilot("jsmn")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("jsmn pilot exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	if summary["status"] != "pass" || len(summary["findings"].([]any)) != 0 {
		t.Fatalf("unexpected pilot summary: %v", summary)
	}
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["status"] != "selftest_passed" || target["entry_hit"] != true {
		t.Fatalf("unexpected pilot target: %v", target)
	}
	if target["corpus_inputs"].(float64) < 3 {
		t.Fatalf("pilot corpus was not replayed: %v", target)
	}
}

func TestJSMNFirmwarePilotLibFuzzer(t *testing.T) {
	project := pilot("jsmn")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "libfuzzer",
		"--time", "3s", "--jobs", "1", "--output", out, "--no-minimize", "--quiet")
	if code == 2 || code == 3 {
		t.Skipf("libFuzzer toolchain not available: %s", stderr)
	}
	if code != 0 {
		t.Fatalf("jsmn libFuzzer pilot exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	if summary["metrics"].(map[string]any)["cases_fuzzed"].(float64) < 1 {
		t.Fatalf("pilot did not execute the fuzzer: %v", summary["metrics"])
	}
}

func TestCommandTableExtraction(t *testing.T) {
	project := fixture("c_command_table")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 1 {
		t.Fatalf("command table check exit = %d, want 1\n%s", code, stderr)
	}
	planData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	target := plan["targets"].([]any)[0].(map[string]any)
	if len(target["command_constants"].([]any)) != 2 {
		t.Fatalf("command_constants = %v", target["command_constants"])
	}
	names := map[string]bool{}
	for _, raw := range target["command_names"].([]any) {
		names[raw.(string)] = true
	}
	if !names["ping"] || !names["bug"] {
		t.Fatalf("command_names = %v", target["command_names"])
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	if len(summary["findings"].([]any)) < 1 {
		t.Fatal("command table seed did not reproduce a finding")
	}
}

func TestCommandSeedsSynthesized(t *testing.T) {
	project := fixture("c_command_seeds")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 1 {
		t.Fatalf("command seed check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	findings := summary["findings"].([]any)
	if len(findings) == 0 || findings[0].(map[string]any)["origin"] != "target_crash" {
		t.Fatalf("unexpected findings: %v", findings)
	}
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["commands_covered"].(float64) != 2 || target["command_constants"].(float64) != 2 {
		t.Fatalf("command coverage = %v/%v", target["commands_covered"], target["command_constants"])
	}
	if target["corpus_removed"].(float64) == 0 ||
		target["corpus_selected"].(float64) >= target["corpus_inputs"].(float64) {
		t.Fatalf("corpus dedup metrics = inputs:%v selected:%v removed:%v",
			target["corpus_inputs"], target["corpus_selected"], target["corpus_removed"])
	}
	seedPath := filepath.Join(out, "corpus", "command_seed_entry", "fuzzfw-command-01-1")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("synthesized command seed missing: %v", err)
	}
	if !bytes.Equal(data, []byte{0x42, 0x00}) {
		t.Fatalf("synthesized seed = %x", data)
	}
}

func TestInvariantOracleDetectsOutputBug(t *testing.T) {
	project := fixture("c_invariant")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 1 {
		t.Fatalf("invariant check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	findings := summary["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("invariant finding missing")
	}
	finding := findings[0].(map[string]any)
	if finding["origin"] != "target_invariant" {
		t.Fatalf("origin = %v", finding["origin"])
	}
	if kind, _ := finding["kind"].(string); !strings.HasPrefix(kind, "invariant:") {
		t.Fatalf("kind = %v", finding["kind"])
	}
	reproduction := finding["reproduction"].(map[string]any)
	if reproduction["level"] != "R1_HOST_REPRODUCED" {
		t.Fatalf("reproduction = %v", reproduction)
	}
	if summary["metrics"].(map[string]any)["new_findings_reproduced"].(float64) != 1 {
		t.Fatalf("metrics = %v", summary["metrics"])
	}
}

func TestCContextLifecyclePasses(t *testing.T) {
	project := fixture("c_context")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("C context check exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["status"] != "selftest_passed" && target["status"] != "fuzzable" {
		t.Fatalf("C context status = %v", target["status"])
	}
}

func TestExactInputCopyDetectsOverread(t *testing.T) {
	project := fixture("c_overread")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 1 {
		t.Fatalf("overread check exit = %d, want 1\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	findings := summary["findings"].([]any)
	if len(findings) == 0 || findings[0].(map[string]any)["origin"] != "target_crash" {
		t.Fatalf("unexpected findings: %v", findings)
	}
}

func TestDMAEventModelPasses(t *testing.T) {
	project := fixture("c_dma")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("DMA event check exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["status"] != "selftest_passed" && target["status"] != "fuzzable" {
		t.Fatalf("DMA target status = %v", target["status"])
	}
}

func TestISREventModelPasses(t *testing.T) {
	project := fixture("c_isr")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("ISR event check exit = %d\n%s", code, stderr)
	}
}

func TestRTOSEventModelPasses(t *testing.T) {
	project := fixture("c_rtos")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("RTOS event check exit = %d\n%s", code, stderr)
	}
}

func TestCppObjectContextPasses(t *testing.T) {
	project := fixture("cpp_context")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("cpp context check exit = %d\n%s", code, stderr)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	for _, raw := range summary["targets"].([]any) {
		target := raw.(map[string]any)
		if target["status"] != "selftest_passed" && target["status"] != "fuzzable" {
			t.Fatalf("target %v status = %v", target["name"], target["status"])
		}
	}
}

func TestPersistentResetLeakDetected(t *testing.T) {
	project := fixture("c_state")
	ensureBuild(t, project)
	out := t.TempDir()
	_, _, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 2 {
		t.Fatalf("stateful check exit = %d, want 2", code)
	}
	summary := readSummary(t, filepath.Join(out, "summary.json"))
	target := summary["targets"].([]any)[0].(map[string]any)
	if target["status"] != "state_leak" {
		t.Fatalf("status = %v", target["status"])
	}
}

func TestFallbackAnalysisPasses(t *testing.T) {
	project := fixture("c_clean")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLIEnv(t, project, []string{"FUZZFW_DISABLE_NATIVE=1"},
		"check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("fallback check exit = %d\n%s", code, stderr)
	}
	analysisData, err := os.ReadFile(filepath.Join(project, ".fuzzfw", "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var analysis map[string]any
	if err := json.Unmarshal(analysisData, &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis["analysis_mode"] == "NATIVE_AST" {
		t.Fatalf("fallback run still used native analysis: %v", analysis["analysis_mode"])
	}
}

func TestCppFreeFunctionPasses(t *testing.T) {
	project := fixture("cpp_parser")
	ensureBuild(t, project)
	out := t.TempDir()
	_, stderr, code := runCLI(t, project, "check", "--engine", "replay", "--time", "1s", "--output", out, "--quiet")
	if code != 0 {
		t.Fatalf("check exit = %d\n%s", code, stderr)
	}
}
