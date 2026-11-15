// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

//go:build integration

package integration

import (
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
