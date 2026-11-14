// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors
package triage

import (
	"strings"
	"testing"
)

func TestCrashKindAndFrames(t *testing.T) {
	log := `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x0001 in __asan_memcpy (/tmp/x+0x1)
    #1 0x0002 in parse_packet /tmp/parser.c:29:9
    #2 0x0003 in LLVMFuzzerTestOneInput /tmp/harness.c:15:11
`
	if kind := crashKind(log, 1, 0, false); kind != "address:heap-buffer-overflow" {
		t.Fatalf("kind = %s", kind)
	}
	frames, source := normalizeFrames(log)
	if len(frames) != 2 || !strings.Contains(frames[0], "parse_packet") {
		t.Fatalf("frames = %#v", frames)
	}
	if source.File != "parser.c" || source.Line != 29 || source.Func != "parse_packet" {
		t.Fatalf("source = %+v", source)
	}
}

func TestFingerprintStable(t *testing.T) {
	finding := Finding{Target: "t", Kind: "address:heap-buffer-overflow", Origin: "target_crash"}
	a := fingerprint(finding, []string{"parse_packet@parser.c:29"}, "plan")
	b := fingerprint(finding, []string{"parse_packet@parser.c:29"}, "plan")
	if a != b {
		t.Fatal("fingerprint changed")
	}
	if findingID(a) == "" || findingID(a) != findingID(b) {
		t.Fatalf("finding IDs = %q %q", findingID(a), findingID(b))
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/baseline.json"
	finding := Finding{
		Fingerprint: "abc", ID: "F1", Target: "t", Kind: "k", Origin: "target_crash",
		Reproduction: Reproduction{Level: "R1_HOST_REPRODUCED", Success: 3, Attempts: 3},
	}
	if err := WriteBaseline(path, []Finding{finding}); err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if baseline == nil || len(baseline.Findings) != 1 || baseline.Findings[0].Fingerprint != "abc" {
		t.Fatalf("baseline = %+v", baseline)
	}
	if got := NewFingerprints([]Finding{finding}, baseline); len(got) != 0 {
		t.Fatalf("known finding treated as new: %+v", got)
	}
}
