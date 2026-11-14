// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Command sbom writes a deterministic CycloneDX 1.5 software bill of materials.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fuzzfw/fuzzfw/internal/version"
)

type bom struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     metadata     `json:"metadata"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type metadata struct {
	Timestamp string    `json:"timestamp,omitempty"`
	Tools     []tool    `json:"tools,omitempty"`
	Component component `json:"component"`
}

type tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type component struct {
	Type     string    `json:"type"`
	BOMRef   string    `json:"bom-ref,omitempty"`
	Group    string    `json:"group,omitempty"`
	Name     string    `json:"name"`
	Version  string    `json:"version,omitempty"`
	Scope    string    `json:"scope,omitempty"`
	Licenses []license `json:"licenses,omitempty"`
	PURL     string    `json:"purl,omitempty"`
	Hashes   []hash    `json:"hashes,omitempty"`
}

type license struct {
	License licenseID `json:"license"`
}

type licenseID struct {
	ID string `json:"id"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func main() {
	output := flag.String("output", "dist", "output directory")
	flag.Parse()
	if err := run(*output); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}
}

func run(outputDir string) error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	appRef := "pkg:generic/fuzzfw@" + version.Version
	sum := sha256.Sum256([]byte("fuzzfw-sbom-" + version.Version))
	serial := fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s",
		hex.EncodeToString(sum[0:4]), hex.EncodeToString(sum[4:6]),
		hex.EncodeToString(sum[6:8]), hex.EncodeToString(sum[8:10]),
		hex.EncodeToString(sum[10:16]))
	document := bom{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: serial,
		Version:      1,
		Metadata: metadata{
			Tools: []tool{{Vendor: "fuzzfw", Name: "fuzzfw", Version: version.Version}},
			Component: component{
				Type: "application", BOMRef: appRef, Name: "fuzzfw", Version: version.Version,
				Licenses: []license{{License: licenseID{ID: "Apache-2.0"}}},
				PURL:     appRef,
			},
		},
		Components: []component{
			{
				Type: "library", BOMRef: "pkg:golang/stdlib", Name: "Go standard library",
				Scope: "required", Licenses: []license{{License: licenseID{ID: "BSD-3-Clause"}}},
			},
		},
		Dependencies: []dependency{{Ref: appRef, DependsOn: []string{"pkg:golang/stdlib"}}},
	}
	modules, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err == nil {
		for _, line := range strings.Split(string(modules), "\n") {
			fields := strings.Fields(line)
			for i := 0; i+1 < len(fields); i++ {
				if !strings.HasPrefix(fields[i], "github.com/pelletier/go-toml") {
					continue
				}
				ref := "pkg:golang/" + fields[i] + "@" + fields[i+1]
				document.Components = append(document.Components, component{
					Type: "library", BOMRef: ref, Name: fields[i], Version: fields[i+1],
					Scope: "required", Licenses: []license{{License: licenseID{ID: "MIT"}}}, PURL: ref,
				})
				document.Dependencies[0].DependsOn = append(document.Dependencies[0].DependsOn, ref)
			}
		}
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(outputDir, "fuzzfw-"+version.Version+".cdx.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Println(path)
	return nil
}
