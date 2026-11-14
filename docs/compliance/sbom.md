# SBOM and third-party notices

## Generate

```sh
make sbom
# or
go run ./tools/sbom --output dist
```

The generator writes a deterministic CycloneDX 1.5 JSON file
`dist/fuzzfw-<version>.cdx.json`. It records:

- `fuzzfw` as the application component under Apache-2.0;
- the Go standard library;
- the `pelletier/go-toml/v2` MIT dependency when present in `go.mod`.

## Scope

The SBOM covers components distributed/linked into the fuzzfw binary. It does
not silently claim that optional external tools are bundled. If a release image
bundles LLVM, honggfuzz, CMake, or Ninja, generate a separate image/filesystem
SBOM or extend the release manifest with their licenses and versions.

## Release checks

- `THIRD_PARTY_NOTICES.md` is up to date.
- `NOTICE` is included in source and binary distributions.
- The SBOM serial/identity is tied to the release version.
- Checksums are published next to the artifact.
- A customer bill of materials can be produced from the same source tag.

## Customer expectations

Enterprises often request:

- component name/version/supplier;
- license identifiers and notice files;
- vulnerability disclosure contact;
- SBOM format and update cadence;
- confirmation that no telemetry or unexpected network egress exists.

fuzzfw's default answer is: no telemetry, no cloud upload, one Go runtime
dependency, and external tools invoked separately. Verify this for each release
rather than assuming it remains true.
