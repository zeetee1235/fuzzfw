# Native analyzers

Two optional C++17 executables implement the spec's native analysis path:

| Tool | Source | Purpose |
|---|---|---|
| `fuzzfw-analyze` | `clang/main.cpp` | Clang LibTooling AST facts: declarations, types, calls, globals, hardware flags. |
| `fuzzfw-ir-analyze` | `llvm/main.cpp` | Read-only LLVM IR walker: conservative argument uses, memory operations, indirect/external calls. |

Both are separate processes. They never link into the Go binary and never
rewrite user code. The Go fallback (`clang -Xclang -ast-dump=json` and textual
LLVM IR) is used when the tools are absent or fail; `analysis.json` records the
reduced mode explicitly.

## Build

```sh
cmake -S analyzer -B analyzer/build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build analyzer/build
```

If the default discovery fails:

```sh
cmake -S analyzer -B analyzer/build -G Ninja \
  -DLLVM_INCLUDE_DIR=/usr/lib/llvm-18/include \
  -DCLANG_INCLUDE_DIR=/usr/lib/llvm-18/include \
  -DCLANG_CPP_LIBRARY=/usr/lib/llvm-18/lib/libclang-cpp.so \
  -DLLVM_LIBRARY=/usr/lib/llvm-18/lib/libLLVM.so
cmake --build analyzer/build
```

Fedora's `clang-devel`/`llvm-devel` and Debian/Ubuntu's `clang`/`libclang-dev`/
`llvm-dev` are supported. The CMake file prefers `find_path`/`find_library` so it
works with both shared `libclang-cpp` layouts and custom release prefixes.

## Contract

`fuzzfw-analyze` input:

```json
{
  "schema_version": 1,
  "root": "/project",
  "directory": "/project/build",
  "file": "/project/src/parser.c",
  "language": "c",
  "variant_id": "abc123",
  "arguments": ["cc", "-Iinclude", "-c", "src/parser.c"]
}
```

Output is `{schema_version, generator, functions[], declarations[]}` using the
same JSON field names as `schemas/analysis.schema.json`. The Go layer assigns
stable function IDs, maps headers, resolves external calls, and joins IR facts.

`fuzzfw-ir-analyze` takes `--input module.ll --output facts.json` and emits
`{schema_version, generator, target_triple, facts[]}` matching
`schemas/ir_facts.schema.json`.

## Read-only guarantee

- No LLVM transformation pass is registered.
- No source file is modified.
- `MayAlias` is never promoted to `MustAlias`.
- An unknown indirect call or external declaration remains `unknown`.
- The current IR walker is conservative and predates full New PM
  AA/MemorySSA-assisted analysis. That limitation is reported, not hidden.

## Fallback testing

Set `FUZZFW_DISABLE_NATIVE=1` to force the Go fallback for a run. The integration
tests use both modes when native tools are available.
