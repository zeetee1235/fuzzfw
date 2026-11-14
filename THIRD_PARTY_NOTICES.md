# Third-party notices

fuzzfw is distributed under Apache-2.0. This file summarizes third-party
components that are linked, invoked, or commonly installed alongside it. It is
not a substitute for the full license texts shipped by those projects.

## Linked into the fuzzfw binary

### Go standard library

- License: BSD-3-Clause
- Copyright: The Go Authors
- https://go.dev/LICENSE

### github.com/pelletier/go-toml/v2

- License: MIT
- Purpose: TOML decoding
- https://github.com/pelletier/go-toml

## Compiled into generated fuzz/self-test binaries when selected

### LLVM libFuzzer

- License: Apache-2.0 WITH LLVM-exception
- Invoked through Clang `-fsanitize=fuzzer`
- The customer/release image must comply with the LLVM license and notices.

### Clang sanitizer runtimes

- License: Apache-2.0 WITH LLVM-exception
- Linked into ASan/UBSan fuzz binaries by Clang.

## Optional separate tools (not vendored)

### LLVM/Clang

- License: Apache-2.0 WITH LLVM-exception
- Used as compiler and optional native analyzer libraries.
- https://llvm.org/LICENSE.txt

### honggfuzz

- License: Apache-2.0
- Separate process; not bundled in the fuzzfw source tree.
- https://github.com/google/honggfuzz

### CMake

- License: BSD-3-Clause
- Build tool, not distributed with fuzzfw.

### Ninja

- License: Apache-2.0
- Build tool, not distributed with fuzzfw.

## No vendored fuzzing engine

fuzzfw does not vendor honggfuzz or libFuzzer source. Release images that bundle
them must include their notices and version information separately.
