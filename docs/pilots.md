# Firmware pilots

Pilots exercise fuzzfw against real, unmodified third-party firmware
components rather than repository fixtures.

## jsmn embedded JSON tokenizer

- Upstream: <https://github.com/zserge/jsmn>
- Pinned commit: `25647e692c7906b96ffd2b05ca54c097948e879c`
- License: MIT
- Project: `tests/pilots/jsmn`

`jsmn` is a single-header JSON parser designed for embedded systems. Its public
entry point is:

```c
int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
               jsmntok_t *tokens, unsigned int num_tokens);
```

The parser and token array are caller-owned, so the pilot uses the explicit
wrapper escape hatch to provide a stack token array and call the real parser.
The wrapper contains no parsing logic.

### Results

Validation environment: Linux x86-64, Clang 22.1.8, fuzzfw `e110146` plus the
command-seed/transition/MSan changes.

```text
replay check:          pass, 0 findings
libFuzzer 20s, 1 job:  pass, 4,817,040 executions, 0 findings
```

Reproduce:

```sh
cd tests/pilots/jsmn
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
fuzzfw check --engine replay --time 1s
fuzzfw check --engine libfuzzer --time 20s --jobs 1 --no-minimize
```

No finding is expected: the goal of this pilot is to prove that fuzzfw can
build, self-test, replay, and fuzz a real embedded parser with its own output
contract. It is not a claim that `jsmn` is vulnerability-free.
