# Examples

| Example | Purpose |
|---|---|
| `simple-parser` | Zero-config C11 parser; auto-builds, discovers targets, and finds an intentional heap overflow with libFuzzer. |

The fixtures under `tests/fixtures/` are the deterministic test matrix:

- `c_clean` — clean C target, expected check exit 0.
- `c_parser` — corpus finding, expected check exit 1 and replay.
- `c_hal` — approved status-only HAL adapter, expected check exit 0.
- `cpp_parser` — C++17 free function in a namespace, expected check exit 0.
- `c_wrapper` — explicit user wrapper escape hatch, expected check exit 0.
- `c_dma`, `c_isr`, `c_rtos` — approved event-model adapters and hooks, expected check exit 0.
- `c_state` — persistent reset leak, expected check exit 2.
- `c_vuln` — unseeded vulnerable target for optional honggfuzz discovery tests.

```sh
cd examples/simple-parser
./run.sh
```
