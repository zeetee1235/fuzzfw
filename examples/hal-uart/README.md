# HAL UART example (placeholder)

A production-quality UART adapter is customer-specific. Do not add a universal
`HAL_UART_Receive` that returns success: it would violate the project's no-auto-
stub rule.

To build this example later:

1. Provide the real HAL header/prototype.
2. Provide an adapter that models input bytes, maximum write, return status,
   initialized context, timeout behavior, and limitations.
3. Provide a contract JSON and register it in `fuzzfw.toml`.
4. Keep the original `process_packet()` call path unchanged.
5. Run `fuzzfw check --engine replay` and verify entry reachability before
   enabling a mutating engine.

The fixture `tests/fixtures/c_hal` shows a minimal approved status-only adapter.
