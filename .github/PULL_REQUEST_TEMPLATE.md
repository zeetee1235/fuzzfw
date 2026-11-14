## Summary

## Evidence and failure behavior

- What classification is expected: ready/adaptable/blocked?
- What new evidence is recorded?
- What happens when the evidence is missing or ambiguous?
- Does this preserve original translation units and avoid automatic HAL stubs?

## Tests

- [ ] Unit tests added/updated
- [ ] Integration/fixture test added/updated
- [ ] Schema/diagnostic docs updated if contracts changed

## Checklist

- [ ] `make lint`
- [ ] `make test`
- [ ] `make test-integration` (if native behavior changed)
- [ ] Commits are signed off (`git commit -s`)
- [ ] No secrets, customer firmware, or proprietary crash inputs included
