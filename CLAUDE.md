# shelob-ng — Instructions for Claude

## Documentation Rule (MANDATORY)

Every code change must include documentation updates. Documentation is not optional.

### What to update for each type of change

| Change type | Files to update |
|------------|----------------|
| New CLI flag | `docs/cli-reference.md`, `README.md` (All flags table) |
| New checker | `docs/checkers.md` (full section), `docs/architecture.md` (diagram), `README.md` (features + checkers tables), `checkers/checker.go` (comment in All()), `cliArgs/cliArgs.go` (valid names) |
| New mutator | `docs/architecture.md` (mutation pipeline), `README.md` (mutation strategies) |
| Bug fix changing behavior | `docs/checkers.md` or relevant doc, `example/*/README.md` expected findings |
| New pathscan path | `docs/checkers.md` (PathDiscovery categories) |
| New example target | `docs/knowledge-base/targets.md`, `example/README.md`, new `example/<target>/README.md` |
| OpenAPI feature added | `docs/openapi-support.md` (move from Not Supported to Supported) |
| Architectural change | `docs/architecture.md` |

### Documentation files map

```
docs/
  README.md             — index + quick-links
  architecture.md       — main loop, packages, data flow, design decisions
  checkers.md           — all 11 checkers + PathDiscovery reference
  corpus.md             — corpus management, seeding, dependency graph
  csp-protocol.md       — CSP spec + adapters (Node.js, Go, Python, C)
  cli-reference.md      — all flags with examples
  extending.md          — how to add checkers, mutators, adapters
  openapi-support.md    — supported/unsupported OpenAPI features
  knowledge-base/       — research material (targets, vuln catalogue, edge cases)

example/
  README.md             — target index
  juice-shop/README.md  — 10 scenarios
  vampi/README.md       — 6 scenarios
  crapi/README.md       — 6 scenarios
  dvws-node/README.md   — 7 scenarios
  petstore/README.md    — 6 scenarios
  restler-demo/README.md — 5 scenarios
```

## Code Style

- Comments explain WHY, not WHAT. Non-obvious logic, security rationale, edge cases.
- No multi-line comment blocks. One short line max.
- Doc comments on all exported functions and types.
- No unused backward-compat code, no placeholder comments for removed code.

## Checker Conventions

- Stateless checkers: zero-value struct, value receiver.
- Stateful checkers: pointer receiver + constructor `NewXxx()`, registered in `All()` as `NewXxx()`.
- All checkers: `sync.Map` or `sync.Mutex` for shared state (concurrent calls).
- Probe requests: use `buildProbeWithCookies()` + `ApplyAuth()`. Never forward Bearer token to user2 probes.
- Return `nil` (not empty slice) when no findings.

## Testing

- Every new checker needs tests: finding case, no-finding case, skip-condition case.
- Use `httptest.NewServer` for mock servers.
- Test file next to implementation: `checkers/mychecker_test.go`.

## Commit Format

Each commit must include both the code change and its documentation update.
Never commit code without updating the relevant docs.
