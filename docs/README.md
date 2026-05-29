# shelob-ng Documentation

## Contents

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Internal design: main loop, packages, data flow, concurrency, key decisions |
| [Checkers Reference](checkers.md) | All 11 checkers + PathDiscovery: detection logic, thresholds, custom checker guide |
| [Corpus Management](corpus.md) | Entry format, selection weights, seeding, persistence, dependency graph, DynamicValuePool |
| [CSP Protocol](csp-protocol.md) | Coverage Sidecar Protocol — concept, lifecycle, per-language implementations |
| [CSP Servers Setup](csp-servers.md) | Operational guide for the 4 shipped adapters: configuration, integration patterns, verification, troubleshooting |
| [CLI Reference](cli-reference.md) | All flags with descriptions, examples, and common invocations |
| [Extending shelob-ng](extending.md) | How to add checkers, mutation strategies, CSP adapters, payload patterns |
| [OpenAPI Support](openapi-support.md) | Supported features, limitations, compatibility tips |

## Quick Links

**I want to understand how shelob-ng works:**
→ [Architecture](architecture.md)

**I want to know what each checker does:**
→ [Checkers Reference](checkers.md)

**I want to use a specific flag:**
→ [CLI Reference](cli-reference.md)

**I want to understand how CSP coverage feedback works:**
→ [CSP Protocol](csp-protocol.md) — lifecycle, protocol spec, all language adapters

**I want to set up CSP for my specific application (Node.js / Go / Python / C):**
→ [CSP Servers Setup](csp-servers.md) — step-by-step config, integration patterns, verification

**I want to write a custom checker:**
→ [Extending shelob-ng](extending.md) → "Adding a Checker"

**I want to know why my spec isn't working:**
→ [OpenAPI Support](openapi-support.md)

**I want to fuzz a specific target:**
→ [example/README.md](../example/README.md) — 6 test targets with step-by-step guides

## Research / Internal

| Document | Description |
|----------|-------------|
| [knowledge-base/vuln-catalogue.md](knowledge-base/vuln-catalogue.md) | Ground-truth vulnerability catalogue: 176 vulns in 5 targets, detection rates |
| [knowledge-base/openapi-edge-cases.md](knowledge-base/openapi-edge-cases.md) | OpenAPI 3.x edge cases affecting fuzzer input generation |
| [knowledge-base/targets.md](knowledge-base/targets.md) | Detailed notes on 11 test targets with Docker commands |
| [knowledge-base/INDEX.md](knowledge-base/INDEX.md) | Knowledge base index |
