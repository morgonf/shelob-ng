# shelob-ng / Swagger Petstore 3 — worked example

[Swagger Petstore 3](https://github.com/swagger-api/swagger-petstore) is the official
reference implementation of the OpenAPI 3.x Petstore spec (13 endpoints, Java/inflector).

**Not a security target.** Use it to:
- Benchmark the fuzzer's spec coverage and 2xx rate (baseline)
- Test OAuth2 implicit flow and apiKey auth handling
- Verify XML and form-encoded body generation

---

## Quick start

```bash
cd example/petstore/
make setup    # start Petstore, fetch spec
make run-1    # spec coverage baseline
```

---

## Contents

```
petstore/
  Makefile
  config.env              shared config: URL, API key
  docker-compose.yml      swaggerapi/petstore3:unstable
  scripts/
    01_setup.sh           start container, fetch spec
    02_scenario_coverage.sh  Scenario 1: spec coverage baseline
  results/                created at runtime
  corpus/                 created at runtime
```

---

## Scenario 1 — Spec coverage baseline

```bash
make run-1
```

Runs all 13 Petstore operations with apiKey auth and reports:
- `visited_count` / `total` — how many endpoints received any response
- `succeeded_count` / `total` — how many returned at least one 2xx

**Expected output** (Petstore is stateless — dependent ops return 404/500 without prior POST):
```
Reached:     13/13 (100%)
Succeeded:    4/13  (30%)
```

Low 2xx rate is expected here — Petstore does not persist state across requests.
After implementing the producer-consumer graph (see `restler-demo/`), the 2xx rate
should increase as `GET /pet/{petId}` receives IDs from `POST /pet`.

---

## Auth schemes in Petstore

The spec defines two schemes:

| Scheme | Type | Usage |
|--------|------|-------|
| `petstore_auth` | OAuth2 implicit | `/pet` endpoints (write/read scopes) |
| `api_key` | API key in header `api_key` | `/pet/findByStatus` and others |

shelob-ng uses `-apikey special-key` which satisfies the `api_key` scheme.
OAuth2 requires a pre-obtained token: `-token <jwt>`.

---

## Live public instance

The official live instance runs at https://petstore3.swagger.io
**Do NOT fuzz the public instance.** Always run your own Docker container.
