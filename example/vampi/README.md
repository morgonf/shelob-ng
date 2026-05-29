# shelob-ng / VAmPI — worked example

[VAmPI](https://github.com/erev0s/VAmPI) — intentionally vulnerable REST API built with Python/Flask.
Covers OWASP API Security Top 10 with a complete and accurate OpenAPI 3.x spec.

**Best for:** BOLA/IDOR testing, SQLi detection, mass assignment, JWT bypass.

---

## Quick start

```bash
cd example/vampi/
make setup       # build fuzzer, start VAmPI, seed DB, fetch spec
make run-2       # BOLA detection (the core vulnerability)
```

---

## Contents

```
vampi/
  Makefile
  config.env              shared config: URL, credentials, paths
  docker-compose.yml      VAmPI with tokentimetolive=3600 (extended JWT TTL)
  scripts/
    01_setup.sh           start container, seed DB, fetch spec
    02_scenario_basic.sh  Scenario 1: basic authenticated scan
    03_scenario_bola.sh   Scenario 2: BOLA / NameSpaceRule (two users)
    04_scenario_payloads.sh Scenario 3: injection payload wordlists
  results/                created at runtime
  corpus/                 created at runtime
```

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Go ≥ 1.22 | Build shelob-ng |
| Docker + Compose v2 | Run VAmPI |
| Python 3 | Spec parsing in setup script |

---

## One-time setup

```bash
make setup
```

This will:
1. Build `shelob-ng` binary at repo root
2. Pull and start `erev0s/vampi:latest` with `tokentimetolive=3600`
3. Seed the database via `GET /createdb` (**required before any fuzzing**)
4. Verify admin1/pass1 login and save the JWT
5. Download `openapi3.yaml` from the running container

> **Note:** `tokentimetolive=3600` extends the JWT lifetime from 60 s to 1 hour.
> Without this, the fuzzer receives 401 partway through longer runs.

---

## Scenarios

| # | Name | Auth | Duration | Focus |
|---|------|------|----------|-------|
| 1 | Basic scan | JWT Bearer | 5 m | All checkers, baseline |
| 2 | BOLA | JWT, two users | 5 m | NameSpaceRule — cross-account access |
| 3 | Payload injection | JWT Bearer | 15 m | SQLi, NoSQL, XSS wordlists |

### Scenario 1 — Basic scan

```bash
make run-1
# or manually:
./shelob-ng -spec openapi3.yaml -url http://localhost:5000 \
            -user admin1 -password pass1 -duration 5m -output results/01_basic
```

**Expected findings:**
- `BehavioralPatterns: HIGH` — SQL error in `GET /books/v1/{book}` (direct concatenation)
- `InvalidDynamicObject` — 500s on boundary IDs
- `SchemaViolation` — `GET /users/v1/_debug` exposes all passwords (excessive data exposure)

### Scenario 2 — BOLA

```bash
make run-2
```

VAmPI's `GET /books/v1/{book}` returns any user's book by name.
`GET /users/v1/{username}` returns profile data across accounts.

**Expected findings:**
- `NameSpaceRule: HIGH` — user2 reads books owned by admin1

### Scenario 3 — Payload injection

```bash
make run-3
# or with custom wordlists:
PAYLOADS_SQLI=/path/to/sqli.txt make run-3
```

---

## VAmPI vulnerability catalogue

| Vulnerability | Endpoint | OWASP API |
|---------------|----------|-----------|
| SQLi | `GET /books/v1/{book}` | A03 |
| BOLA/IDOR | `GET /books/v1/{book}`, `GET /users/v1/{username}` | A01 |
| Excessive data exposure | `GET /users/v1/_debug` | A03 |
| Unauthorized password change | `PUT /users/v1/{username}` | A02 |
| User enumeration | `/users/v1/login` error messages | A02 |
| JWT weak signing key | Any authenticated endpoint | A02 |
| Mass assignment | `POST /users/v1/register` | A06 |
| RegexDoS | `GET /users/v1/{username}` | A04 |

---

## Differential testing

Run with vulnerable=0 to get a baseline (secure mode):

```bash
# Stop vulnerable instance
docker compose down

# Start secure instance on same port
docker run -d -e vulnerable=0 -e tokentimetolive=3600 -p 5000:5000 erev0s/vampi:latest
curl http://localhost:5000/createdb

# Run same scenario
make run-2  # should find 0 BOLA findings

# Compare:
#   vulnerable=1: NameSpaceRule HIGH on /books/v1/{book}
#   vulnerable=0: no findings (ACL enforced)
```
