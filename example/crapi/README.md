# shelob-ng / crAPI — worked example

[crAPI](https://github.com/OWASP/crAPI) (Completely Ridiculous API) is the OWASP flagship
for API security testing. A realistic polyglot microservices app (Java + Go + Python/Django).

**Best for:** All OWASP API Top 10 (2023), multi-service BOLA, stateful producer-consumer chains.

---

## Quick start

```bash
# 1. Start crAPI (external)
git clone https://github.com/OWASP/crAPI.git /opt/crapi
cd /opt/crapi/deploy/docker
docker compose -f docker-compose.minimal.yml up -d
# Wait ~60s for all services; check http://localhost:8888

# 2. Confirm accounts in Mailhog
open http://localhost:8025

# 3. Run fuzzer
cd example/crapi/
make setup    # registers accounts, checks spec
make run-1    # basic scan
make run-2    # BOLA detection
```

---

## Contents

```
crapi/
  Makefile
  config.env         shared config: URLs, credentials, spec path
  scripts/
    01_setup.sh      verify crAPI, register accounts
    02_scenario_basic.sh   Scenario 1: basic authenticated scan
    03_scenario_bola.sh    Scenario 2: BOLA / NameSpaceRule
  results/           created at runtime
  corpus/            created at runtime
```

---

## Architecture

crAPI runs as microservices. The OpenAPI spec covers the **identity service** only.
Community (Go) and Workshop (Python) services have their own internal specs:

| Service | Port/Path | Spec URL |
|---------|-----------|----------|
| Identity (Java) | `localhost:8888/identity` | `openapi-spec/crapi-openapi-spec.json` |
| Community (Go) | `localhost:8888/community` | `localhost:8888/community/docs` |
| Workshop (Python) | `localhost:8888/workshop` | `localhost:8888/workshop/api/schema` |

For full coverage, run shelob-ng separately against each service spec.

---

## Setup details

### Resource requirements

| Component | Requirement |
|-----------|------------|
| RAM | ~4 GB minimum |
| Docker | Compose v1.27+ |
| Startup time | ~60 seconds |

### Account registration flow

crAPI uses email verification. After `make setup`, open Mailhog (`http://localhost:8025`)
and click the confirmation links for both accounts.

```bash
# Pre-seed accounts without email confirmation (for automation):
curl -s -X POST http://localhost:8888/identity/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"name":"Fuzzer","email":"fuzzer@shelob.local","number":"9876543210","password":"Shelob1!"}'
# Then confirm via Mailhog UI
```

---

## Scenarios

| # | Name | Auth | Duration | Focus |
|---|------|------|----------|-------|
| 1 | Basic scan | JWT Bearer | 5 m | Identity service, all checkers |
| 2 | BOLA | JWT, two users | 15 m | Vehicle/mechanic report cross-account access |

---

## crAPI vulnerability catalogue

| Vulnerability | Endpoint | OWASP API 2023 |
|---------------|----------|----------------|
| BOLA | `GET /workshop/api/mechanic/mechanic_report?report_id=X` | A01 |
| BOLA | `GET /identity/api/v2/vehicle/{vehicleId}/location` | A01 |
| BFLA | `DELETE /community/api/v2/community/posts/videos/{videoId}` | A05 |
| JWT forgery | Any authenticated endpoint | A02 |
| Mass assignment | Order/balance endpoints | A06 |
| NoSQL injection | `POST /community/api/v2/coupon/validate-coupon` | A03 |
| SQLi | Workshop coupon redemption | A03 |
| SSRF | Workshop service | A07 |
| Broken auth (OTP bypass) | Password reset OTP | A02 |
| LLM prompt injection | `/community/api/v2/community/posts/chatbot` | A10 |

---

## Known limitations

- The spec (`crapi-openapi-spec.json`) covers only the identity service (~30 paths)
- Community and workshop service paths require separate spec files
- Fuzzing the chatbot LLM endpoint requires manual interaction
- Account registration requires email confirmation — not fully automatable
