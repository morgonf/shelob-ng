# shelob-ng / OWASP Juice Shop — worked example

A complete, ready-to-run walkthrough of shelob-ng against
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — an intentionally
vulnerable Node.js e-commerce application used for security training.

Covers **all 8 usage scenarios** from a quick smoke test to a full 1-hour audit.

---

## Contents

```
example/
  Makefile                    orchestrator — run `make help`
  config.env                  shared config: URLs, credentials, paths
  docker-compose.yml          standard Juice Shop (port 3000)
  docker-compose.csp.yml      Juice Shop + CSP sidecar (ports 3000 + 8080)
  juice-shop.openapi.json     OpenAPI spec extracted from the running container
  payloads/
    sqli.txt                  SQL injection payloads (boolean, union, error, time-based, NoSQL)
    xss.txt                   XSS payloads (reflected, DOM, filter bypass, polyglots)
    ssti.txt                  SSTI payloads (Jinja2, Twig, Handlebars, ERB, Velocity)
    lfi.txt                   LFI / path traversal payloads
    nosql.txt                 NoSQL injection payloads (MongoDB operators)
    cmdi.txt                  Command injection payloads
  csp/
    adapter.js                Node.js V8 Inspector CSP adapter
    Dockerfile                Juice Shop image with the adapter pre-loaded
  scripts/
    00_check.sh               prerequisite check (Go, Docker, curl)
    01_setup.sh               first-time setup
    02_scenario_pure_random.sh
    03_scenario_authenticated.sh
    04_scenario_bola.sh
    05_scenario_payloads.sh
    06_scenario_coverage.sh
    07_scenario_corpus.sh
    08_scenario_checkers.sh
    09_scenario_full.sh
    10_report.sh              aggregate findings report
    11_coverage_report.sh     HTML code-coverage report via c8
  results/                    created at runtime (in .gitignore)
  corpus/                     created at runtime (in .gitignore)
```

---

## Quick start (4 commands)

```bash
cd example/

make check    # verify prerequisites
make setup    # build fuzzer, start Juice Shop, create accounts
make run-8    # 1-hour full audit (use DURATION_FULL=5m for a quick check)
make report   # print findings summary
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | ≥ 1.22 | Build shelob-ng |
| Docker | ≥ 20.x | Run Juice Shop |
| Docker Compose v2 | | Orchestrate containers |
| `curl` | any | Account creation, health checks |
| `jq` | any | Pretty-print findings in report (optional) |

```bash
make check    # verifies all of the above
```

---

## Scenario overview

| # | Name | Features active | Default duration |
|---|------|----------------|-----------------|
| 1 | Pure random | all checkers, no auth | 5 m |
| 2 | Authenticated | session cookie login | 5 m |
| 3 | BOLA | two users, NameSpaceRule | 5 m |
| 4 | Payload injection | SQLi/XSS/SSTI/LFI wordlists | 15 m |
| 5 | Coverage-guided | CSP sidecar + corpus | 15 m |
| 6 | Corpus persistence | save → resume across two runs | 5+5 m |
| 7 | Selective checkers | three sub-scenarios | 5 m × 3 |
| 8 | Full | everything simultaneously | 1 h |

Override the duration at any time:

```bash
DURATION_QUICK=2m DURATION_STANDARD=5m DURATION_FULL=10m make run-all
```

---

## Scenario 1 — Pure random

Tests the fuzzer without authentication. Finds schema violations, server
crashes on boundary inputs, and stack traces in error responses.

```bash
make run-1
# equivalent:
../shelob-ng -spec juice-shop.openapi.json -url http://localhost:3000 \
    -duration 5m -output results/01_pure_random
```

**Expected findings:**
- `SchemaViolation` — response bodies that do not match the OpenAPI schema
- `InvalidDynamicObject` — 500 responses on `id=-1`, `id=0`, `id=null`, `id=""`
- `BehavioralPatterns` — Node.js stack traces in 500 responses

---

## Scenario 2 — Authenticated

Logs in as `fuzzer@shelob.local` before fuzzing. Session cookies are attached
to every request, unlocking authenticated endpoints.

```bash
make run-2
```

**How auth works:**
1. `auth` package detects `POST /rest/user/login` from the spec
2. Sends `{"email": …, "password": …}` and reads `Set-Cookie` headers
3. If no `Set-Cookie`, reads the JSON body for `authentication.token`,
   `data.token`, `access_token` etc. and synthesises a cookie
4. All subsequent fuzzer requests carry the cookie

**Additional endpoints reached:** `/api/BasketItems`, `/api/Orders`,
`/rest/user/whoami`, `/rest/user/change-password`, …

---

## Scenario 3 — BOLA / NameSpaceRule

Uses two accounts to detect Broken Object Level Authorization
(OWASP API Security Top 10 — #1).

```bash
make run-3
```

**Detection sequence for each 2xx response by user1:**
1. Anonymous probe (no cookies) — if 2xx, endpoint is public → skip
2. User2 probe — if 2xx → **HIGH: BOLA/IDOR**

**Expected findings:** User2 can read basket items owned by User1
(`/api/BasketItems/{id}`, `/api/Baskets/{id}`).

---

## Scenario 4 — Security payload injection

Injects external wordlists into all string-typed fields.

```bash
make run-4
```

**Payload files used:**
| File | Technique |
|------|-----------|
| `payloads/sqli.txt` | Boolean, union, error-based, time-based, NoSQL |
| `payloads/xss.txt` | `<script>`, event handlers, JS URI, encoded variants |
| `payloads/ssti.txt` | Jinja2, Twig, Freemarker, Handlebars, ERB |
| `payloads/lfi.txt` | `../etc/passwd`, Windows paths, URL-encoded traversal |
| `payloads/nosql.txt` | `$ne`, `$gt`, `$where`, operator injection |
| `payloads/cmdi.txt` | `; id`, `| whoami`, backtick injection |

**Extend with PayloadsAllTheThings:**
```bash
DOWNLOAD_PATT=1 make setup
# appends PayloadsAllTheThings SQL_Bypass.txt → sqli.txt
#         and XSS Polyglots.txt              → xss.txt
```

**Expected findings:** SQL error text in `/rest/products/search?q=<payload>`
responses when the payload reaches the SQLite query without sanitisation.

---

## Scenario 5 — Coverage-guided (CSP)

Runs shelob-ng with the Coverage Sidecar Protocol. Inputs that reach new
V8 basic blocks are saved to the corpus with a weight proportional to the
coverage delta.

**Requires the CSP-instrumented Juice Shop image (one-time build):**

```bash
docker compose -f docker-compose.yml -f docker-compose.csp.yml build
make start-csp   # start Juice Shop on :3000 + CSP adapter on :8080
make run-5
```

**How the CSP adapter works:**

```
adapter.js is loaded via NODE_OPTIONS="--require ./adapter.js"
    │
    ▼
V8 Inspector: Profiler.startPreciseCoverage({ callCount: true, detailed: true })
    │
POST /csp/reset ────────────────────▶ baseline = current V8 coverage snapshot
<Juice Shop processes the fuzzer request>
GET  /csp/dump  ────────────────────▶ new_since_reset = current − baseline
    │                                 (file:byteOffset strings for each
    │                                  newly executed basic block)
    ▼
shelob-ng: if len(new_since_reset) > 0
             → corpus.Add(entry, delta=len(new_since_reset))
             → display "NEW" event
```

The `cov:` column in the display counts cumulative unique blocks discovered.
Entropy naturally declines over time as the corpus saturates reachable paths.

**Display with CSP enabled:**
```
#8      NEW      cov:    52  corpus:   179  ops:   8/95   req/s:    24  …  [POST /api/SecurityAnswers  +18]
#16     NEW      cov:    66  corpus:   180  ops:   9/95   req/s:    24  …  [DELETE /api/BasketItems/{id}  +14]
#512    pulse    cov:  6831  corpus:   721  ops:  87/95   req/s:    27  …
```

---

## Scenario 6 — Corpus persistence

Demonstrates saving and loading the corpus across two runs.

```bash
make run-6
```

**Run 1** builds corpus, saves it to `corpus/scenario6/`:
```
corpus/scenario6/
  index.json           {"version":1,"entry_count":243,...}
  entries/
    3a7f2c8b....json   CorpusEntry JSON files
```

**Run 2** loads the saved corpus and continues from where run 1 left off:
```
INFO: corpus: 243 entries total after loading from ./corpus/scenario6
```

The corpus retains `CoverageDelta` and `UseCount` for each entry, so
high-value inputs (which opened many new code paths) keep their priority.

---

## Scenario 7 — Selective checkers

Three sub-scenarios, each enabling a single checker to isolate its findings.

```bash
make run-7
```

| Sub-scenario | Flag | Extra HTTP requests | Use when |
|-------------|------|-------------------|---------|
| 7a | `-checker SchemaViolation` | 0 | Fast API contract check |
| 7b | `-checker BehavioralPatterns -payloads sqli=…,xss=…` | 0 | Injection hunting |
| 7c | `-checker UseAfterFree,InvalidDynamicObject` | 1–5 per request | Resource lifecycle |

---

## Scenario 8 — Full audit

All features active simultaneously.

```bash
# Quick check (5 minutes)
DURATION_FULL=5m make run-8

# Full audit (recommended: 1 hour+)
make run-8
```

Full command (expanded):
```bash
../shelob-ng \
  -spec       juice-shop.openapi.json \
  -url        http://localhost:3000 \
  -user       fuzzer@shelob.local \
  -password   Shelob1! \
  -user2      victim@shelob.local \
  -pass2      Victim1! \
  -payloads   sqli=payloads/sqli.txt,xss=payloads/xss.txt,\
              ssti=payloads/ssti.txt,lfi=payloads/lfi.txt,\
              nosql=payloads/nosql.txt,cmdi=payloads/cmdi.txt \
  -csp-url    http://localhost:8080 \
  -corpus-dir corpus/full \
  -duration   1h \
  -output     results/08_full
```

**Expected terminal output:**
```
INFO: spec: juice-shop.openapi.json
INFO: target: http://localhost:3000
INFO: coverage: http://localhost:8080 (CSP)
INFO: corpus: 171 seed entries
INFO: checkers: BehavioralPatterns UseAfterFree InvalidDynamicObject LeakageRule NameSpaceRule SchemaViolation

#0       INITED   cov:     0  corpus:   171  ops:   0/95   req/s:     0  2xx:     0  4xx:     0  5xx:     0
#2       NEW      cov:    14  corpus:   172  ops:   2/95   req/s:     0  2xx:     0  4xx:     2  5xx:     0  [POST /api/Cards  +14]
#9       FINDING  cov:   110  corpus:   179  ops:   9/95   req/s:     0  2xx:     2  4xx:     6  5xx:     1  [BehavioralPatterns/medium] Node.js Stack Trace  http://…/api/Quantitys/
#16      pulse    cov:   174  corpus:   183  ops:  14/95   req/s:     0  2xx:     5  4xx:     7  5xx:     4
…

DONE    #8423    cov: 51204  corpus:  1831  ops: 93/95 (97%)  req/s:  27.4  findings:  154  elapsed: 5m0s

=== API spec coverage: 93/95 reached (97%), 26/95 succeeded (2xx) ===
```

---

## Expected findings (5-minute run, run-8)

| Checker | Count | Representative example |
|---------|-------|----------------------|
| `SchemaViolation` | 74 | Response body contains undeclared fields |
| `BehavioralPatterns` | 55 | Node.js stack trace in 500 response body |
| `InvalidDynamicObject` | 20 | `DELETE /api/Addresss/` → 500 (empty path param) |
| `LeakageRule` | 5 | Public collection accessible after auth-required POST |

**High-severity finding — SQL error leakage:**
```
Checker:   BehavioralPatterns
Severity:  HIGH
Title:     SQL Error Leakage
Operation: GET /rest/products/search
Detail:    pattern matched: SQLITE_ERROR

POC:
curl -v -X GET 'http://localhost:3000/rest/products/search?q=%00'
```

Sending a null byte (`%00`) as the `q` parameter causes Juice Shop to return
an `SQLITE_ERROR` string in the response — leaking the database engine type
and confirming that the query reached the database without sanitisation.

---

## API spec coverage report

After each run, shelob-ng writes `results/<scenario>/api-coverage.json`:

```json
{
  "total":           95,
  "visited_count":   93,
  "succeeded_count": 26,
  "unvisited_count":  2,
  "visited": [ … ],
  "unvisited": [
    {"method": "DELETE", "path": "/api/Cards/{id}"},
    {"method": "GET",    "path": "/rest/user/authentication-details"}
  ]
}
```

- `visited_count` — operations that received any HTTP response (97%)
- `succeeded_count` — operations with at least one 2xx response (27%)

The gap between reached and succeeded shows which endpoints never returned a
valid response (most common cause: lack of authentication or invalid generated
data not satisfying database constraints). These endpoints are the most
interesting targets for deeper investigation.

---

## Code coverage report (CSP only)

After a coverage-guided run, generate an HTML report:

```bash
make coverage-report
# opens coverage.html in the current directory
```

The report is generated by `c8` from the accumulated V8 profiler data
returned by `GET /csp/v8report`. It shows line-by-line coverage across
all Juice Shop source files.

---

## Working with findings

```bash
# List all unique findings (one file per unique issue)
ls results/08_full/findings/

# Pretty-print a finding (includes POC)
jq . results/08_full/findings/BehavioralPatterns_GET__rest_products_search.json

# Count by checker
jq -r '.checker' results/08_full/findings/*.json | sort | uniq -c | sort -rn

# Extract all POC curl commands
jq -r 'select(.poc) | "# \(.checker): \(.title)\n" + .poc + "\n"' \
   results/08_full/findings/*.json

# Show API coverage summary
jq '{reached: .visited_count, succeeded: .succeeded_count, total: .total}' \
   results/08_full/api-coverage.json

# Reproduce the HIGH finding manually
curl -v -X GET 'http://localhost:3000/rest/products/search?q=%00'
```

---

## Finding file format

Every finding is written as a single JSON file named after its dedup key
(`checker_METHOD_path_pattern.json`). The same key is never written twice in
one session — re-running the fuzzer overwrites the file with the latest evidence.

```json
{
  "checker":      "BehavioralPatterns",
  "severity":     "high",
  "title":        "SQL Error Leakage",
  "detail":       "pattern matched: SQLITE_ERROR",
  "method":       "GET",
  "url":          "http://localhost:3000/rest/products/search?q=%00",
  "status_code":  500,
  "path_pattern": "/rest/products/search",
  "poc":          "curl -v -X GET 'http://localhost:3000/rest/products/search?q=%00'"
}
```

## Replay file format

Sequence findings write a `replays/` file with all steps recorded:

```json
{
  "sequence":    "CRUD:/api/Users",
  "executed_at": "2026-05-28T06:00:00Z",
  "steps": [
    {"method":"POST",   "url":"…/api/Users",   "status_code":201, "extracted":{"id":"7"}},
    {"method":"GET",    "url":"…/api/Users/7",  "status_code":200},
    {"method":"DELETE", "url":"…/api/Users/7",  "status_code":200},
    {"method":"GET",    "url":"…/api/Users/7",  "status_code":200}
  ],
  "findings": [
    {
      "title":      "Resource accessible after DELETE",
      "severity":   "high",
      "method":     "GET",
      "url":        "…/api/Users/7",
      "status_code": 200
    }
  ]
}
```
