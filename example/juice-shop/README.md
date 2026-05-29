# shelob-ng / OWASP Juice Shop — worked example

A complete, ready-to-run walkthrough of shelob-ng against
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — an intentionally
vulnerable Node.js e-commerce application used for security training.

Covers **10 usage scenarios**. Every scenario shows the exact `shelob-ng`
command so you can run it without `make`.

---

## Contents

```
example/
  Makefile                    orchestrator — run `make help`
  config.env                  shared config: URLs, credentials, paths
  docker-compose.yml          standard Juice Shop (port 3000)
  docker-compose.csp.yml      Juice Shop + CSP sidecar (ports 3000 + 8080)
  juice-shop.openapi.json     OpenAPI spec (extracted from the running container)
  payloads/
    sqli.txt                  SQL injection payloads
    xss.txt                   XSS payloads
    ssti.txt                  Server-Side Template Injection payloads
    lfi.txt                   LFI / path traversal payloads
    nosql.txt                 NoSQL injection payloads
    cmdi.txt                  Command injection payloads
  csp/
    adapter.js                Node.js V8 Inspector CSP adapter
    Dockerfile                Juice Shop image with adapter pre-loaded
  scripts/                    one script per scenario (called by make run-N)
  results/                    created at runtime (.gitignore)
  corpus/                     created at runtime (.gitignore)
```

---

## Quick start

```bash
cd example/

make check    # verify prerequisites: Go ≥1.22, Docker, curl
make setup    # build fuzzer, start Juice Shop, create accounts, fetch spec
make run-8    # full 1-hour audit (DURATION_FULL=5m for a quick check)
make report   # print findings summary
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | ≥ 1.22 | Build shelob-ng |
| Docker + Compose v2 | ≥ 20.x | Run Juice Shop |
| `curl` | any | Account creation, health checks |
| `jq` | any | Pretty-print findings (optional) |

---

## One-time setup (manual, without make)

```bash
# 1. Build the fuzzer
cd example/..
go build -o shelob-ng .
cd example/

# 2. Start Juice Shop
docker compose up -d
# wait ~30 s, then verify:
curl http://localhost:3000/rest/admin/application-version

# 3. Create test accounts (Juice Shop uses in-memory SQLite — re-create after restart)
# Primary account (fuzzer)
curl -s -X POST http://localhost:3000/api/Users \
  -H 'Content-Type: application/json' \
  -d '{"email":"fuzzer@shelob.local","password":"Shelob1!",
       "passwordRepeat":"Shelob1!",
       "securityQuestion":{"id":1,"question":"Your eldest siblings middle name?"},
       "securityAnswer":"shelob"}'

# Secondary account (BOLA victim)
curl -s -X POST http://localhost:3000/api/Users \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@shelob.local","password":"Victim1!",
       "passwordRepeat":"Victim1!",
       "securityQuestion":{"id":2,"question":"Mother'"'"'s maiden name?"},
       "securityAnswer":"shelob"}'

# 4. Fetch the OpenAPI spec
curl -s http://localhost:3000/api-docs -o juice-shop.openapi.json
```

> **Note:** Docker restarts wipe the in-memory database. Re-run step 3 after
> every `docker compose restart` or `make start`.

---

## Scenario overview

| # | Name | Auth | Extra features | Duration |
|---|------|------|---------------|---------|
| 1 | Pure random | — | all checkers | 5 m |
| 2 | Authenticated | cookie login | all checkers | 5 m |
| 3 | BOLA detection | cookie login | NameSpaceRule, two users | 5 m |
| 4 | Payload injection | cookie login | SQLi/XSS/SSTI/LFI wordlists | 15 m |
| 5 | Coverage-guided | cookie login | CSP sidecar, corpus persistence | 15 m |
| 6 | Corpus persistence | cookie login | save → resume two runs | 5+5 m |
| 7 | Selective checkers | cookie login | three sub-scenarios | 5 m × 3 |
| 8 | Full audit | cookie + two users | all features simultaneously | 1 h |
| 9 | Bearer token auth | JWT `-token` | no cookie login | 5 m |
| 10 | LeakageRule verify | cookie login | LeakageRule only + analysis | 5 m |

---

## Scenario 1 — Pure random

No authentication. Tests every endpoint with random data and all six checkers.
Finds schema violations, stack traces, and server crashes without credentials.

### Run with make

```bash
make run-1
```

### Run manually

```bash
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -duration 5m \
  -output   results/01_pure_random
```

**Flags:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-spec` | `juice-shop.openapi.json` | OpenAPI 3.x spec; corpus is seeded from it |
| `-url` | `http://localhost:3000` | Target base URL |
| `-duration` | `5m` | Stop after 5 minutes |
| `-output` | `results/01_pure_random` | Write findings and coverage report here |

**Expected findings:**
- `SchemaViolation` — responses that do not match the declared schema
- `InvalidDynamicObject` — 500 on boundary IDs (`-1`, `0`, `null`, `""`)
- `BehavioralPatterns` — Node.js stack traces in 500 responses

---

## Scenario 2 — Authenticated

Logs in as the primary user before fuzzing. Session cookies unlock authenticated
endpoints (`/api/BasketItems`, `/rest/user/whoami`, …).

### Run with make

```bash
make run-2
```

### Run manually

```bash
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -duration 5m \
  -output   results/02_authenticated
```

**Flags:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-user` | `fuzzer@shelob.local` | Email for login; triggers auto-detection of the login endpoint |
| `-password` | `Shelob1!` | Password |

**How auth works:**
1. Scans the spec for a `POST` operation whose path matches `/login`, `/user/login`, or whose `operationId` contains `login` / `authenticate`
2. Sends `{"email": …, "password": …}` and reads `Set-Cookie` headers
3. Falls back to reading `authentication.token` / `access_token` from the response body
4. Attaches the cookie or synthetic token to every subsequent request

---

## Scenario 3 — BOLA / NameSpaceRule

Two accounts are used. For every request that returns 2xx for user1, the checker
replays it with user2's session. Cross-account access → **HIGH** finding.

### Run with make

```bash
make run-3
```

### Run manually

```bash
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -user2    victim@shelob.local \
  -pass2    Victim1! \
  -duration 5m \
  -output   results/03_bola
```

**Flags:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-user2` | `victim@shelob.local` | Second user; enables NameSpaceRule checker |
| `-pass2` | `Victim1!` | Password for the second user |

**Detection sequence (NameSpaceRule):**
1. User1 request → 2xx (resource exists and is owned)
2. Anonymous probe — strips all auth headers and cookies; if 2xx → public endpoint → skip
3. User2 probe — cookies from `-user2`/`-pass2` login + shared `X-Api-Key` if set;
   Bearer token is **not** forwarded (it would authenticate as user1); if 2xx → **BOLA HIGH**

**Expected findings:** User2 can read basket items and orders belonging to User1.

---

## Scenario 4 — Security payload injection

External wordlists are injected into every string-typed field: path params,
query params, headers, cookies, and JSON body leaf nodes.

### Run with make

```bash
make run-4
```

### Run manually

```bash
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -payloads sqli=payloads/sqli.txt,xss=payloads/xss.txt,\
            ssti=payloads/ssti.txt,lfi=payloads/lfi.txt,\
            nosql=payloads/nosql.txt,cmdi=payloads/cmdi.txt \
  -duration 15m \
  -output   results/04_payloads
```

**Flags:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-payloads` | `key=path,…` | Comma-separated `name=filepath` pairs; activates `securityMutator` |

**Payload files used:**

| File | Technique |
|------|-----------|
| `payloads/sqli.txt` | Boolean, union, error-based, time-based injection |
| `payloads/xss.txt` | `<script>`, event handlers, JS URI, encoded variants |
| `payloads/ssti.txt` | Jinja2, Twig, Freemarker, Handlebars, ERB |
| `payloads/lfi.txt` | `../etc/passwd`, Windows paths, URL-encoded traversal |
| `payloads/nosql.txt` | `$ne`, `$gt`, `$where`, MongoDB operator injection |
| `payloads/cmdi.txt` | `; id`, `\| whoami`, backtick injection |

**Extend payloads from PayloadsAllTheThings:**
```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /tmp/patt
cat "/tmp/patt/SQL Injection/Intruder/SQL_Bypass.txt" >> payloads/sqli.txt
cat "/tmp/patt/XSS Injection/Intruder/XSS Polyglots.txt" >> payloads/xss.txt
```

**Expected findings:** SQL error text (`SQLITE_ERROR`) in `/rest/products/search?q=<payload>`.

---

## Scenario 5 — Coverage-guided (CSP)

Requires the CSP-instrumented Juice Shop image. Inputs that reach new V8 basic
blocks are saved to the corpus and preferentially re-mutated.

### Run with make

```bash
# One-time: build the CSP image
docker compose -f docker-compose.yml -f docker-compose.csp.yml build

# Start Juice Shop + CSP sidecar (ports 3000 and 8080)
make start-csp

# Run the scenario
make run-5
```

### Run manually

```bash
# 1. Build and start the CSP-instrumented image
docker compose -f docker-compose.yml -f docker-compose.csp.yml up -d

# 2. Wait for both services
curl http://localhost:3000/rest/admin/application-version   # Juice Shop
curl -X POST http://localhost:8080/csp/reset                # CSP sidecar

# 3. Create accounts (if needed)
curl -s -X POST http://localhost:3000/api/Users \
  -H 'Content-Type: application/json' \
  -d '{"email":"fuzzer@shelob.local","password":"Shelob1!",
       "passwordRepeat":"Shelob1!",
       "securityQuestion":{"id":1,"question":"Your eldest siblings middle name?"},
       "securityAnswer":"shelob"}'

# 4. Run the fuzzer
./shelob-ng \
  -spec       juice-shop.openapi.json \
  -url        http://localhost:3000 \
  -user       fuzzer@shelob.local \
  -password   Shelob1! \
  -csp-url    http://localhost:8080 \
  -corpus-dir corpus/csp \
  -duration   15m \
  -output     results/05_coverage
```

**Flags:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-csp-url` | `http://localhost:8080` | Coverage Sidecar Protocol endpoint; enables coverage-guided mode |
| `-corpus-dir` | `corpus/csp` | Save corpus to disk for resumption |

**How CSP works per request:**
```
POST /csp/reset   → snapshot current V8 coverage as baseline
<Juice Shop handles the fuzzer request>
GET  /csp/dump    → returns new_since_reset[] = blocks executed − baseline
delta = len(new_since_reset)
if delta > 0 → corpus.Add(entry, weight=delta) → NEW event on display
```

**Display with CSP enabled:**
```
#7       NEW      cov:    87  corpus:   177  ops:   7/95   req/s:    24  …  [GET /api/Addresss/{id}  +14]
#16      NEW      cov:   109  corpus:   179  ops:   9/95   req/s:    24  …  [POST /api/Baskets  +19]
```

---

## Scenario 6 — Corpus persistence

Saves the corpus after run 1 and reloads it at the start of run 2, resuming
from the most interesting discovered inputs.

### Run with make

```bash
make run-6
```

### Run manually

```bash
mkdir -p corpus/scenario6

# Run 1 — build corpus
./shelob-ng \
  -spec       juice-shop.openapi.json \
  -url        http://localhost:3000 \
  -user       fuzzer@shelob.local \
  -password   Shelob1! \
  -corpus-dir corpus/scenario6 \
  -duration   5m \
  -output     results/06_corpus_run1

# Run 2 — load saved corpus, continue
./shelob-ng \
  -spec       juice-shop.openapi.json \
  -url        http://localhost:3000 \
  -user       fuzzer@shelob.local \
  -password   Shelob1! \
  -corpus-dir corpus/scenario6 \
  -duration   5m \
  -output     results/06_corpus_run2
```

**Flags:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-corpus-dir` | `corpus/scenario6` | Save corpus on exit; load on start if the directory already exists |

**Corpus on disk:**
```
corpus/scenario6/
  index.json           {"version":1, "entry_count":243, ...}
  entries/
    3a7f2c8b....json   {"method":"POST","path_pattern":"/api/Users",...,
                        "coverage_delta":14,"use_count":3,"generation":7}
```

Run 2 starts with the message:
```
INFO: corpus: 243 entries total after loading from ./corpus/scenario6
```

---

## Scenario 7 — Selective checkers

Runs one specific checker at a time to isolate findings by bug class.
The script runs three sub-scenarios in sequence.

### Run with make

```bash
make run-7
```

### Run manually

**7a — Schema violations only** (zero extra HTTP requests, fastest):

```bash
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -checker  SchemaViolation \
  -duration 5m \
  -output   results/07a_schema
```

**7b — Behavioral patterns with payload injection:**

```bash
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -checker  BehavioralPatterns \
  -payloads sqli=payloads/sqli.txt,xss=payloads/xss.txt \
  -duration 5m \
  -output   results/07b_behavioral
```

**7c — Stateful resource lifecycle (UseAfterFree + InvalidDynamicObject):**

```bash
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -checker  UseAfterFree,InvalidDynamicObject \
  -duration 5m \
  -output   results/07c_stateful
```

**Flag:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-checker` | comma-separated names | Enable only listed checkers; empty string = all |

**Valid checker names:**
`BehavioralPatterns`, `UseAfterFree`, `InvalidDynamicObject`,
`LeakageRule`, `NameSpaceRule`, `SchemaViolation`

| Sub-scenario | Checker | Extra HTTP probes | Use when |
|---|---|---|---|
| 7a | `SchemaViolation` | 0 | Fast API contract check |
| 7b | `BehavioralPatterns` | 0 | Injection artifact hunting |
| 7c | `UseAfterFree,InvalidDynamicObject` | 1–5 per request | Resource lifecycle |

---

## Scenario 8 — Full audit

All features enabled simultaneously: two users, payloads, CSP coverage, corpus
persistence, all six checkers.

### Run with make

```bash
DURATION_FULL=5m make run-8   # quick check
make run-8                     # recommended: 1 hour
```

### Run manually

```bash
# Requires CSP-instrumented image (see Scenario 5 for build steps)
# and two accounts created (see One-time setup above)

./shelob-ng \
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

**All flags active:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-user` / `-password` | fuzzer credentials | Cookie-based auth for all requests |
| `-user2` / `-pass2` | victim credentials | Enables NameSpaceRule (BOLA) checker |
| `-payloads` | 6 wordlists | Enables securityMutator; injects into all string fields |
| `-csp-url` | `:8080` | Coverage-guided mode; requires `make start-csp` |
| `-corpus-dir` | `corpus/full` | Persist corpus; resume across runs |

**Expected output (5-minute run):**
```
DONE  #8423  cov: 51204  corpus: 1831  ops: 93/95 (97%)  req/s: 27.4  findings: 154  elapsed: 5m0s
=== API spec coverage: 93/95 reached (97%), 26/95 succeeded (2xx) ===
```

---

## Scenario 9 — Bearer token authentication

Demonstrates the `-token` flag. A JWT is obtained from Juice Shop's login
endpoint and passed to the fuzzer directly — no cookie login step at all.
Every request, including all checker probe requests, carries
`Authorization: Bearer <token>`.

### Run with make

```bash
make run-9
```

The script auto-creates the account if Juice Shop was restarted and the
in-memory database was wiped.

### Run manually

```bash
# Step 1: obtain a JWT
JWT=$(curl -s -X POST http://localhost:3000/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"fuzzer@shelob.local","password":"Shelob1!"}' \
  | python3 -c "import json,sys; d=json.load(sys.stdin); \
      print((d.get('authentication') or {}).get('token',''))")

# If empty, create the account first:
if [ -z "$JWT" ]; then
  curl -s -X POST http://localhost:3000/api/Users \
    -H 'Content-Type: application/json' \
    -d '{"email":"fuzzer@shelob.local","password":"Shelob1!",
         "passwordRepeat":"Shelob1!",
         "securityQuestion":{"id":1,"question":"Your eldest siblings middle name?"},
         "securityAnswer":"shelob"}'
  JWT=$(curl -s -X POST http://localhost:3000/rest/user/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"fuzzer@shelob.local","password":"Shelob1!"}' \
    | python3 -c "import json,sys; d=json.load(sys.stdin); \
        print((d.get('authentication') or {}).get('token',''))")
fi

# Step 2: verify the token
curl -s -o /dev/null -w "whoami: HTTP %{http_code}\n" \
  -H "Authorization: Bearer $JWT" \
  http://localhost:3000/rest/user/whoami

# Step 3: run the fuzzer
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -token    "$JWT" \
  -duration 5m \
  -output   results/09_bearer_token
```

**Flag:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-token` | `eyJ…` | Sets `Authorization: Bearer <value>` on every request and checker probe, except the `NameSpaceRule` user2 probe (which must not carry user1's identity) |

**When to use `-token` instead of `-user`/`-password`:**
- The target uses stateless JWT-only auth (no `Set-Cookie` response header)
- You have a pre-obtained long-lived service account token (CI/CD environment)
- You want to fuzz with an admin token while cookie login would give a regular user session

**Expected coverage:** `~49/95 succeeded (2xx)` — more than cookie-only auth
(`26/95`) because Bearer auth is accepted on more endpoints without needing
pre-created resources.

---

## Scenario 10 — LeakageRule false-positive verification

Verifies that `LeakageRule` does not fire false positives. Two classes of
POST responses are now silently skipped:
- **401** — auth middleware rejected the request before any logic ran
- **Collection endpoints** (no path parameters in the spec entry) — `POST /collection`
  followed by `GET /collection → 200` is expected REST behaviour, not a leak

### Run with make

```bash
make run-10
```

### Run manually

```bash
# Step 1: run with LeakageRule only
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -checker  LeakageRule \
  -duration 5m \
  -output   results/10_leakage_verify

# Step 2: analyse findings
# The checker now skips 401 responses and collection endpoints (no path params)
# at the checker level, so any findings that reach the output are candidates
# for genuine leakage. Only 401-triggered findings would be false positives.
python3 - results/10_leakage_verify << 'EOF'
import json, os, sys, glob, re

out_dir = sys.argv[1]
files   = sorted(glob.glob(os.path.join(out_dir, 'findings', '*.json')))

if not files:
    print("No LeakageRule findings — PASS")
    sys.exit(0)

false_positives = []
real_findings   = []
for path in files:
    with open(path) as f:
        d = json.load(f)
    m = re.search(r'returned (\d+) \(rejected\)', d.get('detail',''))
    code = int(m.group(1)) if m else 0
    # Only 401 is a false positive: auth rejected before logic ran.
    # 403 on singleton endpoints is a valid trigger (post-write ownership check).
    (false_positives if code == 401 else real_findings).append((code, d['url']))

if false_positives:
    print(f"FAIL: {len(false_positives)} false positive(s) from 401 triggers:")
    for code, url in false_positives:
        print(f"  [{code}] {url}")
else:
    print("PASS: no false positives (401 auth rejections are correctly excluded)")

if real_findings:
    print(f"\nFindings ({len(real_findings)}) — singleton endpoints with committed state:")
    for code, url in real_findings:
        print(f"  [{code}] {url}")
EOF
```

**Flag:**

| Flag | Value | Purpose |
|------|-------|---------|
| `-checker` | `LeakageRule` | Run only this checker; isolates its findings |

**What is skipped and why:**

| Trigger | Reason skipped |
|---------|---------------|
| `POST /api/Feedbacks → 401` | Auth middleware rejected before any DB write — no state committed |
| `POST /api/Feedbacks → 403` on collection (no `{id}` in path) | Collection endpoint; `GET /api/Feedbacks → 200` is a public read, not a leaked resource |
| `POST /api/Users/{id} → 403` on singleton | NOT skipped — handler may have written then checked ownership → genuine finding |
| `POST /api/Something → 400` or `422` on singleton | NOT skipped — validation failure after write → genuine finding |

**Expected output:**
```
PASS: zero findings triggered by 401/403 (auth rejections correctly excluded)
```

---

## Expected findings (5-minute full run)

| Checker | Typical count | Representative finding |
|---------|--------------|----------------------|
| `SchemaViolation` | ~74 | Response body missing declared fields |
| `BehavioralPatterns` | ~55 | Node.js stack trace in 500 response |
| `InvalidDynamicObject` | ~20 | `DELETE /api/Addresss/` → 500 (empty path param) |
| `LeakageRule` | 0–2 | POST 4xx on singleton endpoint (with path params) leaves readable state |
| `PathDiscovery` | 1–3 | `/metrics` — Prometheus endpoint unauthenticated (J20) |
| `RateLimitChecker` | 3–8 | `/rest/user/login` — HIGH: 8 rapid requests, none returned 429 |
| `MassAssignment` | 1–3 | `POST /api/Users` — fields `role:admin` accepted without 422 |

**High-severity finding (reproducible):**
```
Checker:   BehavioralPatterns
Severity:  HIGH
Operation: GET /rest/products/search

POC:
curl -v -X GET 'http://localhost:3000/rest/products/search?q=%00'
```

`%00` (null byte) reaches the SQLite query unescaped → `SQLITE_ERROR` leaks
in the response body, confirming missing input sanitisation.

---

## New Checkers — Juice Shop Integration

### PathDiscovery (runs automatically before fuzzing loop)

Juice Shop exposes several endpoints not in the main spec:

| Path | Finding | Juice Shop challenge |
|------|---------|---------------------|
| `/metrics` | HIGH — Prometheus metrics unauthenticated | Exposed Metrics (J20) |
| `/ftp` | MEDIUM — file server accessible | Confidential Document (J17) |
| `/support/logs` | MEDIUM — access logs exposed | Access Log challenge |
| `/security.txt` | INFO — security policy | Security Policy challenge |

```bash
# Extend PathDiscovery with Juice Shop-specific paths:
cat > /tmp/juice-shop-paths.txt << 'EOF'
/ftp                    FTP-style file server with customer data
/ftp/acquisitions.md    Confidential acquisition document
/support/logs           Support log files
/video                  Promotional video endpoint
EOF

./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local -password Shelob1! \
  -path-wordlist /tmp/juice-shop-paths.txt \
  -csp-disable -duration 5m -output results/pathscan_extended
```

### RateLimitChecker

Juice Shop has no rate limiting on any endpoint.

| Endpoint | Finding severity | Challenge |
|---------|-----------------|---------|
| `POST /rest/user/login` | **HIGH** | Password Strength (brute-forceable) |
| `POST /api/Users` | **HIGH** | Registration brute-force |
| `POST /rest/user/reset-password` | **HIGH** | OTP bypass |
| All others | MEDIUM | General rate limit absence |

### MassAssignment

Juice Shop vulnerable endpoints:

```bash
# J13: Admin Registration — add "role":"admin" to POST /api/Users
curl -X POST http://localhost:3000/api/Users \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@test.com","password":"Test1!","passwordRepeat":"Test1!",
       "role":"admin",
       "securityQuestion":{"id":1,"question":"?"},"securityAnswer":"x"}'
# MassAssignment checker: sends this automatically and checks if role:admin appears in response

# J16: Forged Feedback — inject UserId
curl -X POST http://localhost:3000/api/Feedbacks \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $JWT" \
  -d '{"comment":"test","rating":5,"UserId":1}'
# Sends as another user's feedback
```

### SSRF Mutator

Juice Shop doesn't have obvious URL-accepting fields in its spec, so SSRF mutator
returns `StrategyNotApplicable` for most requests. However, image upload endpoints
(`/profile/image/url`) accept URL values — SSRF payloads will be injected there.

---

## API spec coverage report

Written automatically to `results/<scenario>/api-coverage.json` after each run:

```json
{
  "total":           95,
  "visited_count":   93,
  "succeeded_count": 26,
  "unvisited_count":  2,
  "unvisited": [
    {"method": "DELETE", "path": "/api/Cards/{id}"},
    {"method": "GET",    "path": "/rest/user/authentication-details"}
  ]
}
```

- `visited_count` — endpoints that received any HTTP response
- `succeeded_count` — endpoints that returned at least one 2xx response

The gap between the two reveals endpoints that never executed successfully
(most common causes: auth required but not provided, or randomly generated
data fails database constraints).

---

## Code coverage report (CSP only)

After scenario 5 or 8, generate an HTML line-coverage report from the
accumulated V8 profiler data:

```bash
make coverage-report
# → coverage.html (open in browser)
```

---

## Working with findings

```bash
# List all unique findings
ls results/08_full/findings/

# Pretty-print one finding (includes POC curl command)
jq . results/08_full/findings/BehavioralPatterns_GET__rest_products_search.json

# Count by checker across all scenarios
jq -r '.checker' results/*/findings/*.json | sort | uniq -c | sort -rn

# Extract all POC commands ready to paste
jq -r 'select(.poc) | "# \(.checker): \(.title)\n" + .poc + "\n"' \
   results/08_full/findings/*.json

# Show coverage summary
jq '{reached: .visited_count, succeeded: .succeeded_count, total: .total}' \
   results/08_full/api-coverage.json

# Reproduce the HIGH SQLi finding
curl -v 'http://localhost:3000/rest/products/search?q=%00'
```

---

## Finding file format

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

One file per unique `(checker, method, path_pattern)` — re-running overwrites
rather than duplicating.

## Sequence replay format

Written to `results/<scenario>/replays/` when a stateful CRUD sequence finds a bug:

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
  "findings": [{"title":"Resource accessible after DELETE","severity":"high"}]
}
```
