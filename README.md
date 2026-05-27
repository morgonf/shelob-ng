# shelob-ng

Coverage-guided REST API fuzzer based on [Shelob](../shelob/), extended with:

- **AFL-style corpus** — inputs that increase code coverage are saved, weighted, and mutated
- **Three mutation strategies** — structural (type-aware), byte-level (bit/byte flips), security payloads (SQLi/XSS wordlists)
- **Coverage Sidecar Protocol (CSP)** — language-agnostic HTTP endpoint for coverage feedback from any target
- **Six security checkers** — modular detectors inspired by RESTler
- **Stateful CRUD sequences** — automatically built from the OpenAPI spec, detect UseAfterFree and BOLA

---

## Table of contents

1. [Quick start](#quick-start)
2. [Juice Shop guide](#juice-shop-guide) ← ready-to-run instructions
3. [Architecture](#architecture)
4. [Fuzzing loop](#fuzzing-loop)
5. [Corpus and selection](#corpus-and-selection)
6. [Mutation strategies](#mutation-strategies)
7. [Security checkers](#security-checkers)
8. [Stateful sequence testing](#stateful-sequence-testing)
9. [Status display](#status-display)
10. [Output format](#output-format)
11. [All flags](#all-flags)
12. [Coverage Sidecar Protocol](#coverage-sidecar-protocol)

---

## Quick start

```bash
# Build
go build -o shelob-ng .

# Pure-random mode — no target instrumentation required
./shelob-ng -spec openapi.json -url http://localhost:3000

# With authentication and BOLA detection
./shelob-ng -spec openapi.json -url http://localhost:3000 \
    -user admin@juice-sh.op -password admin123 \
    -user2 user@juice-sh.op -pass2 password

# With security payload wordlists
./shelob-ng -spec openapi.json -url http://localhost:3000 \
    -payloads sqli=/tmp/sqli.txt,xss=/tmp/xss.txt \
    -duration 30m -output ./results

# Coverage-guided mode (requires CSP adapter on the target)
./shelob-ng -spec openapi.json -url http://localhost:3000 \
    -csp-url http://localhost:8080
```

---

## Juice Shop guide

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) is the canonical
vulnerable Node.js application used for security training. This guide walks
through running shelob-ng against it end-to-end.

### Step 1 — Start Juice Shop

**Option A: Docker (recommended)**
```bash
docker pull bkimminich/juice-shop
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```

**Option B: Node.js**
```bash
git clone https://github.com/juice-shop/juice-shop
cd juice-shop
npm install
npm start
# Juice Shop listens on http://localhost:3000
```

Verify it is running:
```bash
curl -s http://localhost:3000/rest/admin/application-configuration | head -c 80
# Should return JSON, not a connection error
```

### Step 2 — Get the OpenAPI spec

Juice Shop ships a Swagger spec at the `/api-docs` endpoint:
```bash
curl http://localhost:3000/api-docs -o juice-shop.openapi.json
```

Alternatively, the community maintains a maintained copy at:
`https://github.com/OWASP/www-project-juice-shop/blob/master/docs/api_specs/`

### Step 3 — Create test accounts

Juice Shop has a `/api/Users` registration endpoint. Create two accounts
(one for fuzzing, one for BOLA testing):

```bash
# Account 1 — primary fuzzer user
curl -s -X POST http://localhost:3000/api/Users \
  -H 'Content-Type: application/json' \
  -d '{"email":"fuzzer@test.local","password":"Fuzzer1!","passwordRepeat":"Fuzzer1!","securityQuestion":{"id":1,"question":"Your eldest siblings middle name?"},"securityAnswer":"test"}' \
  | python3 -m json.tool

# Account 2 — second user for BOLA detection
curl -s -X POST http://localhost:3000/api/Users \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@test.local","password":"Victim1!","passwordRepeat":"Victim1!","securityQuestion":{"id":1,"question":"Your eldest siblings middle name?"},"securityAnswer":"test"}' \
  | python3 -m json.tool
```

### Step 4 — (Optional) Prepare payload wordlists

```bash
mkdir -p /tmp/payloads

# SQL injection payloads
cat > /tmp/payloads/sqli.txt << 'EOF'
' OR '1'='1
' OR 1=1--
'; DROP TABLE users;--
1' ORDER BY 1--
1 UNION SELECT null,null,null--
admin'--
EOF

# XSS payloads
cat > /tmp/payloads/xss.txt << 'EOF'
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
javascript:alert(document.cookie)
<svg onload=alert(1)>
EOF
```

### Step 5 — Run shelob-ng

**Minimal run (30 minutes, no auth):**
```bash
./shelob-ng \
  -spec juice-shop.openapi.json \
  -url http://localhost:3000 \
  -duration 30m \
  -output ./juice-results
```

**Full run with auth + BOLA detection + payloads:**
```bash
./shelob-ng \
  -spec juice-shop.openapi.json \
  -url http://localhost:3000 \
  -user fuzzer@test.local \
  -password "Fuzzer1!" \
  -user2 victim@test.local \
  -pass2 "Victim1!" \
  -payloads sqli=/tmp/payloads/sqli.txt,xss=/tmp/payloads/xss.txt \
  -duration 1h \
  -output ./juice-results \
  -corpus-dir ./juice-corpus
```

**Resume from saved corpus (faster second run):**
```bash
./shelob-ng \
  -spec juice-shop.openapi.json \
  -url http://localhost:3000 \
  -user fuzzer@test.local \
  -password "Fuzzer1!" \
  -corpus-dir ./juice-corpus \
  -duration 30m \
  -output ./juice-results-2
```

### Step 6 — Expected terminal output

```
INFO: spec: juice-shop.openapi.json
INFO: target: http://localhost:3000
INFO: coverage: disabled (pure-random mode)
INFO: corpus: 143 seed entries
INFO: checkers: BehavioralPatterns UseAfterFree InvalidDynamicObject LeakageRule SchemaViolation

#0      INITED   cov:     0  corpus:   143  req/s:     0  2xx:     0  4xx:     0  5xx:     0
#1      pulse    cov:     0  corpus:   143  req/s:     1  2xx:     0  4xx:     1  5xx:     0
#4      pulse    cov:     0  corpus:   143  req/s:     4  2xx:     2  4xx:     2  5xx:     0
#32     pulse    cov:     0  corpus:   143  req/s:    27  2xx:    15  4xx:    17  5xx:     0
#64     pulse    cov:     0  corpus:   143  req/s:    52  2xx:    31  4xx:    33  5xx:     0
#128    FINDING  cov:     0  corpus:   143  req/s:    73  2xx:    64  4xx:    64  5xx:     0  [BehavioralPatterns/medium] Error message leaked in response  http://localhost:3000/api/Users/0
#256    pulse    cov:     0  corpus:   143  req/s:    83  2xx:   128  4xx:   128  5xx:     0
...
DONE    #54000   cov:     0  corpus:   143  req/s:  14.9  findings:   7  elapsed: 1h0m2s
```

### Step 7 — Review findings

```bash
# List all findings
ls -lh juice-results/findings/

# Pretty-print one finding
cat juice-results/findings/BehavioralPatterns_20260527_140523_000.json | python3 -m json.tool

# Count by checker
for f in juice-results/findings/*.json; do
    python3 -c "import json,sys; d=json.load(open('$f')); print(d.get('checker',''))"
done | sort | uniq -c | sort -rn

# View sequence replay (if any CRUD sequences fired)
ls juice-results/replays/
cat juice-results/replays/CRUD__api_Users_*.json | python3 -m json.tool
```

### Known Juice Shop findings

When running 1 hour against a default Juice Shop install, shelob-ng typically finds:

| Checker | Finding | Severity |
|---------|---------|---------|
| `BehavioralPatterns` | SQL/Sequelize error text leaked in 500 responses | medium |
| `BehavioralPatterns` | Stack trace in body on invalid inputs | medium |
| `InvalidDynamicObject` | 500 response on `/api/Users/-1` | medium |
| `SchemaViolation` | Response body does not match spec schema | low |
| `LeakageRule` | Partial state after failed POST in some endpoints | medium |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         shelob-ng                           │
│                                                             │
│  ┌──────────┐    ┌───────────┐    ┌──────────────────────┐  │
│  │ cliArgs/ │───▶│  run/     │◀───│ openapi/             │  │
│  │ Config   │    │  Run()    │    │ ParseOpenapiSpec()    │  │
│  └──────────┘    └─────┬─────┘    └──────────────────────┘  │
│                        │                                     │
│         ┌──────────────┼──────────────────────┐             │
│         ▼              ▼                      ▼             │
│  ┌─────────────┐ ┌──────────┐  ┌──────────────────────────┐ │
│  │  corpus/    │ │mutator/  │  │  sequence/               │ │
│  │  Corpus-    │ │Mutate()  │  │  BuildSequences()        │ │
│  │  Manager   │ │          │  │  Runner.Run()             │ │
│  │  Dynamic-  │ │structural│  └──────────────────────────┘ │
│  │  ValuePool │ │bytelevel │                               │
│  └─────────────┘ │security  │  ┌──────────────────────────┐ │
│                  └──────────┘  │  checkers/               │ │
│                                │  BehavioralPatterns      │ │
│  ┌─────────────┐               │  UseAfterFree            │ │
│  │ coverage/   │               │  InvalidDynamicObject    │ │
│  │ CSP client  │               │  LeakageRule             │ │
│  │ (or noop)   │               │  NameSpaceRule           │ │
│  └─────────────┘               │  SchemaViolation         │ │
│                                └──────────────────────────┘ │
│  ┌─────────────┐  ┌──────────┐                              │
│  │  request/   │  │   ui/    │                              │
│  │ FromCorpus- │  │ Logger   │                              │
│  │  Entry()    │  │ (libfuzz)│                              │
│  └─────────────┘  └──────────┘                              │
└─────────────────────────────────────────────────────────────┘
         │                            │
         ▼                            ▼
  ┌──────────────┐            ┌──────────────┐
  │  Target API  │            │ CSP sidecar  │
  │  (any REST)  │            │ (optional)   │
  └──────────────┘            └──────────────┘
```

### Package map

```
corpus/      CorpusEntry, weighted selection, DynamicValuePool, seed from spec
mutator/     3 mutation strategies + weighted orchestration
  payloads/  external payload file loader (SQLi, XSS, ...)
coverage/    CSP HTTP client or no-op stub
checkers/    6 stateless security checkers
sequence/    stateful CRUD sequences: builder, runner, replay persistence
request/     build *http.Request from CorpusEntry
run/         main fuzzing loop
cliArgs/     CLI flag parsing → Config struct
ui/          libfuzzer-style terminal display
```

---

## Fuzzing loop

One iteration of the main loop:

```
┌─────────────────────────────────────────────────────────────────┐
│  corpus.Select()           weighted random pick from corpus     │
│        │                                                        │
│        ▼                                                        │
│  mutator.Mutate(entry)     clone + apply one strategy          │
│        │                   structural / byte-level / security   │
│        │                   fallback to original on all-skip     │
│        ▼                                                        │
│  csp.Reset()               zero coverage counters              │
│        │                                                        │
│        ▼                                                        │
│  request.FromCorpusEntry() build *http.Request                 │
│        │                                                        │
│        ▼                                                        │
│  http.Client.Do(req)       send to target                      │
│        │                                                        │
│        ▼                                                        │
│  csp.Dump()                read new coverage lines             │
│        │                                                        │
│        ├─ delta > 0 ──▶  corpus.Add(entry)   save for future  │
│        │                                                        │
│        ▼                                                        │
│  pool.Extract(body)        harvest IDs/tokens for path reuse   │
│        │                                                        │
│        ▼                                                        │
│  checkers[0..N].Check()    run all enabled security checkers   │
│        │                                                        │
│        ├─ finding ──▶  logFinding()  write JSON to findings/   │
│        │               display.Finding()                        │
│        ▼                                                        │
│  if tick % 20 == 0:        run one CRUD sequence (round-robin) │
│    sequence.Runner.Run()                                        │
│    sequence.SaveReplay()   persist replay if findings          │
└─────────────────────────────────────────────────────────────────┘
```

In pure-random mode (`-csp-disable`), the `csp.Reset()` / `csp.Dump()` calls
are no-ops and `delta` is always 0 — the corpus still accumulates entries with
`delta=1` from the initial seed.

---

## Corpus and selection

### CorpusEntry fields

```
Method        string            "GET", "POST", "DELETE", ...
PathPattern   string            "/api/Users/{id}"
PathParams    map[string]any    {"id": int64(42)}
QueryParams   map[string]string {"q": "test"}
HeaderParams  map[string]string
CookieParams  map[string]string
Body          []byte            raw JSON (or empty)
ContentType   string            "application/json"
CoverageDelta uint64            new lines covered when added
Generation    uint32            0=seed, increments per mutation
```

### Selection weight formula

```
weight(entry) = log2(1 + delta) / log2(2 + useCount)
```

- Higher `delta` → higher initial weight (coverage-interesting inputs stay in rotation)
- Higher `useCount` → weight decays (cooling: every entry eventually gets a turn)
- Minimum weight is never 0 (prevents starvation)
- Seeds start with `delta=1`; real coverage feedback promotes them

### Corpus capacity

Maximum 15,000 entries. When full, the weakest entry (lowest weight) is evicted.

### DynamicValuePool

After each request, JSON values are extracted from the response body and stored
in a ring buffer (256 entries per field key). On the next mutation cycle,
`GetValue(key)` returns a real server-side value (70% probability) or a randomly
generated one (30%), giving path parameters like `/users/{id}` realistic values
instead of spec-generated placeholders.

---

## Mutation strategies

Three strategies are combined with weighted random selection:

```
┌──────────────────────────────────────────────────────────────┐
│  structuralMutator    (default weight: 3)                    │
│                                                              │
│  Pick one field from: path params, query, headers,          │
│  cookies, body  (body has 2× weight)                        │
│                                                              │
│  string  →  edge cases: "", " ", "null", "\x00", 256×"A"   │
│             truncate to random prefix                        │
│             duplicate: v+v                                   │
│  int64   →  0, ±1, MaxInt64, MinInt64, 256, 65535, 65536    │
│             nudge: v + {-1, 0, +1}                          │
│  float64 →  0, ±1, MaxFloat32  /  nudge                     │
│  bool    →  flip                                             │
│  body    →  inject poison field  (proto pollution, NoSQL)    │
│             remove random field                              │
│             mutate leaf value                                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  byteLevelMutator     (default weight: 1)                    │
│                                                              │
│  Operates on raw Body bytes.                                 │
│  6 operations chosen uniformly:                              │
│    bitFlip      flip one random bit                          │
│    byteFlip     flip one random byte                         │
│    insertion    insert one random byte                       │
│    deletion     delete one random byte                       │
│    duplication  double the body (body + body)                │
│    interesting  replace one byte with 0x00/0x01/0x7f/       │
│                 0x80/0xfe/0xff                               │
│  Skipped (StrategyNotApplicable) when Body is empty.         │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  securityMutator      (default weight: 2)                    │
│                                                              │
│  Injects payload strings from external wordlist files        │
│  into string-valued fields.                                  │
│                                                              │
│  Targets:  path params (string type)                         │
│            all query / header / cookie params                │
│            string leaves in JSON body (dotted-path access)   │
│                                                              │
│  Enabled only when -payloads flag is set.                    │
│  Skipped when no string targets exist.                       │
└──────────────────────────────────────────────────────────────┘
```

When a strategy returns `StrategyNotApplicable`, the orchestrator falls back to
the next strategy. If all strategies skip, the original (unmodified) entry is used.

---

## Security checkers

Six stateless checkers run on every request/response pair.

```
┌────────────────────────────────────────────────────────────────┐
│ Checker pipeline (each request)                                │
│                                                                │
│  request ──▶  BehavioralPatterns  scan body for SQL/XSS/trace │
│           │                                                    │
│           ├──▶  UseAfterFree      DELETE 2xx?                  │
│           │       └── probe GET same URL                       │
│           │           └── 2xx? → finding HIGH                  │
│           │                                                    │
│           ├──▶  InvalidDynamicObject  has path params?         │
│           │       └── probe with -1, 0, 999999999, "null", ""  │
│           │           └── 5xx? → finding MEDIUM                │
│           │                                                    │
│           ├──▶  LeakageRule       POST returned 4xx?           │
│           │       └── probe GET same URL                       │
│           │           └── 2xx? → finding MEDIUM                │
│           │                                                    │
│           ├──▶  NameSpaceRule     any 2xx? (needs -user2)      │
│           │       └── replay with user2 cookies                │
│           │           └── 2xx? → finding HIGH (BOLA/IDOR)      │
│           │                                                    │
│           └──▶  SchemaViolation   validate resp vs OAS schema  │
│                   └── mismatch? → finding LOW                  │
└────────────────────────────────────────────────────────────────┘
```

| Checker | Extra requests | Severity |
|---------|---------------|---------|
| `BehavioralPatterns` | 0 | medium |
| `UseAfterFree` | 1 (GET probe) | high |
| `InvalidDynamicObject` | up to 5 (one per probe value) | medium |
| `LeakageRule` | 1 (GET probe) | medium |
| `NameSpaceRule` | 1 (replay with user2) | high |
| `SchemaViolation` | 0 | low |

`BehavioralPatterns` detects 8 patterns:
- SQL error messages (`SQLITE_ERROR`, `ORA-`, `syntax error`, `Sequelize`)
- XSS artifacts (`<script>` reflected in response)
- Path traversal indicators (`../`, `etc/passwd`)
- SSTI markers (`{{`, `}}` in rendered responses)
- Go / Python / Java / Node.js stack traces

---

## Stateful sequence testing

Every 20 fuzzing iterations, shelob-ng runs one CRUD sequence.

### How sequences are built from the spec

```
For each POST /resource in spec:
  Find matching child path /resource/{param}
  Check POST response schema for id/uuid/key field
  If found → build sequence:

  Step 1  POST /resource           create resource, extract {id}
            │
            ▼  bind id → {param}
  Step 2  GET  /resource/{id}      verify 2xx (resource exists)
            │
            ▼
  Step 3  DELETE /resource/{id}    delete resource, expect 2xx
            │
            ▼
  Step 4  GET  /resource/{id}      probe: MUST be 4xx
                                   2xx here = UseAfterFree finding HIGH
```

### Sequence finding flow

```
Runner.Run(seq)
  bound = {}

  for each step:
    entry = step.Entry.Clone()
    for param, val in bound:
      entry.PathParams[param] = val    ← inject extracted IDs

    resp, body = send(entry)

    if step.ExtractKey != "":
      bound[step.BindParam] = extractJSONField(body, step.ExtractKey)

    if resp.status/100 != step.WantStatus:
      emit Finding{...}

  SaveReplay(replay, outputDir)        ← only when findings present
```

---

## Status display

shelob-ng prints libfuzzer-style event lines to stdout:

```
INFO: spec: juice-shop.openapi.json
INFO: target: http://localhost:3000
INFO: coverage: disabled (pure-random mode)
INFO: corpus: 143 seed entries
INFO: checkers: BehavioralPatterns UseAfterFree InvalidDynamicObject LeakageRule SchemaViolation

#0      INITED   cov:     0  corpus:   143  req/s:     0  2xx:     0  4xx:     0  5xx:     0
#1      pulse    cov:     0  corpus:   143  req/s:     1  2xx:     0  4xx:     1  5xx:     0
#4      pulse    cov:     0  corpus:   143  req/s:     4  2xx:     2  4xx:     2  5xx:     0
#8      NEW      cov:    12  corpus:   144  req/s:     8  2xx:     5  4xx:     3  5xx:     0  [GET /api/Users/{id}  +12]
#32     pulse    cov:    12  corpus:   144  req/s:    27  2xx:    18  4xx:    14  5xx:     0
#64     FINDING  cov:    12  corpus:   144  req/s:    52  2xx:    33  4xx:    30  5xx:     1  [BehavioralPatterns/medium] Error message leaked  http://localhost:3000/api/Users/0
#128    pulse    cov:    12  corpus:   144  req/s:    63  2xx:    65  4xx:    63  5xx:     0
#256    NEW      cov:    18  corpus:   145  req/s:    71  2xx:   130  4xx:   126  5xx:     0  [POST /api/Users  +6]
...
DONE    #54000   cov:    18  corpus:   145  req/s:  14.9  findings:   3  elapsed: 1h0m2s
```

### Column reference

| Column | Meaning |
|--------|---------|
| `#N` | Total HTTP requests sent (including checker probes) |
| `INITED/NEW/pulse/FINDING/DONE` | Event type |
| `cov:` | Cumulative new coverage lines (sum of all CSP deltas) |
| `corpus:` | Current corpus size |
| `req/s:` | Requests per second since start |
| `2xx/4xx/5xx:` | Response status code buckets |

### Event types

| Event | Trigger | Extra info shown |
|-------|---------|-----------------|
| `INITED` | Once at startup | — |
| `pulse` | Every power-of-2 request count, or every 3 s | — |
| `NEW` | Coverage increased (CSP delta > 0) | `[METHOD /path  +delta]` |
| `FINDING` | Checker or sequence found an issue | `[checker/severity] title  url` |
| `DONE` | Duration elapsed | `findings: N  elapsed: Xm Ys` |

### Color coding

| Color | Event |
|-------|-------|
| Cyan | `INITED`, `DONE` |
| Green | `NEW` |
| Dim/faint | `pulse` |
| Red | `FINDING` |
| Yellow | `WARN:` |

Disable with `-no-color` or set `NO_COLOR=1` / `TERM=dumb`.

---

## Output format

### Finder output directory structure

```
<output>/
  findings/
    BehavioralPatterns_20260527_140001_000.json
    UseAfterFree_20260527_140523_000.json
    seq_CRUD__api_Users_20260527_141200_000.json
  replays/
    CRUD__api_Users_20260527_141200_000.json
```

### Single-request finding (checker)

```json
{
  "checker": "UseAfterFree",
  "severity": "high",
  "title": "Resource accessible after DELETE",
  "detail": "DELETE returned 204; subsequent GET returned 200 (expected 404)",
  "method": "GET",
  "url": "http://localhost:3000/api/Users/42",
  "status_code": 200
}
```

### Sequence finding

```json
{
  "sequence": "CRUD:/api/Users",
  "step_index": 3,
  "severity": "high",
  "title": "Resource accessible after DELETE",
  "detail": "Resource accessible after DELETE expected 4xx, got 200",
  "method": "GET",
  "url": "http://localhost:3000/api/Users/7",
  "status_code": 200
}
```

### Sequence replay

```json
{
  "sequence": "CRUD:/api/Users",
  "executed_at": "2026-05-27T14:12:00.123Z",
  "steps": [
    {
      "method": "POST",
      "url": "http://localhost:3000/api/Users",
      "status_code": 201,
      "extracted": {"id": "7"}
    },
    {
      "method": "GET",
      "url": "http://localhost:3000/api/Users/7",
      "status_code": 200
    },
    {
      "method": "DELETE",
      "url": "http://localhost:3000/api/Users/7",
      "status_code": 204
    },
    {
      "method": "GET",
      "url": "http://localhost:3000/api/Users/7",
      "status_code": 200
    }
  ],
  "findings": [
    {
      "sequence": "CRUD:/api/Users",
      "step_index": 3,
      "severity": "high",
      "title": "Resource accessible after DELETE",
      "detail": "Resource accessible after DELETE expected 4xx, got 200",
      "method": "GET",
      "url": "http://localhost:3000/api/Users/7",
      "status_code": 200
    }
  ]
}
```

---

## All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-spec` | **required** | OpenAPI spec file (JSON or YAML) |
| `-url` | from spec | Target base URL, overrides `servers[]` in spec |
| `-user` | | Username for cookie-based login / Basic auth |
| `-password` | | Password |
| `-apikey` | | API key header value |
| `-token` | | Bearer token |
| `-output` | `fuzzer_output` | Output directory for findings and replays |
| `-detailed` | false | Log successful requests in addition to findings |
| `-duration` | `1h` | Fuzzing duration (`30m`, `2h`, `24h`, ...) |
| `-debug` | false | Enable debug-level logging (very verbose) |
| `-rps` | 0 | Requests per second cap (0 = unlimited) |
| `-no-color` | false | Disable ANSI colors (auto-set when `NO_COLOR` env is present or `TERM=dumb`) |
| `-csp-url` | | Coverage Sidecar Protocol base URL (`http://host:port`) |
| `-csp-disable` | false | Explicitly disable coverage feedback; run in pure-random mode |
| `-corpus-dir` | | Persist corpus to this directory; load on start if present |
| `-payloads` | | Security payload files: `key=/path.txt,key2=/path2.txt` |
| `-checker` | all | Comma-separated list of checkers to enable; empty = all |
| `-user2` | | Second user for BOLA/`NameSpaceRule` checker |
| `-pass2` | | Password for second user |

---

## Coverage Sidecar Protocol

CSP is a minimal HTTP protocol that any application can implement to export
coverage data to shelob-ng.

### Endpoints

```
POST /csp/reset
  Called before each fuzzing request.
  Zeros coverage counters so the next /csp/dump shows only what the
  current request exercised.
  Response: 200 OK (body ignored)

GET /csp/dump
  Called after each fuzzing request.
  Returns coverage data as JSON.
  Response: 200 OK + JSON body
```

### /csp/dump response schema

```json
{
  "total_lines":    1200,
  "covered_lines":  347,
  "bitmap":         "<base64-encoded coverage bitmap>",
  "new_since_reset": ["handler.go:42", "db.go:118"]
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `total_lines` | int | Total instrumented lines |
| `covered_lines` | int | Lines covered since process start |
| `bitmap` | string | Base64 coverage bitmap (optional) |
| `new_since_reset` | []string | Lines newly covered since last `/csp/reset` |

When `len(new_since_reset) > 0`, `delta = len(new_since_reset)` and the
triggering entry is added to the corpus with that delta as its weight.

### Adapter examples

Ready-made CSP adapters are in `adapters/`:

```
adapters/
  go/       net/http handler, uses runtime/coverage (Go 1.20+)
  c/        gcov + libmicrohttpd
  nodejs/   express middleware + V8 coverage
  python/   Flask + coverage.py
```

### When to use coverage mode

| Scenario | Recommendation |
|----------|---------------|
| Black-box target, no source access | `-csp-disable` (pure random) |
| Target you control (Go/Node/Python) | Add CSP adapter, use `-csp-url` |
| Maximum finding rate on known app | Pure random + payload wordlists |
| Finding deep logic bugs | Coverage-guided mode |
