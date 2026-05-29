# CLI Reference

Complete reference for all shelob-ng command-line flags.

---

## Synopsis

```
shelob-ng -spec <file> [options]
```

The only required flag is `-spec`. All others have defaults or are optional.

---

## Required

### `-spec <file>`

OpenAPI specification file. Accepts JSON (`.json`) and YAML (`.yaml`, `.yml`).
Can be a local file path — HTTP URLs are not supported (download first with `curl`).

```bash
./shelob-ng -spec openapi.json ...
./shelob-ng -spec api/swagger.yaml ...
```

The spec must be OpenAPI 3.x. Swagger 2.0 specs can be converted with
`swagger-converter` or `api-spec-converter`.

---

## Target

### `-url <url>`

Base URL of the target API. Overrides the `servers[]` array in the spec.
Trailing slashes are stripped automatically.

```bash
./shelob-ng -spec api.json -url http://localhost:3000
./shelob-ng -spec api.json -url https://staging.api.example.com
```

If omitted, the first server URL from the spec is used.
If the spec has no servers and no `-url` is provided, the fuzzer exits with an error.

---

## Authentication

### `-user <username>` / `-password <password>`

Credentials for cookie-based login. shelob-ng detects the login endpoint
automatically from the spec (paths matching `/login`, `/users/login`, `operationId`
containing `"login"` or `"authenticate"`).

The login request body is tried with multiple field name variants:
- `{"email": user, "password": pass}`
- `{"username": user, "password": pass}`
- `{"user": user, "password": pass}`

Session cookies from `Set-Cookie` response headers are attached to all subsequent
requests. If the login response contains a JWT (in `authentication.token`,
`token`, `access_token`, or `auth_token`), it is also used as a Bearer token.

```bash
./shelob-ng -spec api.json -url http://localhost:3000 \
    -user admin@example.com -password 'S3cr3t!'
```

### `-user2 <username>` / `-pass2 <password>`

Credentials for the second user. Required by `NameSpaceRule` (BOLA) and `BFLA`
checkers. Uses the same login detection logic as the primary user.

```bash
./shelob-ng -spec api.json -url http://localhost:3000 \
    -user  owner@example.com  -password 'Pass1!' \
    -user2 other@example.com  -pass2    'Pass2!'
```

### `-apikey <value>`

Static API key. Sets the `X-Api-Key: <value>` header on every request,
including all checker probe requests.

```bash
./shelob-ng -spec api.json -url http://localhost:8080 \
    -apikey special-key
```

Can be combined with `-user`/`-password`. The cookie login and the API key
header are applied independently.

### `-token <value>`

Static Bearer token. Sets `Authorization: Bearer <value>` on every request.

**Important:** The Bearer token is **not** forwarded to `NameSpaceRule` user2 probes.
A JWT encodes user1's identity; forwarding it to user2 probes would authenticate
user2 as user1, defeating the BOLA check.

```bash
./shelob-ng -spec api.json -url http://localhost:3000 \
    -token eyJhbGciOiJSUzI1NiJ9...

# Use a pre-obtained JWT directly (no cookie login):
JWT=$(curl -s -X POST http://localhost:3000/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@example.com","password":"pass"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
./shelob-ng -spec api.json -url http://localhost:3000 -token "$JWT"
```

---

## Output

### `-output <directory>`

Output directory for findings, replays, and coverage reports. Created if it
does not exist. Default: `fuzzer_output`.

```
<output>/
├── findings/
│   ├── BehavioralPatterns_GET__rest_products_search_a1b2c3d4.json
│   └── ...
├── replays/
│   └── CRUD__api_Users_20260529_040000.json
└── api-coverage.json
```

### `-sarif <path>`

Write a SARIF 2.1.0 report at the end of the run. The report reads all
finding JSON files from `<output>/findings/` and aggregates them.

Compatible with: GitHub Security tab, AzureDevOps, Svacer, Defect Dojo.

```bash
./shelob-ng -spec api.json -url http://localhost:3000 \
    -sarif results.sarif
```

GitHub Actions integration:
```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### `-fail-on <severity>`

Exit with code **1** after the run completes when at least one finding at or
above `<severity>` was written. Severity order: `high > medium > low`.

All I/O (corpus save, api-coverage.json, SARIF) completes before the process
exits, so no data is lost.

```bash
# Fail CI pipeline on any HIGH finding
./shelob-ng -spec api.json -url http://target \
    -duration 10m -fail-on high

# Fail on MEDIUM or higher
./shelob-ng -spec api.json -url http://target \
    -duration 10m -fail-on medium
```

**CI/CD pipeline pattern:**

```bash
./shelob-ng -spec api.json -url http://staging \
    -user admin@corp.local -password AdminPass \
    -duration 10m -output ./ci-results \
    -fail-on high
EXIT=$?
# Exit 0 = no HIGH findings
# Exit 1 = at least one HIGH finding (printed to stdout before exit)
```

When findings trigger the exit, a summary is printed:
```
FAIL: 2 finding(s) at "high" severity or above:
  • [high] BehavioralPatterns — SQL Error Leakage
  • [high] RateLimitChecker — Missing Rate Limiting on Auth Endpoint
```

### `-detailed`

Include successful (2xx) test cases in the output log alongside findings.
By default only findings are written. Useful for debugging corpus behaviour.

---

## Timing and Rate

### `-duration <duration>`

How long to run the fuzzer. Accepts Go duration strings. Default: `1h`.

```bash
./shelob-ng -spec api.json -url http://target -duration 30m
./shelob-ng -spec api.json -url http://target -duration 2h30m
./shelob-ng -spec api.json -url http://target -duration 24h
```

The fuzzer runs for at most this duration, then performs a clean shutdown:
waits for outstanding checker goroutines, saves corpus, writes api-coverage.json.

### `-rps <n>`

Requests per second limit for the main fuzzing loop. Default: `0` (unlimited).

The RPS limiter applies only to main-loop iterations; checker probe requests
run concurrently and are not counted against the limit.

```bash
# Cap at 10 req/s for a rate-limited staging environment
./shelob-ng -spec api.json -url https://staging.api.corp.local \
    -rps 10 -duration 4h
```

---

## Coverage Sidecar Protocol

### `-csp-url <url>`

Base URL of the CSP sidecar. Enables coverage-guided fuzzing.
See [csp-protocol.md](csp-protocol.md) for details and adapter implementations.

```bash
# Juice Shop with V8 Inspector CSP sidecar
./shelob-ng -spec juice-shop.openapi.json -url http://localhost:3000 \
    -csp-url http://localhost:8080 \
    -corpus-dir ./corpus -duration 4h
```

### `-csp-disable`

Force pure-random mode. Ignores `-csp-url` if also set. Use when the target
does not have a CSP sidecar but you want to explicitly avoid the default
CSP attempt.

```bash
./shelob-ng -spec api.json -url http://localhost:3000 -csp-disable
```

---

## Corpus

### `-corpus-dir <directory>`

Directory for corpus persistence. If the directory exists and contains a
valid `index.json`, shelob-ng loads saved entries at startup. At shutdown
(SIGINT, SIGTERM, or duration expiry), the corpus is saved to this directory.

Enables corpus resumption across runs:
```bash
# Run 1: build corpus
./shelob-ng -spec api.json -url http://target \
    -corpus-dir ./corpus -duration 1h

# Run 2: resume from saved corpus
./shelob-ng -spec api.json -url http://target \
    -corpus-dir ./corpus -duration 1h
```

If the directory does not exist, it is created at shutdown.
If it exists but is empty or invalid, the fuzzer starts with a fresh corpus.

---

## Security Payloads

### `-payloads <key=path,...>`

Comma-separated `name=filepath` pairs. Each file is loaded as a newline-separated
wordlist. Activates the `securityMutator` strategy which injects payload strings
into all string-typed fields.

```bash
./shelob-ng -spec api.json -url http://target \
    -payloads sqli=/tmp/sqli.txt,xss=/tmp/xss.txt,ssti=/tmp/ssti.txt

# With PayloadsAllTheThings:
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /tmp/patt
./shelob-ng -spec api.json -url http://target \
    -payloads "sqli=/tmp/patt/SQL Injection/Intruder/SQL_Bypass.txt,\
               xss=/tmp/patt/XSS Injection/Intruder/XSS Polyglots.txt"
```

**Standard payload types:**

| Key | Content | Detects via |
|-----|---------|-------------|
| `sqli` | SQL injection strings | BehavioralPatterns: SQL error |
| `xss` | XSS payloads | BehavioralPatterns: XSS artifact |
| `ssti` | Template injection | BehavioralPatterns: SSTI |
| `lfi` | Path traversal | BehavioralPatterns: LFI |
| `nosql` | MongoDB operator injection | BehavioralPatterns: NoSQL |
| `cmdi` | OS command injection | BehavioralPatterns: cmdi |

The key name is stored in the payload set but not currently used for filtering —
all loaded payloads are treated as a single pool. Future versions may support
per-endpoint payload selection.

---

## Checkers

### `-checker <name,...>`

Comma-separated list of checker names to enable. Empty (default) enables all.

```bash
# Run only SchemaViolation and BehavioralPatterns
./shelob-ng -spec api.json -url http://target \
    -checker SchemaViolation,BehavioralPatterns

# BOLA-only scan
./shelob-ng -spec api.json -url http://target \
    -user user1@x.com -password pass1 \
    -user2 user2@x.com -pass2 pass2 \
    -checker NameSpaceRule

# Rate limit scan (short duration — fires quickly)
./shelob-ng -spec api.json -url http://target \
    -user admin@x.com -password pass \
    -checker RateLimitChecker \
    -duration 2m
```

**Valid checker names:**

| Name | What it detects |
|------|----------------|
| `BehavioralPatterns` | SQL errors, stack traces, XSS, LFI, cmdi, SSRF metadata |
| `UseAfterFree` | Resource accessible after DELETE |
| `InvalidDynamicObject` | 5xx on boundary path parameter values |
| `LeakageRule` | Partial state after failed POST |
| `NameSpaceRule` | BOLA/IDOR (requires -user2) |
| `BFLA` | Broken Function Level Authorization (requires -user2) |
| `AuthBypassRule` | Auth bypass on spec-secured endpoints |
| `SchemaViolation` | Response does not match declared schema |
| `RateLimitChecker` | No 429 after rapid requests |
| `MassAssignment` | Server accepts privilege-escalation fields |
| `ReDoSChecker` | Catastrophic regex backtracking |

`PathDiscovery` (pre-scan) always runs and cannot be disabled via `-checker`.

### `-path-wordlist <file>`

File with additional paths for the PathDiscovery pre-scan.
One path per line; tab-separated description is optional.
Lines starting with `#` are comments.

```bash
# Create wordlist
cat > my-paths.txt << 'EOF'
# Internal endpoints
/api/internal/config    internal config dump
/v1/admin/users         old admin endpoint
/debug/pprof            Go pprof profiling
EOF

./shelob-ng -spec api.json -url http://target \
    -path-wordlist my-paths.txt
```

---

## Display

### `-no-color`

Disable ANSI escape codes in terminal output. Auto-set when:
- `NO_COLOR` environment variable is set (any value)
- `TERM=dumb`

```bash
# In CI/CD environments
NO_COLOR=1 ./shelob-ng -spec api.json -url http://target
./shelob-ng -spec api.json -url http://target -no-color
```

### `-debug`

Enable debug-level logging. Very verbose — logs every request, corpus operation,
checker invocation, and auth step. Useful for:
- Diagnosing why certain endpoints are not being reached
- Understanding the dependency graph behaviour
- Debugging custom checkers during development

```bash
./shelob-ng -spec api.json -url http://target -debug 2>&1 | head -100
```

---

## Environment Variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Equivalent to `-no-color` |
| `TERM=dumb` | Equivalent to `-no-color` |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Normal exit — duration expired, SIGINT, or `-fail-on` set but no matching findings |
| `1` | Fatal error (missing required flag, spec parse failure, etc.) **or** `-fail-on` triggered |

By default the fuzzer exits with `0` even when findings are produced.
Use `-fail-on high` (or `medium`/`low`) to opt into non-zero exit for CI/CD.

---

## Common Invocations

```bash
# Minimal smoke test
./shelob-ng -spec api.json -url http://localhost:3000 -duration 5m -csp-disable

# Full security audit with two users
./shelob-ng -spec api.json -url http://target \
    -user  admin@corp.local  -password AdminPass \
    -user2 user@corp.local   -pass2    UserPass \
    -payloads sqli=sqli.txt,xss=xss.txt,lfi=lfi.txt \
    -corpus-dir ./corpus \
    -sarif findings.sarif \
    -duration 4h \
    -output ./results

# Fast rate limit check (2 min)
./shelob-ng -spec api.json -url http://target \
    -user admin@corp.local -password AdminPass \
    -checker RateLimitChecker \
    -duration 2m -csp-disable

# Coverage-guided deep audit
./shelob-ng -spec api.json -url http://localhost:3000 \
    -csp-url http://localhost:8080 \
    -user admin@example.com -password pass \
    -payloads sqli=sqli.txt,xss=xss.txt \
    -corpus-dir ./corpus \
    -duration 24h \
    -output ./results/deep-audit

# Bearer token only (no cookie login)
./shelob-ng -spec api.json -url http://api.corp.local \
    -token "$(cat /tmp/access_token.txt)" \
    -duration 1h -csp-disable

# Extend PathDiscovery for a specific target
./shelob-ng -spec api.json -url http://localhost:3000 \
    -path-wordlist custom-paths.txt \
    -duration 5m -csp-disable -output /tmp/pathscan

# CI/CD pipeline check (fail on HIGH findings)
./shelob-ng -spec api.json -url http://staging \
    -checker BehavioralPatterns,RateLimitChecker,AuthBypassRule \
    -duration 10m -csp-disable -output ./ci-results
HIGH_COUNT=$(jq -r '.severity' ./ci-results/findings/*.json 2>/dev/null | grep -c high || echo 0)
[ "$HIGH_COUNT" -eq 0 ] || { echo "FAIL: $HIGH_COUNT HIGH findings"; exit 1; }
```
