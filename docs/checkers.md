# Checkers Reference

shelob-ng ships with 11 runtime checkers plus PathDiscovery (a pre-scan phase).
All runtime checkers implement the `Checker` interface and run concurrently after
every HTTP request/response pair.

```go
type Checker interface {
    Name() string
    Check(ctx context.Context, cctx CheckContext,
          entry *corpus.CorpusEntry, req *http.Request,
          resp *http.Response, body []byte) []Finding
}
```

Filter active checkers with `-checker BehavioralPatterns,NameSpaceRule` (empty = all).

---

## CheckContext

Shared resources passed to every `Check()` call:

```go
type CheckContext struct {
    Client       *http.Client    // for probe requests
    TargetURL    string          // "http://localhost:3000"
    AuthCookies  []*http.Cookie  // primary user session
    User2Cookies []*http.Cookie  // second user (nil if not configured)
    OASRouter    routers.Router  // for schema lookups
    APIKey       string          // X-Api-Key value
    Token        string          // Bearer token value
}
```

---

## BehavioralPatterns

**File:** `checkers/behavioral.go`
**Probe requests:** 0 (pure response analysis)
**Severity:** HIGH for SQL/XSS/LFI/cmdi/SSTI; MEDIUM for stack traces

Scans response bodies with compiled regular expressions. Each pattern targets a
class of vulnerability artifact that leaks into HTTP responses.

### Patterns

| Pattern | What it detects | Severity |
|---------|----------------|---------|
| SQL Error | `sql syntax`, `ORA-\d{5}`, `PostgreSQL.*ERROR`, `SQLITE_ERROR`, `SQLSTATE\[`, etc. | HIGH |
| XSS Artifact | `<script[^>]*>`, `javascript:\s*alert`, `onerror\s*=` — **HTML responses only** | HIGH |
| Path Traversal / LFI | `root:x:0:0`, `/etc/shadow`, `[boot loader]` | HIGH |
| Command Injection | `uid=\d+\(\w+\)\s+gid=\d+`, `bash: not found`, `command not found` | HIGH |
| SSTI | `FreeMarker template error`, `jinja2.exceptions`, `TemplateSyntaxError` | HIGH |
| SSRF Cloud Metadata | `169.254.169.254`, `metadata.google.internal`, `ami-id`, `computeMetadata/v1`, `subscriptionId` | HIGH |
| Go Panic | `goroutine \d+ [running]`, `panic: runtime error`, `SIGSEGV` | MEDIUM |
| Python Traceback | `Traceback (most recent call last):`, `AttributeError:` | MEDIUM |
| Java Exception | `at java.lang.`, `NullPointerException`, `org.springframework.` | MEDIUM |
| Node.js Error | `TypeError: Cannot read propert`, `at Module._compile` | MEDIUM |

The XSS pattern has `htmlOnly: true` — it only fires when `Content-Type` contains
`text/html`. This prevents false positives on JSON APIs that legitimately contain
example XSS strings in documentation fields or challenge descriptions.

### Adding patterns

```go
// In checkers/behavioral.go, add to the `patterns` slice:
{
    regexp.MustCompile(`(?i)(YourPattern)`),
    "Your Title",
    SeverityHigh,   // or SeverityMedium
    false,          // htmlOnly: true if XSS-type pattern
},
```

---

## UseAfterFree

**File:** `checkers/useafterfree.go`
**Probe requests:** 1 GET
**Severity:** HIGH
**Trigger:** DELETE returned 2xx

After a DELETE succeeds, the checker probes the same URL with an authenticated GET.
If the resource is still accessible (2xx), the server failed to enforce deletion.

```
DELETE /api/orders/42 → 200 OK
    ↓
GET  /api/orders/42 → 200 OK  ← HIGH: UseAfterFree
```

The GET probe carries the same auth cookies as the original DELETE. It does **not**
strip auth — a 404 from the GET is considered correct behaviour regardless of auth state.

---

## InvalidDynamicObject

**File:** `checkers/invaliddyn.go`
**Probe requests:** up to 5 per path parameter
**Severity:** MEDIUM
**Trigger:** any request with path parameters

Substitutes each path parameter with sentinel boundary values and checks for 5xx:
- `-1` (negative integer)
- `0` (zero)
- `999999999` (large integer)
- `null` (string literal "null")
- `` (empty string)

A 5xx response on any boundary value indicates missing input validation — the server
panicked or threw an exception rather than returning a proper 4xx.

**Note:** Does not fire on `200` — a server that returns 200 for `id=null` may be
intentionally designed that way (e.g., `GET /users/null` → create anonymous session).

---

## LeakageRule

**File:** `checkers/leakage.go`
**Probe requests:** 1 GET
**Severity:** MEDIUM
**Trigger:** POST returned 4xx (except 401)

When a POST request fails with a 4xx, the server may have committed partial state
before detecting the error (e.g., a create operation that validates data after
inserting it). The checker probes `GET <targetURL>/<path>` to see if the resource
was created despite the failure.

### Skip conditions

```
1. resp.StatusCode == 401
   Auth middleware rejected the request before any application logic ran.
   No state can have been committed.

2. len(entry.PathParams) == 0 (collection endpoint)
   POST /api/Feedbacks → 4xx
   GET  /api/Feedbacks → 200  (public list endpoint)
   This is normal REST — a collection GET always returns 200.
   The checker only fires on singleton endpoints (/resource/{id}).

3. resp.StatusCode >= 500 (implicit)
   Server crashed before committing state; not a LeakageRule scenario.
```

### Probe URL construction

```go
probeURL = cctx.TargetURL + req.URL.Path  // no query string
```

This avoids false positives caused by mutated query parameters that would return
404 even on an accessible resource.

---

## NameSpaceRule (BOLA / IDOR)

**File:** `checkers/namespace.go`
**Probe requests:** 1–2
**Severity:** HIGH
**Trigger:** any request returned 2xx
**Requires:** `-user2 / -pass2`

Tests **object ownership** (BOLA/IDOR): if user1 can access a resource, can user2
also access it?

### Detection sequence

```
1. user1 request → 2xx (resource exists and user1 can access it)

2. Anonymous probe (all auth stripped: no cookies, no Authorization, no X-Api-Key)
   → if 2xx: endpoint is publicly accessible → SKIP
     (not a BOLA — it's just a public endpoint)

3. user2 probe (user2 cookies + shared X-Api-Key if set)
   → if 2xx: user2 accessed user1's resource → HIGH (BOLA)
   → if 4xx/403: access control is enforced → no finding
```

### Important: Bearer token in user2 probe

The Bearer token (`-token` or auto-extracted JWT) is **never** forwarded to the
user2 probe. The Bearer token encodes user1's identity (e.g., JWT `sub` claim).
Forwarding it would authenticate the probe as user1, defeating the BOLA check.
Only `X-Api-Key` (a shared application-level credential, not user-specific) is forwarded.

---

## BFLA (Broken Function Level Authorization)

**File:** `checkers/bfla.go`
**Probe requests:** 1–2
**Severity:** HIGH
**Trigger:** privileged endpoint returned 2xx
**Requires:** `-user2 / -pass2`

Tests **role boundaries** (BFLA): can a lower-privilege user call a function
intended only for admins?

### Privileged endpoint heuristic

An endpoint is considered privileged if its path or `operationId` matches:

```
/admin|backoffice|dashboard|internal|manage|management|
 panel|private|staff|superuser|console/
```

or `operationId` contains `"admin"` (case-insensitive).

This deliberately avoids re-checking ordinary resource endpoints already covered
by NameSpaceRule.

### Detection sequence

Identical to NameSpaceRule, but only applied to endpoints matching the heuristic:

```
user1 (admin) → 2xx
anonymous probe → if 2xx: skip (public endpoint)
user2 (regular) → if 2xx: BFLA HIGH
```

---

## AuthBypassRule

**File:** `checkers/authbypass.go`
**Probe requests:** 1
**Severity:** HIGH
**Trigger:** authenticated user got 2xx AND spec declares security on operation
**Requires:** at least one auth credential configured

Tests whether unauthenticated clients can reach spec-declared secure endpoints.

### Distinction from NameSpaceRule/BFLA

| Checker | Anonymous 2xx means… |
|---------|----------------------|
| NameSpaceRule | endpoint is public → **skip** |
| BFLA | endpoint is public → **skip** |
| AuthBypassRule | endpoint should require auth but doesn't → **FIRE** |

AuthBypassRule specifically looks for the combination of:
1. Spec says `security: [bearerAuth]` (or any non-empty security requirement)
2. An anonymous probe still gets 2xx

### Security declaration lookup

```go
func operationRequiresAuth(cctx CheckContext, req *http.Request) bool {
    route, _, _ := cctx.OASRouter.FindRoute(req)
    op := route.Operation
    if op.Security != nil {
        return len(*op.Security) > 0   // security: [] is explicitly public
    }
    return len(route.Spec.Security) > 0  // inherit global security
}
```

---

## SchemaViolation

**File:** `checkers/schema.go`
**Probe requests:** 0
**Severity:** MEDIUM

Validates the response body against the OpenAPI schema using `kin-openapi`'s
`openapi3filter.ValidateResponse`. Fires when the response:
- Has an undeclared status code
- Has a `Content-Type` that differs from the declared media type
- Has a body that does not conform to the declared JSON schema
  (missing required fields, wrong types, extra fields when `additionalProperties: false`)

**Historical note:** The legacy `response.go` validation passed `{}` as the body.
The SchemaViolation checker uses the real response body, which is why it catches
issues the legacy code missed.

---

## RateLimitChecker

**File:** `checkers/ratelimit.go`
**Probe requests:** 8 (burst)
**Severity:** HIGH (auth paths) / MEDIUM (others)
**Type:** Stateful — persists hit counts across calls

Detects API endpoints that accept unlimited rapid requests without returning 429.

### Thresholds

| Path type | Threshold | Severity |
|-----------|-----------|---------|
| Auth (`/login`, `/register`, `/otp`, `/password`, `/reset`, `/forgot`, etc.) | 5 natural non-429 responses | HIGH |
| All other endpoints | 20 natural non-429 responses | MEDIUM |

The `authPathRE` regex matches: `login`, `signin`, `signup`, `register`,
`auth(enticate)?`, `token`, `password`, `passphrase`, `otp`, `pin`, `verify`,
`2fa`, `mfa`, `reset`, `forgot` — both as path segments (`/api/login`) and
hyphenated words (`/reset-password`).

### Detection sequence

```
1. Count natural responses to (method, pathPattern)
2. On threshold hit: mark as fired (prevents concurrent double-fire)
3. Send burst of 8 rapid identical requests (preserving all auth headers)
4. If any burst response is 429 → rate limiter engaged → no finding
5. If all burst responses are non-429 → HIGH or MEDIUM finding
```

### State

```go
type RateLimitChecker struct {
    mu    sync.Mutex
    hits  map[string]int
    fired map[string]struct{}
}
```

Thread-safe via mutex. One checker instance is shared across all goroutines.
`fired` prevents repeating the burst after the first probe.

### False positives

- Server may rate-limit by IP at a network level (invisible to the checker)
- Server may return 503 instead of 429 (not recognized as rate limiting)
- Load balancer may distribute requests across backends, each with independent counters

---

## MassAssignment

**File:** `checkers/massassignment.go`
**Probe requests:** 1
**Severity:** HIGH (if reflected) / MEDIUM (if silently accepted)
**Trigger:** POST/PUT/PATCH returned 2xx with JSON Content-Type

Detects when servers accept JSON fields that should be server-side only
(role escalation, balance manipulation, admin flag setting).

### Poison fields

```json
{
    "role":       "admin",
    "admin":      true,
    "isAdmin":    true,
    "is_admin":   true,
    "superuser":  true,
    "verified":   true,
    "premium":    true,
    "credits":    99999,
    "balance":    99999,
    "permission": "admin"
}
```

### Detection sequence

```
1. Parse original request body (must be JSON object)
2. Add poison fields (only where key doesn't already exist)
3. Send probe with original body + poison fields

4. Probe returns 4xx/422 → server validated fields → no finding

5. Probe returns 2xx:
   a. Parse probe response body
   b. Check if any poison field value appears in response:
      - deepGet() searches nested objects recursively
      - string-compare poison value vs response value
   c. If reflection found → HIGH ("fields reflected in response")
   d. If no reflection → MEDIUM ("fields accepted without validation error")
```

### Limitations

- Only detects fields that are reflected back in the create/update response.
- To confirm persistence (fields saved to DB), a follow-up GET would be needed
  (not currently implemented — would require knowing the resource URL).
- Inapplicable to non-JSON, GET, and DELETE requests.

---

## ReDoSChecker

**File:** `checkers/redos.go`
**Probe requests:** 2–6 (timing measurements)
**Severity:** MEDIUM
**Trigger:** any 2xx/4xx response (skips 5xx)

Detects Regular Expression Denial of Service by comparing server response time
for a short input vs. a long input designed for catastrophic backtracking.

### Probe patterns

| Pattern | Short input | Long input | Targets |
|---------|------------|-----------|---------|
| Email-style | `aa@` | `a`×80 + `@` | Email validation regexes |
| URL/hostname | `aaaaaaaaaa.` | `a`×80 + `.` | URL/hostname validation |
| IP-style | `1.1.1.1.1.` | `1.` × 40 | IP address validation |

### Thresholds

```go
const (
    reDoSTimeRatio   = 5.0               // long must be ≥5× slower than short
    reDoSMinAbsDelay = 500 * time.Millisecond  // long must be ≥500ms absolute
    reDoSMaxShort    = 200 * time.Millisecond  // short must be <200ms (skip if server is slow)
)
```

All three conditions must hold simultaneously to minimize false positives.

### String field selection

The checker tests one field per call (the first string-typed field found):
path params → query params → body top-level string fields.

### False positive mitigation

- `reDoSMaxShort = 200ms`: if the server is already slow (high load), skip.
- `reDoSTimeRatio = 5`: requires a 5× slowdown, not just any variation.
- Network jitter can still cause false positives on very slow networks.

---

## PathDiscovery (Pre-Scan)

**Package:** `pathscan/`
**Timing:** once, before the main fuzzing loop
**Cannot be disabled via `-checker`**

Probes 70+ known sensitive paths that are typically not documented in OpenAPI specs.

### Built-in path categories

- Debug/development: `/debug`, `/api/debug`, `/_debug`, `/v1/debug`, `/v2/debug`, `/console`
- Environment: `/env`, `/.env`, `/config`, `/v1/info`, `/v2/info`, `/info`
- Spring Actuator: `/actuator`, `/actuator/env`, `/actuator/beans`, `/actuator/heapdump`, `/actuator/metrics`
- Monitoring: `/metrics`, `/health`, `/healthz`, `/readyz`, `/livez`
- Admin: `/admin`, `/admin/users`, `/admin/debug`, `/admin/stats`, `/management`, `/internal`, `/private`
- Versioning traps: `/v1/users`, `/api/v1/users`
- Target-specific: `/users/v1/_debug` (VAmPI), `/delivery/orders` (DVRestaurant), `/admin/reset-chef-password`
- GraphQL: `/graphql`, `/graphiql`, `/api/graphql`
- File server: `/ftp`, `/backup`, `/logs`, `/support/logs`
- Disclosure: `/.well-known/security.txt`, `/security.txt`

### Detection logic

```
For each candidate path:
    GET <targetURL><path>  (unauthenticated)

    if 2xx AND body matches sensitiveBodyRE:
        → HIGH: "Sensitive Data Exposed via Hidden Endpoint"
        (sensitiveBodyRE matches: SECRET_KEY, DATABASE_URL, JWT_SECRET,
         "password":, process.env., os.environ, "admin":true)

    if 2xx AND (auth configured) AND body has admin/password/secret/env/config:
        → MEDIUM: "Unauthenticated Access to Sensitive Endpoint"

    if 403 AND path description mentions "admin":
        → INFO: "Hidden Admin Endpoint Exists (IP-Restricted)"
```

### Custom wordlist format

```
# One path per line; tab-separated description is optional
/custom-debug	custom debug endpoint
/api/internal/config	internal config API
/v1/admin/users
```

```bash
./shelob-ng -spec api.json -url http://target \
    -path-wordlist /path/to/wordlist.txt \
    -duration 5m
```

---

## Writing a Custom Checker

### Minimal example

```go
package checkers

import (
    "context"
    "net/http"
    "shelob-ng/corpus"
)

type MyChecker struct{}

func (MyChecker) Name() string { return "MyChecker" }

func (MyChecker) Check(
    ctx context.Context,
    cctx CheckContext,
    entry *corpus.CorpusEntry,
    req *http.Request,
    resp *http.Response,
    body []byte,
) []Finding {
    // Example: flag when response body contains a credit card number
    if ccRE.Match(body) {
        return []Finding{{
            Checker:     "MyChecker",
            Severity:    SeverityHigh,
            Title:       "Credit Card Number in Response",
            Detail:      "PAN detected in response body",
            Method:      req.Method,
            URL:         req.URL.String(),
            StatusCode:  resp.StatusCode,
            PathPattern: entry.PathPattern,
            POC:         BuildCurlPOC(req, entry.Body),
        }}
    }
    return nil
}
```

### Stateful checker

If your checker needs to track state across calls, use a pointer receiver:

```go
type MyStatefulChecker struct {
    mu    sync.Mutex
    state map[string]int
}

func NewMyStatefulChecker() *MyStatefulChecker {
    return &MyStatefulChecker{state: make(map[string]int)}
}

func (c *MyStatefulChecker) Name() string { return "MyStateful" }
// ... Check() with c.mu.Lock() around state access
```

Register with `NewMyStatefulChecker()` in `All()` instead of a zero value.

### Issuing probe requests

```go
// Probe preserving primary auth
probe, _ := buildProbeWithCookies(ctx, req, entry, cctx.AuthCookies)
ApplyAuth(probe, cctx.APIKey, cctx.Token)
resp, _ := cctx.Client.Do(probe)

// Anonymous probe (no auth at all)
anonProbe, _ := buildProbeWithCookies(ctx, req, entry, nil)
// do NOT call ApplyAuth here

// user2 probe (BOLA testing)
user2Probe, _ := buildProbeWithCookies(ctx, req, entry, cctx.User2Cookies)
if cctx.APIKey != "" {
    user2Probe.Header.Set("X-Api-Key", cctx.APIKey)
}
// do NOT forward cctx.Token — it encodes user1's identity
```

### Register in All()

```go
// checkers/checker.go
func All() []Checker {
    return []Checker{
        // ... existing checkers ...
        MyChecker{},              // stateless: zero value
        NewMyStatefulChecker(),   // stateful: constructor
    }
}
```

Update `-checker` valid names in `cliArgs/cliArgs.go`.
