# Extending shelob-ng

This guide covers how to add custom checkers, mutation strategies, CSP adapters,
and payload wordlists to shelob-ng.

---

## Adding a Checker

### 1. Implement the Checker interface

Create `checkers/mychecker.go`:

```go
package checkers

import (
    "context"
    "fmt"
    "io"
    "net/http"

    "shelob-ng/corpus"
    log "github.com/sirupsen/logrus"
)

// MyChecker detects [describe what it detects].
//
// Detection sequence:
//   1. [describe trigger condition]
//   2. [describe probe if any]
//   3. [describe finding condition]
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
    // Early exit conditions
    if resp.StatusCode >= 500 {
        return nil  // skip server errors
    }

    // Detection logic
    if !myCondition(resp, body) {
        return nil
    }

    // Optional: issue a probe request
    probe, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL.String(), nil)
    if err != nil {
        log.Debugf("mychecker: build probe: %v", err)
        return nil
    }
    // Apply auth to probe
    for _, c := range cctx.AuthCookies {
        probe.AddCookie(c)
    }
    ApplyAuth(probe, cctx.APIKey, cctx.Token)

    probeResp, err := cctx.Client.Do(probe)
    if err != nil {
        return nil
    }
    defer probeResp.Body.Close()
    io.Copy(io.Discard, probeResp.Body) //nolint:errcheck

    if !myFindingCondition(probeResp) {
        return nil
    }

    return []Finding{{
        Checker:     "MyChecker",
        Severity:    SeverityHigh,   // or SeverityMedium, SeverityLow, SeverityInfo
        Title:       "Short description (≤80 chars)",
        Detail:      fmt.Sprintf("evidence: status %d", probeResp.StatusCode),
        Method:      req.Method,
        URL:         req.URL.String(),
        StatusCode:  probeResp.StatusCode,
        PathPattern: entry.PathPattern,
        POC:         BuildCurlPOC(probe, nil),
    }}
}
```

### 2. Register in All()

In `checkers/checker.go`:

```go
func All() []Checker {
    return []Checker{
        BehavioralPatterns{},
        // ... existing checkers ...
        MyChecker{},  // add here
    }
}
```

### 3. Add to valid checker names

In `cliArgs/cliArgs.go`, update the `-checker` flag description:

```go
checker := flag.String("checker", "",
    "... valid names: ...,MyChecker")
```

### 4. Write tests

Create `checkers/mychecker_test.go`:

```go
package checkers

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestMyChecker_FindsVulnerability(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
        w.Write([]byte(`{"vulnerable": true}`))
    }))
    defer srv.Close()

    chk := MyChecker{}
    entry := makeEntry("GET", "/api/test")
    req, _ := http.NewRequest("GET", srv.URL+"/api/test", nil)
    resp := makeRespWithCode(200)

    findings := chk.Check(context.Background(),
        CheckContext{Client: srv.Client()},
        entry, req, resp, []byte(`{}`))

    if len(findings) == 0 {
        t.Fatal("expected findings")
    }
    if findings[0].Severity != SeverityHigh {
        t.Errorf("expected HIGH, got %s", findings[0].Severity)
    }
}
```

### Stateful Checker

If your checker needs state across calls, use a pointer receiver with `sync.Mutex`:

```go
type MyStatefulChecker struct {
    mu    sync.Mutex
    state map[string]int
}

func NewMyStatefulChecker() *MyStatefulChecker {
    return &MyStatefulChecker{state: make(map[string]int)}
}

func (c *MyStatefulChecker) Name() string { return "MyStateful" }

func (c *MyStatefulChecker) Check(ctx context.Context, cctx CheckContext,
    entry *corpus.CorpusEntry, req *http.Request,
    resp *http.Response, body []byte) []Finding {

    key := entry.Method + "\x00" + entry.PathPattern

    c.mu.Lock()
    c.state[key]++
    count := c.state[key]
    c.mu.Unlock()

    if count < 10 {
        return nil
    }
    // ... detection logic
}
```

Register with `NewMyStatefulChecker()` (not `MyStatefulChecker{}`):

```go
func All() []Checker {
    return []Checker{
        // ...
        NewMyStatefulChecker(),  // pointer, not value
    }
}
```

---

## Adding a Mutation Strategy

### 1. Implement the Strategy interface

Create `mutator/mystrategy.go`:

```go
package mutator

import (
    "math/rand"
    "shelob-ng/corpus"
)

type myStrategy struct {
    rng *rand.Rand
}

func (s *myStrategy) Name() string { return "my_strategy" }

func (s *myStrategy) Apply(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error) {
    // entry is already a Clone() — modify freely
    obj, err := ParseJSONObject(entry.Body)
    if err != nil {
        return nil, StrategyNotApplicable
    }

    // Example: inject a custom field
    AddField(obj, "my_injection", "value")

    body, err := MarshalBody(obj)
    if err != nil {
        return nil, StrategyNotApplicable
    }
    entry.Body = body
    return entry, nil
}
```

Return `StrategyNotApplicable` when the strategy cannot act on this entry
(wrong content type, no body, no applicable fields, etc.).
The orchestrator will try the next strategy.

### 2. Register in NewMutator()

In `mutator/mutator.go`:

```go
func NewMutator(cfg Config) Mutator {
    // ...
    items := []weightedStrategy{
        {strategy: &byteLevelMutator{rng: rng}, weight: byteW},
        {strategy: &structuralMutator{rng: rng, schema: cfg.Schema}, weight: structW},
        {strategy: &securityMutator{rng: rng, payloads: cfg.Payloads}, weight: secW},
        {strategy: &ssrfMutator{rng: rng}, weight: 0.5},
        {strategy: &myStrategy{rng: rng}, weight: 0.3},  // add here
    }
    // ...
}
```

Weight determines selection probability relative to other strategies.
Total weight = 3.0 + 1.0 + 1.0 + 0.5 + 0.3 = 5.8 → my_strategy fires ~5% of the time.

### Helper functions

The `mutator` package provides several helpers:

```go
// JSON object operations
ParseJSONObject(body []byte) (map[string]interface{}, error)
MarshalBody(obj map[string]interface{}) ([]byte, error)
SetLeafString(obj map[string]interface{}, dottedPath, value string) error
CollectStringLeaves(obj map[string]interface{}) []string
AddField(obj map[string]interface{}, key string, value interface{})
RemoveField(obj map[string]interface{}, key string)

// Field selection
PickField(entry *corpus.CorpusEntry, rng *rand.Rand) (FieldTarget, bool)
PickStringFields(entry *corpus.CorpusEntry) []FieldTarget

// FieldTarget kinds
const (
    FieldPath   FieldKind = iota
    FieldQuery
    FieldHeader
    FieldCookie
    FieldBody
)
```

---

## Adding a PathDiscovery Path

To add paths to the built-in list, edit `pathscan/wordlist.go`:

```go
func builtinPaths() []Candidate {
    return []Candidate{
        // ... existing paths ...
        {"/my-custom-path", "description of what this path might expose"},
    }
}
```

Or use `-path-wordlist` at runtime to avoid modifying source code:

```
# my-paths.txt
/custom-debug    custom debug endpoint exposing env vars
/api/v0/admin    old admin API (deprecated but still active)
```

```bash
./shelob-ng -spec api.json -url http://target \
    -path-wordlist my-paths.txt
```

---

## Adding a BehavioralPatterns Pattern

To detect a new class of response artifact, add to `checkers/behavioral.go`:

```go
var patterns = []behavioralPattern{
    // ... existing patterns ...
    {
        regexp.MustCompile(`(?i)(YourPattern|AnotherPattern)`),
        "Your Pattern Title",
        SeverityHigh,   // or SeverityMedium
        false,          // htmlOnly: set to true for XSS-type patterns
    },
}
```

**Guidelines:**
- Prefer specific patterns over broad ones to minimize false positives.
- Use `(?i)` for case-insensitive matching.
- RE2 syntax only — no lookaheads, no backreferences.
- For XSS/HTML-specific patterns, set `htmlOnly: true` to avoid JSON false positives.
- Test against the target's error responses before deploying — some APIs echo
  back parts of the request in error messages, which can cause false positives.

---

## Adding an SSRF Payload

To add an SSRF payload URL to the ssrfMutator, edit `mutator/ssrf.go`:

```go
var ssrfPayloads = []string{
    // ... existing payloads ...
    "http://your-internal-service:8080/",       // internal service
    "http://169.254.0.1/",                       // alternate metadata IP
    "http://docker.for.mac.localhost:9200/",     // Docker Desktop Elasticsearch
}
```

Or add new field names to the URL field detector:

```go
var urlFieldNames = []string{
    // ... existing names ...
    "image_source",     // image fetcher field
    "notification_url", // webhook notification URL
}
```

---

## Writing a CSP Adapter

See [csp-protocol.md](csp-protocol.md) for the full protocol specification
and reference implementations in Node.js, Go, Python, and C.

The minimal contract:

```
POST /csp/reset → snapshot coverage as baseline → 200 OK
GET  /csp/dump  → return {"new_since_reset": [list of covered units since last reset]}
```

---

## Adding a Custom Payload Wordlist Format

The `mutator/payloads` package currently only supports newline-delimited text files.
To support a different format:

```go
// mutator/payloads/loader.go
func LoadFromCustomFormat(path string) (*Set, error) {
    // parse your format
    // call set.Add(payload) for each entry
}
```

Update `run/loadPayloads()` to detect and route custom formats by file extension.

---

## Modifying the Main Loop

The main fuzzing loop is in `run/run.go`. Key extension points:

### Pre-scan hook

Add before `display.Start()`:

```go
// Custom pre-scan
myPreScanFindings := myPreScan(ctx, httpClient, targetURL)
for _, f := range myPreScanFindings {
    logFinding(f, cfg.OutputDir, &seenFindings)
}
```

### Per-request hook

Add after the response is received:

```go
// Custom per-request processing
if myInterestingCondition(resp, body) {
    myCustomAction(entry, req, resp, body)
}
```

### Post-run hook

Add before `display.Done()`:

```go
// Custom reporting
myReporter.Write(cfg.OutputDir)
```

---

## Coding Conventions

### Package structure

Each package has a single responsibility. Cross-package dependencies flow
downward: `run/` → `checkers/`, `mutator/`, `corpus/`, `coverage/` → no circular imports.

### Error handling

- Checker probe failures are logged at `Debug` level and return `nil` (no finding).
- Mutator `StrategyNotApplicable` is expected — the orchestrator tries the next strategy.
- Fatal errors in `run/` terminate the process; all other errors degrade gracefully.

### Concurrency

- Checkers must be safe for concurrent `Check()` calls (multiple goroutines).
- Stateless checkers (zero-value structs) are inherently safe.
- Stateful checkers must use `sync.Mutex` or `sync.Map` for shared state.
- `*http.Client` is safe for concurrent use.

### Testing

Every checker should have:
1. A test that verifies the finding is produced when the vulnerability is present.
2. A test that verifies no finding when the server behaves correctly (rate limiter, 422, etc.).
3. A test that verifies the checker skips when preconditions are not met (wrong method, no body, etc.).

Use `httptest.NewServer` for mock servers. See `checkers/ratelimit_test.go` for patterns.
