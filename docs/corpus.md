# Corpus Management

The corpus is the central data structure of shelob-ng's fuzzing loop. It stores
HTTP request templates (CorpusEntries) that proved interesting — either by
exercising new code coverage or by being the first request to reach a particular
API operation.

---

## CorpusEntry

The fundamental unit of the corpus. Represents one reproducible HTTP request:

```go
type CorpusEntry struct {
    // Request specification
    Method       string                 // "GET", "POST", "DELETE", ...
    PathPattern  string                 // "/api/Users/{id}" (OpenAPI template)
    OperationID  string                 // spec.operationId
    PathParams   map[string]interface{} // {"id": int64(42), "format": "json"}
    QueryParams  map[string]string      // {"q": "test", "page": "1"}
    HeaderParams map[string]string      // {"X-Custom": "value"}
    CookieParams map[string]string
    Body         []byte                 // raw JSON/XML/binary
    ContentType  string                 // "application/json"

    // Corpus metadata (excluded from hash / dedup key)
    CoverageDelta uint64   // V8 blocks added when this entry was first saved; 0 for seeds
    UseCount      uint64   // times this entry has been selected for mutation
    Generation    uint32   // 0 = seeded from spec; increments per mutation cycle
}
```

### Hashing

`entry.Hash()` produces a SHA-256 hash of the request specification fields
(all except `CoverageDelta`, `UseCount`, `Generation`). Used to detect duplicate
entries. Two mutations of the same entry that happen to produce the same parameters
will hash identically and the second will be rejected by `corpus.Add()`.

### Cloning

Mutators always receive `entry.Clone()` — a deep copy of all maps and slices.
This prevents mutation state from leaking back into the corpus.

---

## Selection

### Weight Formula

```
weight(entry) = log2(1 + CoverageDelta) / log2(2 + UseCount)
```

- **Numerator grows** with coverage delta: inputs that triggered more new blocks
  are selected more often.
- **Denominator grows** with use count: frequently-used entries lose priority,
  preventing the fuzzer from fixating on a small number of high-delta inputs.
- Seeds (`CoverageDelta = 1`) start with `weight ≈ 1.0 / log2(2) = 1.0`.

### Selection Algorithm

Weighted random selection with prefix sums (O(log n)):

```
1. Compute cumulative weight array: cum[i] = sum(weight[0..i])
2. Pick r = random in [0, cum[last]]
3. Binary search for i where cum[i-1] ≤ r < cum[i]
4. Return entries[i]
```

This O(log n) algorithm makes selection efficient even for large corpora (15k entries).

### Priority Rules

1. Mutated entries (`Generation > 0`) are weighted as described above.
2. Seeds (`Generation = 0`) are selected uniformly at random, weighted equally.
3. When the corpus contains only seeds (no successful mutations yet), seeds are
   selected in a round-robin pattern to ensure all operations are visited early.

---

## Admission

An entry is added to the corpus when at least one of:

1. **CSP delta > 0** — the request caused new code blocks to be executed.
   The entry is stored with `CoverageDelta = delta`.

2. **First 2xx for the operation** — the request is the first to successfully
   reach a particular `(method, pathPattern)` combination.
   Stored with synthetic `CoverageDelta = 1`.
   This ensures all reachable API operations enter the corpus even when CSP
   is disabled.

### Maximum Size

The corpus holds at most **15,000 entries**. On overflow, the entry with the
lowest `Weight()` is evicted.

```go
const maxCorpusSize = 15_000
```

This cap prevents memory growth during very long runs. In practice, most APIs
have far fewer than 15,000 meaningfully distinct inputs.

---

## Seeding

At startup, `corpus.SeedFromSpec()` generates initial entries from the OpenAPI spec:

```go
for each operation in spec.Paths:
    for i in 0..SeedCount (default 3):
        entry = newEntryFromOperation(method, path, operation)
        corpus.Add(entry, delta=1)
```

For each parameter, `generateInput.GenerateRandomDataModels()` is called with
the schema. Seeds cover:

- Required path, query, header, and cookie parameters
- Optional parameters (when `IncludeOptionalParams = true`, the default)
- Request body (preferred: `application/json`; fallback: first available content type)

### Schema-Aware Generation

```
schema.Type == "string":
  if schema.Pattern: generate matching string via regex
  if schema.Format:  format-specific (date, uuid, email, uri, ...)
  if schema.Enum:    pick random enum value
  else: random letters, respecting minLength/maxLength

schema.Type == "integer":
  if schema.Min/Max: random integer within bounds
  if schema.Enum: pick random enum
  else: format-specific (int32/int64)

schema.Type == "number": similar to integer with float range

schema.Type == "boolean": random true/false

schema.Type == "array":
  generate one item of schema.Items type (depth tracking)

schema.Type == "object":
  for each property in schema.Properties:
    generate value for property schema (depth tracking)
  if additionalProperties schema: generate 1-3 random key-value pairs

schema.AllOf / OneOf / AnyOf:
  resolveComposed() → pick one branch or merge all, then recurse
```

### Circular Reference Protection

Recursive schemas (e.g., `TreeNode` with `children: [TreeNode]`) are handled
by a depth cap of 5:

```go
const maxGenerateDepth = 5

func generateRandom(schema *openapi3.Schema, depth int) interface{} {
    if depth > maxGenerateDepth {
        return nil  // safe zero value
    }
    // ... recurse with depth+1
}
```

---

## Dynamic Value Pool

The `DynamicValuePool` harvests values from successful API responses and reuses
them as path parameters in future requests.

### Extraction

After every HTTP response with a 2xx status:

```go
pool.Extract(responseBody)
```

This walks the JSON body recursively and stores each leaf value in a per-key
ring buffer (256 entries per key):

```
{"user": {"id": 42, "email": "alice@example.com"}}
    → pool["id"]    ← 42
    → pool["email"] ← "alice@example.com"
```

### Usage

When building a path parameter:

```go
value = pool.GetValue(paramName)
if value == nil:
    value = generateRandom(paramSchema, 0)  // 30% of the time, or no pooled values
```

70% of path parameter values are taken from the pool; 30% are freshly generated.
This ensures both deep exploitation of known resources and occasional exploration
of new inputs.

---

## Persistence

### Save

At shutdown (`-corpus-dir` set):

```
<corpus-dir>/
  index.json        {"version": 1, "entry_count": 243, "saved_at": "..."}
  entries/
    abc123.json     full CorpusEntry serialized as JSON
    def456.json
    ...
```

### Load

At startup (`-corpus-dir` set and directory exists):

1. Read `index.json` — verify version compatibility
2. Load all `entries/*.json` files
3. Call `corpus.Add()` for each — entries that hash-collide with seeds are skipped
4. Log: `corpus: N entries total after loading from <dir>`

---

## Dependency Graph

The dependency graph pre-executes "producer" operations before "consumer"
operations so that path parameters carry real resource IDs.

### Structure

```go
type ProducerBinding struct {
    ConsumerPattern string  // "/api/Users/{id}"
    PathParam       string  // "id"
    ProducerPattern string  // "/api/Users"
    IDField         string  // "id" (field name in producer response body)
}
```

### Build

At startup, the spec is analyzed for producer-consumer relationships:

```
For each POST /X in spec:
    response schemas → look for id/uuid/key/slug fields
    child paths → find /X/{param}
    if both found: register ProducerBinding
```

Common ID field names: `id`, `uuid`, `key`, `slug`, `token`, `name`.

### Runtime Learning

When the spec has no response schemas (brownfield APIs), bindings are
discovered at runtime after the first successful POST:

```
POST /api/orders → 201 {"id": 42, "status": "pending"}
  → LearnProducer:
      found field "id" in response body
      spec has child path /api/orders/{orderId}
      → register binding: /api/orders/{orderId} ← "id" from POST /api/orders
```

### Execution

Before building a consumer request:

```
1. binding = depGraph.FindBinding("/api/orders/{orderId}")
2. Execute producer: POST /api/orders (same auth, fresh random body)
3. Extract: id = ExtractJSONField(producerResp.Body, "id") → 42
4. Inject: entry.PathParams["orderId"] = 42
5. Build + send: GET /api/orders/42 → 200 OK (real resource!)
```

On producer failure: consumer proceeds with pooled or random ID (graceful degradation).

---

## CRUD Sequences

Every 20 main-loop iterations, shelob-ng runs one CRUD sequence (round-robin).
CRUD sequences are derived from the spec at startup:

```
For each POST /X where spec defines /X/{param}:
    Step 1: POST /X            → create, extract {id}
    Step 2: GET  /X/{id}       → verify creation (expect 2xx)
    Step 3: DELETE /X/{id}     → delete (expect 2xx)
    Step 4: GET  /X/{id}       → probe after delete (expect 4xx!)
```

If step 4 returns 2xx, the server has a **UseAfterFree** vulnerability:
the resource is still accessible after deletion.

Sequence results are written to `<output>/replays/` with the full step log
and any findings.

---

## Corpus Size Over Time

In a typical run against a well-structured API:

```
t=0s:    171 seeds (3 per operation × 57 operations)
t=30s:   ~200 (first 2xx signals for new operations)
t=5m:    ~500-2000 (coverage-guided growth, CSP mode)
         ~250-400 (pure-random mode)
t=1h:    ~2000-8000 (stabilizes as coverage saturates)
```

In pure-random mode (`-csp-disable`), corpus growth is bounded by the number
of distinct API operations (each contributes at most one "first 2xx" entry).
In coverage-guided mode, every unique code path adds an entry, producing
richer corpora.
