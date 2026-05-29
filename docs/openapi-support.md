# OpenAPI Support

shelob-ng supports OpenAPI 3.x specifications. This document describes which
features are supported, which have limitations, and which are not supported.

---

## Supported: Core Features

### Path Parameters

All path parameter styles are resolved:

```yaml
parameters:
  - name: userId
    in: path
    required: true
    schema:
      type: integer
      format: int64
```

Path parameters are generated from the schema and substituted into the URL
template. The `DynamicValuePool` reuses real server-assigned IDs when available.

### Query Parameters

All query parameters (required and optional) are generated and appended to the URL.
The `explode` and `style` fields affect serialization — see [Limitations](#limitations).

```yaml
parameters:
  - name: status
    in: query
    schema:
      type: string
      enum: [available, pending, sold]
```

Enum values are respected: the generator picks one at random.

### Request Bodies

JSON request bodies are fully supported. The schema is parsed recursively,
resolving `$ref`, `allOf`, `oneOf`, `anyOf`.

```yaml
requestBody:
  required: true
  content:
    application/json:
      schema:
        $ref: '#/components/schemas/Pet'
```

For operations with multiple content types, `application/json` is preferred.

### Security Schemes

shelob-ng applies credentials based on the configured flags, not the spec's
security declarations. The security declarations are used only by `AuthBypassRule`
to identify which operations require authentication.

Supported credential mechanisms:

| Auth type | CLI flag | Header set |
|-----------|---------|-----------|
| Cookie-based login | `-user` / `-password` | `Cookie: session=...` |
| API key | `-apikey` | `X-Api-Key: <value>` |
| Bearer token | `-token` | `Authorization: Bearer <value>` |
| JWT from login | auto-detected | `Authorization: Bearer <jwt>` |

### $ref Resolution

All `$ref` references are resolved by `kin-openapi` before shelob-ng processes
the spec. Both local (`#/components/schemas/...`) and relative file references
work correctly.

### Response Validation (SchemaViolation)

shelob-ng validates actual response bodies against the declared response schema
using `kin-openapi`'s `openapi3filter.ValidateResponse`. This catches:
- Undeclared status codes
- Wrong Content-Type
- Missing required fields
- Type mismatches
- `additionalProperties: false` violations

---

## Supported: Schema Types

| Type | Generated value |
|------|----------------|
| `string` | Random letters, respecting `minLength`/`maxLength`; format-specific for `date`, `date-time`, `email`, `uuid`, `uri`, `hostname`, `ipv4`, `ipv6`, `password`, `byte`, `binary` |
| `integer` | Random int32/int64, respecting `minimum`/`maximum` and `enum` |
| `number` | Random float, respecting `minimum`/`maximum` |
| `boolean` | Random true/false |
| `array` | Single-element array with generated item |
| `object` | All declared properties generated recursively |
| `allOf` | Properties merged from all sub-schemas |
| `oneOf` | One branch selected at random |
| `anyOf` | One branch selected at random |

### Depth Limit

Recursive schemas are truncated at depth 5 to prevent stack overflows.
Properties at depth > 5 receive `nil` (JSON `null`).

---

## Supported with Limitations

### Parameter Styles

The `style` and `explode` fields affect how array and object parameters are
serialized in the query string. shelob-ng serializes array parameters using
the `form` style with `explode: true` (default for query params):

```
?color=blue&color=black  (explode: true)
```

Other styles are **not** currently implemented:
- `spaceDelimited` → `?color=blue%20black`
- `pipeDelimited` → `?color=blue|black`
- `deepObject` → `?filter[name]=John&filter[age]=30`
- `matrix`, `label` (path params)

This means APIs that require `deepObject` style (Stripe, GitHub) will receive
incorrectly serialized query parameters for object-type params.

### Optional Parameters

Optional parameters are included in seeds when `IncludeOptionalParams = true`
(the default). However, the structural mutator picks only **one** field per
mutation, so not all combinations of optional parameters are exhausted.

### Cookie Parameters

Cookie parameters declared with `in: cookie` are currently added via
`req.Header.Add("Cookie", ...)` instead of `req.AddCookie(...)`. This is
functionally equivalent for most servers but does not preserve cookie attributes
(path, domain, httpOnly).

### `nullable: true` / `type: ["string", "null"]`

Nullable fields (OpenAPI 3.0 `nullable: true` or OpenAPI 3.1 `type: ["string", "null"]`)
never generate `null` values. The generator always picks the non-null type.

Null values can reveal code paths that handle missing data — this is a known
gap. Workaround: add `null` to security payload wordlists.

### `readOnly` Properties

Properties marked `readOnly: true` are still included in request body generation.
Many strict APIs return 422 when read-only fields are sent. This generates
noise in SchemaViolation findings.

### `format: binary`

File upload parameters (binary format) generate random byte sequences.
Actual file content is not provided — real MIME types and file structures
are not generated.

---

## Not Supported

### OpenAPI 2.0 (Swagger)

shelob-ng requires OpenAPI 3.x. Convert 2.0 specs first:

```bash
# Using swagger-converter (official)
docker run --rm -v $(pwd):/spec swaggerapi/swagger-converter \
    /spec/swagger.yaml > openapi3.yaml

# Using api-spec-converter
npx api-spec-converter --from=swagger_2 --to=openapi_3 swagger.yaml > openapi3.yaml
```

### Callbacks

`callbacks` objects in the spec (webhook definitions) are not exercised.
shelob-ng is a client-side fuzzer and does not set up HTTP listeners for
server-to-client callbacks.

### Links

Response `links` objects (which declare producer-consumer relationships
formally in the spec) are not parsed. The dependency graph uses heuristics
(field name matching) instead. Parsing `links` would improve accuracy —
see [roadmap issue #1](../docs/knowledge-base/roadmap.md).

### `content` on Parameters

Parameters using `content` (a media-type map) instead of `schema` are skipped.
This is a rare pattern used for complex JSON-encoded query parameters.

```yaml
# Not supported:
parameters:
  - name: filter
    in: query
    content:
      application/json:
        schema:
          type: object
```

### Multiple Servers

shelob-ng uses a single target URL (`-url` flag or `servers[0].url`).
Operations bound to different servers (when `servers` is declared per-path)
all go to the same target.

### Discriminator Mapping

The `discriminator` object is not used during input generation. When generating
`oneOf`/`anyOf` bodies, the discriminator property is not automatically set.
APIs that require the discriminator field to match the chosen branch will
return 422 on all such requests.

### OAuth2 Auto-Login

OAuth2 `clientCredentials` and `password` flows are not automated.
Use `-token <pre-obtained-token>` instead.

### `application/x-www-form-urlencoded`

Form-encoded bodies are not generated. Operations that declare only
`application/x-www-form-urlencoded` receive no body.

### `multipart/form-data`

Multipart bodies are not generated. File upload operations receive no body.

---

## Spec Compatibility Tips

### Ensure server URL is correct

```yaml
servers:
  - url: http://localhost:3000  # must match -url flag or be overridden
```

Use `-url` to override: `./shelob-ng -spec api.yaml -url http://localhost:3000`

### Declare response schemas for producer-consumer

The dependency graph works best when POST operations declare their response schema:

```yaml
paths:
  /api/orders:
    post:
      responses:
        '201':
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:          # ← required for dependency graph
                    type: integer
```

Without `id` in the response schema, the dependency graph falls back to
runtime learning (still works, but only after the first successful POST).

### Mark auth-required operations

For `AuthBypassRule` to fire correctly, operations must declare their
security requirements:

```yaml
# Global security (applies to all operations):
security:
  - bearerAuth: []

# Per-operation override (explicitly public):
paths:
  /health:
    get:
      security: []   # explicitly public — AuthBypassRule won't fire here
```

### Use consistent ID field names

The dependency graph recognizes: `id`, `uuid`, `key`, `slug`, `token`, `name`.
If your API uses a different field name (e.g., `orderId`, `record_id`), runtime
learning will still detect it from response bodies, but only after the first
successful POST.

---

## OpenAPI 3.1 Notes

shelob-ng processes 3.1 specs but has partial support for 3.1-specific features:

| Feature | Support |
|---------|---------|
| `type: ["string", "null"]` | Partial — picks first non-null type |
| `const` keyword | Not supported — treated as enum with one value |
| `webhooks` top-level | Not supported |
| Schema siblings alongside `$ref` | Supported (kin-openapi handles) |
| `mutualTLS` security scheme | Ignored |
| JSON Schema 2020-12 dialect | Partial — kin-openapi handles most cases |
