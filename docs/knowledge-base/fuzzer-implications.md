# Fuzzer Implementation Implications

Actionable задачи для shelob-ng на основе анализа OpenAPI edge cases и тестовых мишеней.
Дата: 2026-05-29.

Это — рабочий список. Каждый пункт отсылает к детальному описанию в `openapi-edge-cases.md`.

---

## Tier 0: Критические исправления (блокируют работу на реальных спеках)

### T0.1 — Circular $ref depth limit
**Проблема:** stack overflow на specs с рекурсивными схемами (Kubernetes, любая tree-структура).
**Где:** `generateInput/generateInput.go` — `GenerateRandomDataModels`
**Fix:** добавить параметр `depth int`, обрезать на 5, вернуть `nil`
**Тест:** `docs/fixtures/recursive.yaml` — без fix → stack overflow

### T0.2 — allOf/oneOf/anyOf schema resolution
**Проблема:** polymorphic schemas молча генерируют пустые данные → 100% 422 на endpoints
**Где:** `generateInput/generateInput.go` — новая функция `resolveComposedSchema()`
**Fix:** для allOf — слить properties; для oneOf/anyOf — случайно выбрать одну ветку
**Тест:** создать spec с `oneOf: [Cat, Dog]`, убедиться что генерируются валидные тела

---

## Tier 1: Высокий приоритет (качество данных, снижение 422-шума)

### T1.1 — readOnly field exclusion
**Проблема:** `id`, `createdAt`, `updatedAt` отправляются в request body → 422 на strict APIs
**Где:** `corpus/seed.go` — `newEntryFromOperation`
**Fix:** пропускать `schema.Value.ReadOnly == true`

### T1.2 — nullable null injection
**Проблема:** null никогда не генерируется → code paths для null не тестируются
**Где:** `generateInput/generateInput.go`
**Fix:** 15% probability вернуть `nil` если `schema.Nullable || type contains "null"`

### T1.3 — additionalProperties: {schema} generation
**Проблема:** `{type: object, additionalProperties: {type: string}}` → всегда `{}`
**Где:** `generateInput/generateInput.go` — case `"object"`
**Fix:** если `len(schema.Properties) == 0 && schema.AdditionalProperties != nil` → генерировать 1-3 random KV

### T1.4 — Cookie params as proper Cookie: header
**Проблема:** `in: cookie` параметры добавляются как raw headers вместо `Cookie: name=value`
**Где:** `urlParams/urlParams.go`
**Fix:** `httpRequest.AddCookie(&http.Cookie{Name: key, Value: value})`

### T1.5 — Form-encoded bodies support
**Проблема:** Stripe и многие legacy APIs используют `application/x-www-form-urlencoded`; shelob-ng игнорирует тела
**Где:** `corpus/seed.go` — добавить case для `application/x-www-form-urlencoded`
**Fix:** генерировать `url.Values`, кодировать как form body

### T1.6 — additionalProperties:false → skip poison field injection
**Проблема:** добавление `admin`/`role` полей к strict schema → 100% 422, нет signal
**Где:** `mutator/structural.go` — `bodyAddField`
**Fix:** проверять `schema.AdditionalPropertiesAllowed == false`; если true → пропустить

---

## Tier 2: Средний приоритет (покрытие нестандартных API)

### T2.1 — content on parameters
**Проблема:** параметры с `content:` (JSON-encoded query params) молча пропускаются
**Где:** `corpus/seed.go` — `SeedFromSpec`
**Fix:** после проверки `param.Schema`, fallback на `param.Content`

### T2.2 — deepObject style query params
**Проблема:** `?filter[name]=John&filter[age]=30` (Stripe, GitHub) не генерируется
**Где:** `corpus/seed.go` — генерация query params
**Fix:** проверять `param.Style == "deepObject"`, форматировать соответственно

### T2.3 — Discriminator property injection
**Проблема:** polymorphic bodies без discriminator поля → 422
**Где:** `generateInput/` или `resolveComposedSchema()`
**Fix:** если `schema.Discriminator != nil`, добавить `{discriminatorField: branchKey}`

### T2.4 — Parameter pollution strategy
**Проблема:** дублирование параметра в разных местах с конфликтом не тестируется
**Где:** `mutator/security.go` — новая стратегия
**Fix:** для query params, инжектировать те же имена в URL даже если они body-only

### T2.5 — HTTP Method Override testing
**Проблема:** firewall bypass через X-HTTP-Method-Override не тестируется
**Где:** `mutator/security.go`
**Fix:** для DELETE/PUT/PATCH операций, генерировать дополнительный POST + override header

### T2.6 — OAS 3.1 type array support
**Проблема:** `type: ["string", "null"]` → берётся только первый тип
**Где:** `generateInput/generateInput.go`
**Fix:** если type — массив, итерировать; 15% — выбрать "null" если он есть

---

## Tier 3: Долгосрочно (новые классы тестирования)

### T3.1 — links parsing для producer-consumer
Формальный механизм для зависимостей вместо эвристики по именам полей.
`corpus/dependency.go` — дополнить существующую реализацию.

### T3.2 — clientCredentials OAuth2 auto-token
`auth/auth.go` — при `oauth2` flow `clientCredentials`: автоматически получать token.

### T3.3 — Content-Type confusion strategy
Отправлять XML с `Content-Type: application/xml` когда spec декларирует JSON.
Новая стратегия в `mutator/security.go`.

### T3.4 — Spec pre-scan report
Перед фаззингом: отчёт по spec — deprecated ops, ops без security [], polymorphic schemas, circular refs.
Помогает приоритизировать что тестировать.

---

## Связь с GitHub Issues

| Issue | Связанные gaps |
|-------|---------------|
| #1 producer-consumer (CLOSED) | T3.1 (links) дополнит |
| #2 BFLA (CLOSED) | — |
| #3 grammar constraints (CLOSED) | T1.6 (additionalProperties:false) дополняет |
| #4 per-op corpus | T1.1 (readOnly) помогает качеству seeds |
| #5 SARIF (CLOSED) | — |
| #6 ResourceHierarchy | T2.4 (parameter pollution) связан |
| #10 mass assignment | T1.6 (skip poison for strict schemas) |
| Новые | T0.1, T0.2 — добавить как issues |

---

## Порядок реализации

```
Week 1:   T0.1 + T0.2 (критические, ~0.5 дня каждый)
Week 1:   T1.1 + T1.2 + T1.4 (~1 ч каждый)
Week 2:   T1.3 + T1.5 + T1.6 (~2 ч каждый)
Week 3+:  T2.x по мере необходимости
```

После T0.1 + T0.2: запустить на Kubernetes spec (`/openapi/v2`) → benchmark 2xx rate.
После T1.x: запустить на Stripe spec → проверить что тела form-encoded работают.
