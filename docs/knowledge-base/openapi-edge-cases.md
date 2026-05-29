# OpenAPI 3.x Edge Cases для фаззера

Источник: исследование агента + swagger-parser test fixtures.
Дата: 2026-05-29.

---

## 1. Composition Schemas: allOf / oneOf / anyOf / not

### Семантика для генерации входных данных

| Keyword | Смысл | Стратегия генерации |
|---------|-------|---------------------|
| `allOf` | объект должен удовлетворять ВСЕМ схемам | Слить `properties` всех схем, сгенерировать объект со всеми required полями |
| `oneOf` | объект удовлетворяет РОВНО ОДНОЙ схеме | Случайно выбрать одну ветку и генерировать из неё |
| `anyOf` | объект удовлетворяет ХОТЯ БЫ ОДНОЙ схеме | Как oneOf; также тестировать пересечения веток |
| `not` | объект НЕ должен удовлетворять схеме | Пропустить или вернуть random string — низкий ROI |

### Текущее состояние в shelob-ng

`generateInput.GenerateRandomDataModels` смотрит только на `schema.Type`.
Если spec содержит `oneOf: [Cat, Dog]` — `schema.Type` = nil → функция возвращает пустую строку.
**Эффект:** все polymorphic endpoints молча генерируют ничего полезного.

### Fix (приоритет: критический)

Добавить `resolveComposedSchema()` в `generateInput/`:
```go
func resolveComposedSchema(s *openapi3.Schema, depth int) *openapi3.Schema {
    if len(s.AllOf) > 0 {
        // Слить все Properties из всех AllOf схем
        merged := &openapi3.Schema{Type: &openapi3.Types{"object"}, Properties: openapi3.Schemas{}}
        for _, ref := range s.AllOf {
            for k, v := range ref.Value.Properties {
                merged.Properties[k] = v
            }
        }
        return merged
    }
    if len(s.OneOf) > 0 {
        // Случайно выбрать одну ветку
        return s.OneOf[rand.Intn(len(s.OneOf))].Value
    }
    if len(s.AnyOf) > 0 {
        return s.AnyOf[rand.Intn(len(s.AnyOf))].Value
    }
    return s
}
```

kin-openapi уже резолвит все `$ref` к моменту доступа к `.AllOf`, `.OneOf`, `.AnyOf` — они являются `[]*SchemaRef` с заполненным `.Value`.

### Test fixture
`swagger-parser: anyOf_OneOf.yaml` — oneOf: Book|Movie, anyOf: Movie|Book, mixed-type array items.

---

## 2. Discriminator

### Что это
```yaml
discriminator:
  propertyName: petType
  mapping:
    cat: "#/components/schemas/Cat"
    dog: "#/components/schemas/Dog"
```
Сообщает серверу, какой конкретный тип использовать среди `oneOf`/`anyOf` веток по значению поля.

### Проблема для фаззера
Без discriminator property сервер вернёт 422 **до** любой интересной обработки.
Без него вся сессия фаззинга на polymorphic endpoints = 422-шум.

### Fix
В `resolveComposedSchema()`: если `schema.Discriminator != nil`, добавить поле:
```go
obj[schema.Discriminator.PropertyName] = chosenBranchKey
// где chosenBranchKey = ключ из schema.Discriminator.Mapping для выбранной ветки
```

### Test fixtures
```
swagger-parser: discriminator-mapping-resolution/
  main-internal-mapping.yaml    — discriminator с mapping внутри файла
  main-external-mapping.yaml    — discriminator с $ref на внешние файлы
  main-no-mapping.yaml          — discriminator без mapping (implicit)
  main-no-mapping-oneof.yaml    — discriminator + oneOf без mapping
```

---

## 3. Circular $ref (рекурсивные схемы)

### Примеры
- `TreeNode.children[].items.$ref → TreeNode` (рекурсивный массив)
- Kubernetes: `Container.volumes[].configMap.items[].key` → обратно к `Container`
- swagger-parser fixture: `recursive.yaml` — `Inner.items.$ref → Inner`

### Проблема
`GenerateRandomDataModels` рекурсирует в `schema.Items.Value` и `schema.Properties` **без защиты от циклов**.
Circular spec → stack overflow фаззера.

### Fix (быстрый)
Добавить параметр `maxDepth int`, отрезать на глубине 5:
```go
func GenerateRandomDataModels(schema *openapi3.Schema, depth int) interface{} {
    if depth > 5 {
        return nil  // safe zero value
    }
    // ... остальная логика с depth+1 при рекурсии
}
```

### Test fixtures
```
swagger-parser:
  recursive.yaml                     — circular через array items
  recursive2.yaml                    — второй вариант
  issue_1751_recursive_array.yaml   — рекурсивный массив
  issue_1751_mutual_recursion.yaml  — взаимная рекурсия A→B→A
```

---

## 4. nullable: true vs type: [string, null]

### Разница между версиями

| OAS версия | Синтаксис | kin-openapi поле |
|-----------|-----------|-----------------|
| 3.0.x | `nullable: true` + основной тип | `schema.Nullable == true` |
| 3.1.x | `type: ["string", "null"]` | `*schema.Type` — массив из 2 элементов |

### Проблема
`GenerateRandomDataModels` делает `(*schema.Type)[0]` — берёт только первый тип, игнорирует nullable.
Никогда не генерирует `null`.

### Почему важно
Отправка `null` для nullable field упражняет другой code path.
BOLA/BFLA баги часто всплывают именно при `null` в ID-полях.

### Fix
15% вероятность вернуть `nil` (JSON `null`) когда `schema.Nullable == true` ИЛИ тип-массив содержит `"null"`.
В corpus seeding: добавить один seed на каждую операцию, где все nullable поля = null.

---

## 5. additionalProperties: false

### Что означает
Сервер отклоняет любое JSON-поле не объявленное в `properties`.
Строгие реализации: 422 на любое лишнее поле.

### Проблема для фаззера
`bodyAddField` в `mutator/structural.go` добавляет poison-поля (`admin`, `role`, `__proto__`).
Против API с `additionalProperties: false` → 100% 422 → весь бюджет впустую.

### Fix
В `SchemaIndex` хранить флаг `additionalProperties: false` по операциям.
В `bodyAddField`: если флаг установлен → пропустить injection лишних полей.
Mass assignment (issue #10) тестировать ТОЛЬКО для схем где `additionalProperties: true` или unset.

---

## 6. readOnly / writeOnly Properties

| Ключевое слово | Смысл | Для фаззера |
|---------------|-------|------------|
| `readOnly: true` | Поле в responses, НЕ в requests | ИСКЛЮЧИТЬ из request body — иначе strict API возвращает 422 |
| `writeOnly: true` | Поле в requests, НЕ в responses | ВКЛЮЧАТЬ в request body; кандидат для security payload injection |

### Текущее состояние
`GenerateRandomDataModels` итерирует все `schema.Properties` включая `readOnly`.
Фаззер отправляет `id`, `createdAt`, `updatedAt` в каждом request body.

### Fix
В `newEntryFromOperation` (`corpus/seed.go`): пропускать properties где `schema.Value.ReadOnly == true`.
`writeOnly` поля добавлять в список целей для security payload injection.

---

## 7. deprecated: true на операциях

Deprecated операции — высокоценные цели:
- Меньше строгая валидация (писались для старых клиентов)
- Возможные authentication bypasses — старые auth-схемы
- Могут иметь ссылки на удалённые ресурсы (BOLA potential)

**Рекомендация:** не фильтровать, но логировать предупреждение при достижении deprecated endpoint.

---

## 8. Parameter Style и Explode

### Матрица сериализации query params

| style | explode | Пример | Замечание |
|-------|---------|--------|-----------|
| `form` (default) | `true` (default) | `?color=blue&color=black` | Большинство API |
| `form` | `false` | `?color=blue,black,brown` | CSV в одном параметре |
| `spaceDelimited` | `false` | `?color=blue%20black` | Редко |
| `pipeDelimited` | `false` | `?color=blue\|black` | Редко |
| `deepObject` | `true` | `?filter[name]=John&filter[age]=30` | **Stripe, GitHub** — часто пропускается фаззерами |

### Текущее состояние
`urlParams.go` делает `queryParams.Add(name, fmt.Sprintf("%v", input))`.
Для array schema: `GenerateRandomDataModels` возвращает `[]interface{}{singleElement}` → форматируется как `[value]` (Go-нотация) → **всегда неверно**.

### Fix
В `corpus/seed.go` для `in: query` с array schema:
- Проверять `param.Explode` (pointer to bool; nil = default стиля)
- Проверять `param.Style`
- Строить query string соответственно

### Test fixture
`swagger-parser: style-explode.yaml` — form/spaceDelimited/explode=true/false для query + header, multipart encoding.

---

## 9. content на Parameters (альтернатива schema)

OpenAPI 3.0 позволяет параметру использовать `content` вместо `schema`:
```yaml
parameters:
  - name: filter
    in: query
    content:
      application/json:
        schema:
          type: object
```

### Текущее состояние
`SeedFromSpec`: если `param.Schema == nil` → параметр молча пропускается.
`content`-параметры никогда не генерируются.

### Fix
После проверки `param.Schema`, также проверять `param.Content`.
Если есть — извлечь схему из первого media type entry.

---

## 10. Cookie Parameters

### Проблема
`urlParams.go` добавляет cookie params через `httpRequest.Header.Add(key, value)`.
Результат: заголовок `key: value` вместо правильного `Cookie: key=value`.

### Fix
```go
// вместо: httpRequest.Header.Add(key, value)
httpRequest.AddCookie(&http.Cookie{Name: key, Value: value})
```

---

## 11. OpenAPI 3.1.0 — Новые возможности

### Ключевые отличия от 3.0.x

| Фича | OAS 3.0 | OAS 3.1 |
|------|---------|---------|
| Nullable | `nullable: true` | `type: ["string", "null"]` |
| Schema siblings с $ref | Запрещено | Разрешено |
| `webhooks` | Нет | Добавлено |
| `const` | Нет | `const: "pending"` |
| `type` как массив | Нет | `type: ["object", "string"]` |
| Базовый словарь | OpenAPI Schema | JSON Schema 2020-12 |
| `mutualTLS` security | Нет | Добавлено |

### Test fixtures (swagger-parser/3.1.0/)
```
oas3.1.yaml           — webhooks + type-array + const + mutualTLS
securitySchemes31.yaml — mutualTLS security scheme
schemaSiblings.yaml    — sibling keywords рядом с $ref
petstore-3.1.yaml      — полный petstore на 3.1
```

---

## 12. Links — Статические связи между операциями

### Формат
```yaml
responses:
  "201":
    links:
      GetUserById:
        operationId: getUser
        parameters:
          userId: "$response.body#/id"
```

### Значение для producer-consumer graph
`links` — формальный spec-уровневый механизм для producer-consumer зависимостей.
Парсинг `links` дополняет эвристику по именам полей (`id`/`uuid`) в `corpus/dependency.go`.

**Алгоритм:**
1. Итерировать все responses во всех операциях
2. Для каждого `response.Links`: сохранить `(sourceOpId, targetOpId, paramMapping)`
3. При построении sequence: если sourceOp успешен → извлечь linked value → inject в targetOp

### Test fixture
`swagger-parser: linkIssue.yaml` — `getRepositoriesByOwner` → `getRepository` через `$response.body#/slug`

---

## 13. Callbacks

Описывают webhooks — HTTP-запросы которые сервер делает ОБРАТНО к клиенту.
Практически не применимы при black-box API fuzzing (фаззер = клиент, не сервер).

**Рекомендация:** пропускать callbacks, документировать как unsupported.

### Test fixture
`swagger-parser: callbacks-issue/swagger.yaml` — callback через `$ref` на внешний `domain.yaml`

---

## 14. Security Scheme Patterns

### OAuth2 Flows для фаззера

| Flow | Автоматизация | Приоритет |
|------|--------------|-----------|
| `clientCredentials` | POST tokenUrl + client_id + secret | Реализовать (roadmap 2.4) |
| `password` | POST tokenUrl + username + password | Аналог текущего cookie auth |
| `authorizationCode` | Требует browser redirect | Использовать pre-obtained token |
| `implicit` | Deprecated в OAuth 2.1 | Использовать pre-obtained token |

### AND vs OR в security requirements

```yaml
security:
  - ApiKey: []          # OR item 1: только ApiKey
  - BearerAuth: []      # OR item 2 начало: BearerAuth
    SessionCookie: []   # AND с BearerAuth — оба нужны для item 2
```

**Внешний массив = OR, внутренний map = AND.**

**Текущий баг:** если одна операция требует ОДНОВРЕМЕННО ApiKey + Cookie (AND), cookie перезаписывается ApiKey в следующей итерации цикла.

### security: [] — явно публичные операции

Операция с `security: []` явно overrides глобальный security → публичная.
Использование: `/health`, `/login`, `/register`.

**Security testing:** публичные операции, возвращающие sensitive data → BOLA/information disclosure кандидаты.

---

## 15. Реальные API спеки с интересными паттернами

### GitHub REST API
- **~700 операций**, `oneOf` с 15+ вариантами для PR responses
- **Вложенные `allOf`** — почти каждая схема
- `x-github-*` extensions — игнорировать, не падать
- `application/json+patch` и `application/merge-patch+json` в PATCH операциях — shelob-ng игнорирует (нужна поддержка)

### Stripe API
- **~800 операций**
- `anyOf: [{type: string}, {type: integer}]` — polymorphic IDs везде
- **`deepObject` style** query params: `?expand[]=customer` — shelob-ng не поддерживает
- **Тела — form-encoded** (`application/x-www-form-urlencoded`), не JSON — shelob-ng игнорирует тела!

### Kubernetes API
- **~2500 операций** — самая сложная публичная спека
- **Глубокая рекурсия** — ОБЯЗАТЕЛЬНО нужен depth limit до запуска
- `application/strategic-merge-patch+json` — нестандартный content type
- `additionalProperties: {type: string}` для labels/annotations → shelob-ng генерирует `{}` (не итерирует AdditionalProperties)

---

## 16. Векторы атак, не реализованные в текущем фаззере

### Parameter Pollution
Один параметр в нескольких местах с конфликтующими значениями:
```
GET /api/account?role=user&role=admin
POST body: {"role":"user"} + query: ?role=admin
```
Разные frameworks разбирают по-разному (PHP = последний, Express = первый, Go = первый).

**Реализация:** в security mutator — для операций с query params, дополнительно инжектировать тот же параметр в URL даже если он определён только в body.

### Content-Type Confusion
- Отправить XML с `Content-Type: application/xml` когда spec декларирует только JSON
- `Content-Type: application/json; charset=utf-7` — UTF-7 обходит XSS фильтры

### HTTP Method Override
```
POST /api/resource/1
X-HTTP-Method-Override: DELETE
```
Обходит firewall rules блокирующие DELETE/PUT/PATCH.
Варианты: `X-Method-Override`, `_method` (Rails form param).

**Реализация:** для каждой DELETE/PUT/PATCH операции генерировать POST с override header.

---

## 17. additionalProperties: {schema} — пропускаемый паттерн

```yaml
labels:
  type: object
  additionalProperties:
    type: string
```

Kubernetes labels/annotations, OpenAPI extensions — все используют этот паттерн.

**Текущая проблема:** `GenerateRandomDataModels` итерирует только `schema.Properties`, игнорирует `schema.AdditionalProperties`.
Результат: объекты с только `additionalProperties` → `{}` (пустой объект).

**Fix:** В case `"object"`: если `len(schema.Properties) == 0` и `schema.AdditionalProperties != nil`, сгенерировать 1-3 random key-value пары по схеме AdditionalProperties.

---

## Приоритизированный список gaps для shelob-ng

| Приоритет | Gap | Файл | Усилие |
|-----------|-----|------|--------|
| **Critical** | allOf/oneOf/anyOf handling | `generateInput/generateInput.go` | 1 день |
| **Critical** | Circular $ref depth limit | `generateInput/generateInput.go` | 2 ч |
| **High** | readOnly field exclusion | `corpus/seed.go` | 1 ч |
| **High** | nullable null injection | `generateInput/generateInput.go` | 1 ч |
| **High** | additionalProperties: {schema} | `generateInput/generateInput.go` | 2 ч |
| **High** | Cookie params as proper Cookie header | `corpus/seed.go` / `urlParams/` | 1 ч |
| **High** | Form-encoded bodies support | `corpus/seed.go` | 2 ч |
| Medium | content on parameters | `corpus/seed.go` | 1 ч |
| Medium | deepObject style query params | `corpus/seed.go` | 2 ч |
| Medium | additionalProperties:false skip poison | `mutator/structural.go` | 1 ч |
| Medium | Discriminator property injection | `generateInput/` | 2 ч |
| Medium | Parameter pollution strategy | `mutator/security.go` | 2 ч |
| Medium | HTTP Method Override | `mutator/security.go` | 1 ч |
| Low | links parsing для producer-consumer | `corpus/dependency.go` | 1 день |
| Low | clientCredentials OAuth2 auto-token | `auth/auth.go` | 1 день |
