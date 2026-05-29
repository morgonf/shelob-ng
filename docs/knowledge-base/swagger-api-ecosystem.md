# Swagger-API Ecosystem

Источник: https://github.com/swagger-api — официальная org проекта OpenAPI/Swagger.
Дата сбора: 2026-05-29.

---

## Ключевые репозитории

| Репозиторий | Язык | Stars | Назначение |
|-------------|------|-------|------------|
| [swagger-ui](https://github.com/swagger-api/swagger-ui) | JS | 28 815 | Рендеринг OpenAPI в HTML UI |
| [swagger-codegen](https://github.com/swagger-api/swagger-codegen) | Mustache | 17 750 | Генерация клиентов/серверов из spec |
| [swagger-editor](https://github.com/swagger-api/swagger-editor) | JS | 9 437 | Онлайн-редактор OpenAPI spec |
| [swagger-core](https://github.com/swagger-api/swagger-core) | Java | 7 522 | Java-библиотека генерации OpenAPI из аннотаций |
| [swagger-parser](https://github.com/swagger-api/swagger-parser) | Java | 860 | Парсинг, валидация, dereference spec |
| [swagger-petstore](https://github.com/swagger-api/swagger-petstore) | Java | 325 | Эталонная реализация PetStore API v3 |
| [swagger-samples](https://github.com/swagger-api/swagger-samples) | JS/Java | 544 | Примеры интеграции с разными фреймворками |
| [swagger-inflector](https://github.com/swagger-api/swagger-inflector) | Java | 171 | Design-first server: OpenAPI spec → Java server |
| [swagger-converter](https://github.com/swagger-api/swagger-converter) | Shell | 150 | Конвертер Swagger 2.0 → OpenAPI 3.x |
| [apidom](https://github.com/swagger-api/apidom) | TypeScript | 99 | Семантический AST-парсер для OpenAPI/AsyncAPI |
| [validator-badge](https://github.com/swagger-api/validator-badge) | Java | 223 | Онлайн-валидатор Swagger/OpenAPI |

---

## swagger-petstore (официальная реализация)

**Docker:**
```bash
docker pull swaggerapi/petstore3
docker run -d -p 8080:8080 swaggerapi/petstore3
# OpenAPI spec: http://localhost:8080/api/v3/openapi.yaml
# Swagger UI: http://localhost:8080/
```

**Spec location:** `src/main/resources/openapi.yaml`
**Реализация:** Java + swagger-inflector (design-first)

### Ключевые особенности spec:
- `securitySchemes`:
  - `petstore_auth`: OAuth2 implicit flow (scopes: `write:pets`, `read:pets`)
  - `api_key`: apiKey в header `api_key`
- Content-type negotiation: `application/json`, `application/xml`, `application/x-www-form-urlencoded`
- `$ref` к `components/requestBodies` (reusable request bodies)
- `x-swagger-router-model` — vendor extension для маппинга на Java-классы
- Вложенные объекты: `Pet → Category`, `Pet → [Tag]`
- Enum в параметрах: `status` (available/pending/sold)
- Array query param с `explode: true`: `/pet/findByTags?tags=tag1&tags=tag2`

### Схемы компонентов:
```yaml
schemas:
  Pet:       # required: name, photoUrls; nested: Category, [Tag]
  Order:     # enum status: placed/approved/delivered
  Category:  # id + name
  Tag:       # id + name  
  User:      # 8 полей
  ApiResponse: # code + type + message
```

---

## swagger-parser — Test Fixtures

Репозиторий: `modules/swagger-parser-v3/src/test/resources/`
Содержит **185+ файлов** для регрессионного тестирования парсера.

### Категории edge cases (по именам файлов):

#### Composition schemas
| Файл | Что тестирует |
|------|--------------|
| `anyOf_OneOf.yaml` | `oneOf` + `anyOf` для responses, mixed-type arrays |
| `composed.yaml` | `allOf` с `$ref` — ExtendedAddress наследует Address |
| `simpleAllOf.yaml` | Простой `allOf` |
| `oneof-anyof.yaml` | Смешанное использование |
| `composedSchemaRef.yaml` | `$ref` внутри composed schema |

#### Recursive / circular schemas
| Файл | Что тестирует |
|------|--------------|
| `recursive.yaml` | `Inner.items.$ref → Inner` (circular через array) |
| `recursive2.yaml` | Второй вариант рекурсии |
| `issue_1751_recursive_array.yaml` | Рекурсивный массив |
| `issue_1751_mutual_recursion.yaml` | Взаимная рекурсия A→B→A |

#### Discriminator
| Файл | Что тестирует |
|------|--------------|
| `discriminator-mapping-resolution/main-internal-mapping.yaml` | Discriminator с `mapping` внутри файла |
| `discriminator-mapping-resolution/main-external-mapping.yaml` | Discriminator с `$ref` к внешним файлам |
| `discriminator-mapping-resolution/main-no-mapping.yaml` | Discriminator без `mapping` (implicit) |
| `discriminator-mapping-resolution/main-no-mapping-oneof.yaml` | Discriminator + `oneOf` без mapping |

#### Parameter styles
| Файл | Что тестирует |
|------|--------------|
| `style-explode.yaml` | `style: form/spaceDelimited` + `explode: true/false` для query и header |
| `blankQueryParameter.yaml` | Пустые query параметры |
| `emptyQueryParameter.yaml` | Query с пустым значением |
| `dotted-property-names.yaml` | Свойства с точками в именах |

#### OpenAPI 3.1.0
| Файл | Что тестирует |
|------|--------------|
| `3.1.0/oas3.1.yaml` | `webhooks`, `type: [object, string]`, `const`, `mutualTLS` security |
| `3.1.0/securitySchemes31.yaml` | `mutualTLS` security scheme (новый в 3.1) |
| `3.1.0/petstore-3.1.yaml` | Полный petstore на 3.1 |
| `3.1.0/schemaSiblings.yaml` | Sibling keywords рядом с `$ref` (разрешено в 3.1, не в 3.0) |

#### Links & Callbacks
| Файл | Что тестирует |
|------|--------------|
| `linkIssue.yaml` | `links` в responses: `getRepositoriesByOwner` → `getRepository` |
| `callbacks-issue/swagger.yaml` | `callbacks` с `$ref` во внешний файл domain.yaml |

#### $ref patterns
| Файл | Что тестирует |
|------|--------------|
| `nested-file-references/` | Цепочка $ref через несколько файлов |
| `relative-file-references/` | Относительные пути $ref |
| `internal-refs.yaml` | Только внутренние #/components/... |
| `remote_references/` | $ref на удалённые URL |
| `ref-without-component/` | $ref напрямую на объект (не через components) |

#### Null / optional values  
| Файл | Что тестирует |
|------|--------------|
| `null-example.yaml` | `nullable: true` (OAS 3.0) |
| `null-full-example.yaml` | Полный пример с nullable fields |
| `unexpectedNullValues.yaml` | Неожиданные null в spec |
| `media-type-null-example.yaml` | null в media type примере |

#### Validation issues (найденные баги)
Файлы `issue-NNN.yaml` — документируют конкретные баги парсера:
- `issue-1015.json` — schema без type
- `issue-1040/` — circular ref через $ref chain
- `issue-1108.yaml` — additionalProperties с $ref
- `issue-1261.yaml` — discriminator без mapping
- `issue-1309.yaml` — oneOf с discriminator
- `billion_laughs_snake_yaml.yaml` — DoS атака через YAML anchors (billion laughs)

---

## swagger-parser — Ключевые модули

```
modules/
  swagger-parser-core/         — базовые интерфейсы, AuthorizationValues
  swagger-parser-v3/           — OpenAPI 3.x парсер (основной)
  swagger-parser-v2-converter/ — Swagger 2.0 → OpenAPI 3.0 конвертер
  swagger-parser-safe-url-resolver/ — безопасный резолвер URL (защита от SSRF)
```

### safe-url-resolver — важно для фаззера
`swagger-parser-safe-url-resolver` блокирует $ref на:
- `localhost`, `127.0.0.1`, `0.0.0.0`
- Private network ranges (10.x, 192.168.x, 172.16.x)
- `file://` URLs
→ Фаззер должен помнить: spec с $ref на внутренние URL может не загрузиться.

---

## swagger-core — генерация spec из Java-аннотаций

Паттерны, которые генерирует swagger-core и редко встречаются в hand-written specs:
- `x-swagger-router-model: package.ClassName` — vendor extension на каждой схеме
- `x-swagger-router-controller: ControllerName` — на операциях
- Автоматическое добавление `default` response на все операции
- Вложенные `$ref` через несколько уровней наследования Java-классов

---

## apidom — AST-парсер нового поколения

Заменяет swagger-parser для OAS 3.1 + AsyncAPI.
Поддерживает: OpenAPI 3.0, 3.1, AsyncAPI 2.x, JSON Schema.
Важно: **LSP-сервер** для VS Code (`apidom-lsp-vscode`) — валидация spec в IDE.

---

## Полезные тестовые данные для shelob-ng

### Specs из swagger-parser test fixtures (скачать локально):
```bash
# Recursive schema — тест на бесконечную рекурсию
gh api repos/swagger-api/swagger-parser/contents/modules/swagger-parser-v3/src/test/resources/recursive.yaml \
  --jq '.content' | base64 -d > docs/fixtures/recursive.yaml

# allOf composition  
gh api repos/swagger-api/swagger-parser/contents/modules/swagger-parser-v3/src/test/resources/composed.yaml \
  --jq '.content' | base64 -d > docs/fixtures/composed-allof.yaml

# oneOf/anyOf
gh api repos/swagger-api/swagger-parser/contents/modules/swagger-parser-v3/src/test/resources/anyOf_OneOf.yaml \
  --jq '.content' | base64 -d > docs/fixtures/oneof-anyof.yaml

# Parameter styles
gh api repos/swagger-api/swagger-parser/contents/modules/swagger-parser-v3/src/test/resources/style-explode.yaml \
  --jq '.content' | base64 -d > docs/fixtures/style-explode.yaml

# Links
gh api repos/swagger-api/swagger-parser/contents/modules/swagger-parser-v3/src/test/resources/linkIssue.yaml \
  --jq '.content' | base64 -d > docs/fixtures/links.yaml
```
