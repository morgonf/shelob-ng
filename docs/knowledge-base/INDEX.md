# Shelob-NG Knowledge Base

База знаний по OpenAPI, REST API тестированию и тестовым мишеням фаззера.
Создана: 2026-05-29. Пополняется итеративно.

---

## Файлы базы знаний

| Файл | Содержимое | Статус |
|------|-----------|--------|
| [swagger-api-ecosystem.md](swagger-api-ecosystem.md) | Swagger-api org: все репозитории, test fixtures, Petstore spec | ✅ Ready |
| [openapi-edge-cases.md](openapi-edge-cases.md) | OpenAPI 3.x edge cases: composition, circular refs, params, security | ✅ Ready |
| [fuzzer-implications.md](fuzzer-implications.md) | Actionable задачи для shelob-ng, Tier 0-3, связь с issues | ✅ Ready |
| [targets.md](targets.md) | Тестовые мишени: vulnerable apps, sandbox APIs, Docker setup | ✅ Ready |
| [fixtures/](fixtures/) | Локальные OpenAPI spec файлы для тестирования фаззера | ✅ 8 files |

---

## Fixtures (docs/knowledge-base/fixtures/)

| Файл | Что тестирует |
|------|--------------|
| `recursive.yaml` | Circular $ref через array items → stack overflow без depth limit |
| `anyOf_OneOf.yaml` | oneOf: Book\|Movie, anyOf, mixed-type array items |
| `composed.yaml` | allOf с $ref — ExtendedAddress наследует Address |
| `style-explode.yaml` | form/spaceDelimited + explode query + header + multipart encoding |
| `linkIssue.yaml` | links в responses: getRepositories → getRepository |
| `discriminator-mapping.yaml` | discriminator с mapping и $ref на petstore subresources |
| `oas3.1-features.yaml` | webhooks, type-array, const, mutualTLS security (OAS 3.1) |
| `petstore-v3-official.yaml` | Официальный Petstore v3 (OAuth2 + apiKey, XML+JSON+form bodies) |

---

## Быстрый старт: тестирование с fixtures

```bash
cd /home/user/claude/shelob-ng

# Тест на circular ref (должен НЕ падать после T0.1 fix):
go run . -spec docs/knowledge-base/fixtures/recursive.yaml \
         -url http://localhost:8080 -csp-disable -duration 10s

# Тест на oneOf/anyOf (проверить что генерируются валидные тела):
go run . -spec docs/knowledge-base/fixtures/anyOf_OneOf.yaml \
         -url http://localhost:8080 -csp-disable -duration 10s

# Официальный Petstore с OAuth2 (свой экземпляр):
docker run -d -p 8080:8080 swaggerapi/petstore3
go run . -spec docs/knowledge-base/fixtures/petstore-v3-official.yaml \
         -url http://localhost:8080/api/v3 -csp-disable -duration 60s
```

---

## Тестовые мишени (краткая справка до targets.md)

| Мишень | Docker | Spec URL | Auth | Уязвимости |
|--------|--------|----------|------|-----------|
| [Juice Shop](https://github.com/juice-shop/juice-shop) | `bkimminich/juice-shop` | `:3000/api-docs` | JWT Bearer | SQLi, XSS, BOLA, auth bypass, BFLA |
| [VAmPI](https://github.com/erev0s/VAmPI) | `erev0s/vampi` | `:5000/openapi3` | JWT Bearer | BOLA, SQLi, mass assign, JWT bypass |
| [crAPI](https://github.com/OWASP/crAPI) | docker-compose | `openapi-spec/` | JWT Bearer | Все OWASP API Top 10 + LLM injection |
| [DVWS-Node](https://github.com/snoopysecurity/dvws-node) | docker-compose | `swagger-output.json` | JWT+Cookie | 39 уязвимостей, XML, GraphQL, NoSQL |
| [DVRestaurant](https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game) | `./start_app.sh` | `:8091/openapi.json` | JWT | OWASP API Top 10 2023 |
| [Petstore 3](https://github.com/swagger-api/swagger-petstore) | `swaggerapi/petstore3` | `:8080/api/v3/openapi.json` | OAuth2 + apiKey | Нет (sandbox) |
| [QuickPizza](https://github.com/grafana/quickpizza) | `ghcr.io/grafana/quickpizza-local` | `:3333/` | Bearer | Нет (httpbin-style utils) |
| [httpbin](https://github.com/kennethreitz/httpbin) | `kennethreitz/httpbin` | `localhost/spec.json` | Basic/Bearer | Нет (HTTP mirror) |

---

## Приоритеты для следующей сессии

Из `fuzzer-implications.md`, Tier 0:

1. **T0.1** — `generateInput/generateInput.go`: добавить `depth int` параметр, обрезать на 5
2. **T0.2** — `generateInput/generateInput.go`: `resolveComposedSchema()` для allOf/oneOf/anyOf
3. **T1.1** — `corpus/seed.go`: пропускать `readOnly: true` properties
4. **T1.4** — `urlParams/urlParams.go`: `AddCookie()` вместо `Header.Add()` для in:cookie params
