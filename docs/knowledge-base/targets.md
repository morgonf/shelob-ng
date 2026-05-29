# Тестовые мишени для shelob-ng

Легальные REST API цели для тестирования фаззера.
Дата: 2026-05-29.

---

## Сводная таблица

| # | Мишень | Spec | Auth | Stack | Docker | Уязвимости |
|---|--------|------|------|-------|--------|-----------|
| 1 | [Juice Shop](#1-juice-shop) | OAS 3.0 (частичная) | JWT Bearer | Node.js/SQLite | `:3000` | Full OWASP Top 10 + API Top 10 |
| 2 | [VAmPI](#2-vampi) | **OAS 3.x полная** | JWT Bearer | Python/Flask | `:5000` | BOLA, SQLi, mass assign, JWT bypass |
| 3 | [crAPI](#3-crapi) | **OAS 3.0.1** | JWT Bearer | Polyglot μsvc | `:8888` | Все OWASP API Top 10 + LLM |
| 4 | [DVWS-Node](#4-dvws-node) | **OAS 3.0.0** | JWT + Cookie | Node.js | `:80` | 39 уязвимостей, XML, GraphQL, NoSQL |
| 5 | [DVRestaurant](#5-damn-vulnerable-restaurant) | OAS (FastAPI auto) | JWT? | Python/FastAPI | `:8091` | OWASP API Top 10 2023 |
| 6 | [Petstore 3](#6-swagger-petstore-3) | **OAS 3.0.4** | OAuth2 + API Key | Java | `:8080` | Нет (sandbox) |
| 7 | [QuickPizza](#7-grafana-quickpizza) | **OAS 3.0.3** | Bearer token | Go | `:3333` | Нет (httpbin-style utils) |
| 8 | [RESTler Demo](#8-restler-demo-server) | OAS 3.0.2 | None | Python/FastAPI | No | Нет (tutorial) |
| 9 | [httpbin](#9-httpbin) | Swagger 2.0 | Basic/Bearer | Python/Flask | `:80` | Нет (HTTP mirror) |
| 10 | [vAPI](#10-vapi) | Postman → OAS | Token | PHP/Laravel | `:8000` | OWASP API Top 10 упражнения |
| 11 | [RealWorld](#11-realworld-conduit) | OAS | JWT Bearer | Many | Many | Нет (reference) |

---

## Приоритизированные рекомендации

**Tier 1** — лучшее сочетание полноты spec + плотности уязвимостей:
1. **VAmPI** — начать здесь; полная spec, предсказуемый JWT, switchable mode
2. **crAPI** — самый реалистичный; producer-consumer chains, multi-service, все OWASP API Top 10
3. **DVWS-Node** — лучший для XML/NoSQL/injection coverage

**Tier 2** — полезны для специфических сценариев:
4. **DVRestaurant** — FastAPI auto-spec = нет дрейфа spec/implementation
5. **Petstore 3** — тестирование OAuth2 implicit + API key auth
6. **QuickPizza** — httpbin utilities + реалистичный CRUD в одном контейнере

**Tier 3** — вспомогательные:
7. **httpbin** — тестирование инфраструктуры фаззера (redirect, encoding, timeouts)
8. **Juice Shop** — высокий ROI для ручной верификации findings; частичная spec

---

## Детальное описание

### 1. Juice Shop

- **GitHub:** https://github.com/juice-shop/juice-shop
- **Stack:** Node.js (TypeScript), SQLite, Angular frontend
- **Docker:**
  ```bash
  docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
  ```
- **OpenAPI spec:** `/api-docs` (Swagger UI); `swagger.yml` в корне репозитория — **OpenAPI 3.0.0**
- **Предупреждение:** официальный `swagger.yml` покрывает только `/orders`. Реальная поверхность атаки (~100 endpoints) доступна через Swagger UI — она генерируется динамически из регистрации маршрутов
- **Auth:** JWT Bearer token; логин: `POST /rest/user/login` → `token` в ответе → `Authorization: Bearer <token>`
- **Уязвимости:** SQLi, XSS, IDOR/BOLA, auth bypass, JWT weak secret, mass assignment, path traversal, CSRF, BFLA, rate limit bypass, XXE, SSRF, insecure deserialization
- **shelob-ng команда:**
  ```bash
  go run . -spec http://localhost:3000/api-docs \
           -url http://localhost:3000 \
           -user fuzzer@shelob.local -password Shelob1! \
           -user2 victim@shelob.local -pass2 Victim1! \
           -csp-disable -duration 5m
  ```
- **Важно:** JWT токены истекают — фаззер должен переавторизовываться. In-memory SQLite: аккаунты сбрасываются при `docker restart`.

---

### 2. VAmPI

- **GitHub:** https://github.com/erev0s/VAmPI
- **Stack:** Python, Flask
- **Docker:**
  ```bash
  # Одиночный экземпляр (vulnerable mode):
  docker run -d -e vulnerable=1 -e tokentimetolive=3600 -p 5000:5000 erev0s/vampi:latest

  # Docker Compose — два экземпляра:
  # insecure on :5002, secure on :5001 (для differential testing)
  docker-compose up -d
  ```
- **Порты:** 5000 (standalone); 5001 (secure) / 5002 (insecure) via compose
- **OpenAPI spec:** `openapi_specs/openapi3.yml` — **OpenAPI 3.x, полная и структурированная**; Swagger UI: `http://127.0.0.1:5000/ui/`
- **Auth:** JWT Bearer token; логин: `POST /users/v1/login` → `auth_token`
- **Token TTL:** по умолчанию 60 сек! При разработке использовать `tokentimetolive=3600`
- **Подготовка:** ОБЯЗАТЕЛЬНО выполнить `GET /createdb` перед первым запуском для seed БД
- **Уязвимости:**
  - BOLA/IDOR: `/books/v1/{book}` — чужие книги доступны
  - Mass assignment: смена пароля чужого пользователя через POST body
  - Excessive data exposure: `GET /users/v1/_debug` — все пароли в открытом виде
  - User enumeration: разные error messages для user not found vs wrong password
  - JWT bypass: слабый signing key (brute-forceable)
  - RegexDoS: `/users/v1/{username}` — evil regex
  - SQLi: `/books/v1/{book}` — прямая конкатенация
- **shelob-ng команда:**
  ```bash
  # Seed DB сначала:
  curl http://localhost:5000/createdb

  go run . -spec http://localhost:5000/openapi3 \
           -url http://localhost:5000 \
           -user admin1 -password pass1 \
           -user2 user2 -pass2 pass2 \
           -csp-disable -duration 5m
  ```

---

### 3. crAPI

- **GitHub:** https://github.com/OWASP/crAPI
- **Stack:** Java (identity), Go (community), Python/Django (workshop), TypeScript frontend; PostgreSQL, MongoDB
- **Docker:**
  ```bash
  git clone https://github.com/OWASP/crAPI
  cd crAPI/deploy/docker
  # Полная версия:
  docker compose -f docker-compose.yml --compatibility up -d
  # Минимальная (меньше RAM):
  docker compose -f docker-compose.minimal.yml up -d
  ```
- **Порты:**
  - App: `8888` (HTTP), `8443` (HTTPS)
  - Mailhog UI: `8025` (для регистрации/подтверждения email)
  - Chatbot MCP: `5500`
- **Требования:** Docker Compose v1.27+, ~4 GB RAM
- **OpenAPI spec:** `openapi-spec/crapi-openapi-spec.json` — **OpenAPI 3.0.1**, ~3400 строк. Покрывает только identity service. Community (Go) и Workshop (Python) сервисы — отдельные specs по `/docs`
- **Auth:** JWT Bearer token; регистрация требует подтверждения email через Mailhog `:8025`
- **Уязвимости (все OWASP API Top 10 2023):**
  - BOLA: `GET /workshop/api/mechanic/mechanic_report?report_id=X` — чужой отчёт
  - BOLA: `GET /identity/api/v2/vehicle/{vehicleId}/location` — геолокация чужого авто
  - BFLA: DELETE чужих видео
  - Mass assignment: изменение баланса через лишние поля
  - JWT forgery: слабые JWT
  - NoSQL injection: купоны MongoDB
  - SQLi: redemption endpoint
  - SSRF: workshop service
  - Broken auth: OTP rate-limit bypass
  - LLM prompt injection: chatbot (v1.1.6+)
- **shelob-ng команда:**
  ```bash
  go run . -spec openapi-spec/crapi-openapi-spec.json \
           -url http://localhost:8888 \
           -user user1@example.com -password Crapi123! \
           -user2 user2@example.com -pass2 Crapi123! \
           -csp-disable -duration 10m
  ```
- **Важно:** Producer-consumer chains: `POST /identity/api/v2/vehicle/add_vehicle` → vehicleId → последующие vehicle endpoints. Идеальная мишень для проверки dependency graph.

---

### 4. DVWS-Node

- **GitHub:** https://github.com/snoopysecurity/dvws-node
- **Stack:** Node.js, MongoDB, MySQL
- **Docker:**
  ```bash
  git clone https://github.com/snoopysecurity/dvws-node
  cd dvws-node
  docker-compose up
  ```
- **Порт:** 80 (настраивается через `.env`)
- **Дополнительно:** добавить `dvws.local` в `/etc/hosts`
- **OpenAPI spec:** `swagger-output.json` — **OpenAPI 3.0.0**, 24 endpoint'а. Авто-генерируется через `swagger-generator.js`
- **Auth:** JWT Bearer + Cookie; заголовок `Authorization`
- **Уязвимости (39 total):**
  - IDOR, SQLi, NoSQL injection (MongoDB)
  - XXE и XML bomb DoS
  - XPATH injection, LDAP injection
  - OS command injection
  - SSRF, path traversal
  - JWT secret brute-force
  - CORS misconfiguration
  - GraphQL introspection/ACL bypass (GraphQL endpoint рядом с REST)
  - XSS, CSRF, unsafe deserialization
- **Особенность:** XML import/export endpoints — редкий case для REST фаззеров; GraphQL рядом с REST

---

### 5. Damn Vulnerable RESTaurant

- **GitHub:** https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game
- **Stack:** Python, FastAPI, PostgreSQL
- **Docker:**
  ```bash
  git clone https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game
  cd Damn-Vulnerable-RESTaurant-API-Game
  ./start_app.sh   # режим тестирования
  ./start_game.sh  # режим обучения (с подсказками)
  ```
- **Порт:** 8091
- **OpenAPI spec:** FastAPI auto-gen — **ВСЕГДА точно отражает реальные маршруты**
  - Swagger UI: `http://localhost:8091/docs`
  - Spec JSON: `http://localhost:8091/openapi.json`
  - ReDoc: `http://localhost:8091/redoc`
- **Auth:** JWT (вероятно, FastAPI типичный)
- **Уязвимости:** OWASP API Top 10 (2023); REST + GraphQL endpoints; расширяемый framework
- **Три режима:** exploit (pentest) / fix (developer learning) / pentest (mixed)
- **Особенность:** данные сохраняются между перезапусками контейнера; GitHub Codespaces интеграция

---

### 6. Swagger Petstore 3

- **GitHub:** https://github.com/swagger-api/swagger-petstore
- **Stack:** Java, swagger-inflector (design-first)
- **Docker:**
  ```bash
  docker run --name petstore3 -d -p 8080:8080 swaggerapi/petstore3:unstable
  # Swagger UI: http://localhost:8080
  # Spec: http://localhost:8080/api/v3/openapi.json
  ```
- **OpenAPI spec:** `src/main/resources/openapi.yaml` — **OpenAPI 3.0.4**
- **Endpoints:** 13 paths — `/pet`, `/pet/findByStatus`, `/pet/findByTags`, `/pet/{petId}`, `/pet/{petId}/uploadFile`, `/store/inventory`, `/store/order`, `/store/order/{orderId}`, `/user`, `/user/createWithList`, `/user/login`, `/user/logout`, `/user/{username}`
- **Auth:**
  - `petstore_auth`: OAuth2 implicit flow (scopes: `write:pets`, `read:pets`)
  - `api_key`: apiKey в header `api_key`
- **Content types:** `application/json`, `application/xml`, `application/x-www-form-urlencoded`
- **Уязвимостей нет** — эталонная реализация
- **Применение:** тестирование генерации запросов, OAuth2 + API key auth, XML/form-encoded bodies, array query params с `explode: true`
- **Публичный экземпляр:** https://petstore3.swagger.io (но фаззить только свой localhost!)

---

### 7. Grafana QuickPizza

- **GitHub:** https://github.com/grafana/quickpizza
- **Stack:** Go backend, Svelte frontend
- **Docker:**
  ```bash
  docker run --rm -it -p 3333:3333 ghcr.io/grafana/quickpizza-local:latest
  ```
- **Порт:** 3333
- **OpenAPI spec:** `quickpizza-openapi.yaml` — **OpenAPI 3.0.3**, 28+ endpoints
- **Auth:** Bearer token; `POST /api/users` (регистрация) → `POST /api/users/token/login` → token
- **Endpoint'ы:** Pizza CRUD, ingredients, ratings, users, admin + **httpbin-style utilities:**
  - `GET /api/status/{status}` — вернуть любой HTTP код
  - `GET /api/bytes/{n}` — вернуть n байт
  - `GET /api/delay/{delay}` — задержка ответа
  - `GET /api/cookies`, `GET /api/headers` — инспекция
  - `GET /api/csrf` — CSRF token endpoint
- **Уязвимостей нет** — designed for perf/observability testing
- **Применение:** тестирование обработки status codes, encoding, timeouts + реалистичный CRUD в одном контейнере

---

### 8. RESTler Demo Server

- **GitHub:** https://github.com/microsoft/restler-fuzzer/tree/main/demo_server
- **Stack:** Python, FastAPI
- **Run:**
  ```bash
  cd demo_server
  python -m venv venv && source venv/bin/activate
  pip install -r requirements.txt
  python demo_server/app.py
  ```
- **Порт:** 8888
- **OpenAPI spec:** `demo_server/swagger.json` — **OpenAPI 3.0.2**, 4 endpoint'а
  - `GET /api/blog/posts` — список постов
  - `POST /api/blog/posts` — создать пост (возвращает `postId`)
  - `GET/PUT/DELETE /api/blog/posts/{postId}` — CRUD по ID
  - `GET /api/doc` — документация
- **Auth:** нет
- **Уязвимостей нет** — tutorial baseline
- **Применение:** тест producer-consumer chain: POST создаёт `postId` → GET/PUT/DELETE потребляют. Простейший benchmark 2xx rate.

---

### 9. httpbin

- **GitHub:** https://github.com/kennethreitz/httpbin / https://github.com/postmanlabs/httpbin
- **Stack:** Python, Flask/Gunicorn
- **Docker:**
  ```bash
  docker run -p 80:80 kennethreitz/httpbin
  ```
- **Порт:** 80; Swagger UI на `/`; spec: `/spec.json` (Swagger 2.0)
- **Auth:** `/basic-auth/{user}/{passwd}` — Basic; `/bearer` — Bearer; `/digest-auth/*` — Digest
- **Endpoint'ы:** GET/POST/PUT/PATCH/DELETE зеркала, `/status/{code}`, `/delay/{n}`, `/redirect/{n}`, `/cookies`, `/headers`, `/anything`, `/stream/{n}`, `/bytes/{n}`
- **Публичный:** https://httpbin.org
- **Применение:** тестирование инфраструктуры фаззера — обработка redirect, encoding, различных status codes, timeout handling

---

### 10. vAPI

- **GitHub:** https://github.com/roottusk/vapi
- **Stack:** PHP 7.3+, Laravel 8, MySQL
- **Docker:**
  ```bash
  git clone https://github.com/roottusk/vapi
  cd vapi
  docker-compose up -d
  ```
- **Порты:** App: 8000; phpMyAdmin: 8001
- **OpenAPI spec:** **Нет OAS файла** — только Postman collection (`vAPI.postman_collection.json`)
  - Конвертация: `postman-to-openapi vAPI.postman_collection.json -f openapi.yaml`
  - Postman workspace: https://www.postman.com/roottusk/workspace/vapi/
- **Auth:** token-based (auto-генерируется через Postman tests)
- **Уязвимости:** OWASP API Top 10 (2019) — все 10 категорий через упражнения
- **Ограничение:** Нет нативного OAS файла — требует конвертации или ручного написания spec

---

### 11. RealWorld (Conduit)

- **GitHub:** https://github.com/gothinkster/realworld
- **Spec:** `apps/api-design/` — стандартизованная OpenAPI spec
- **Публичный backend:** `https://api.realworld.show` (без API key, регистрация через `/users`)
- **Auth:** JWT Bearer token; `POST /users` → регистрация → токен в ответе
- **Endpoint'ы:** Users, profiles, articles, comments, tags — типичный социальный CRUD
- **Реализации:** 100+ backends (Node, Go, Rust, Django, Spring, ...) — выбрать любой для self-hosted
- **Уязвимостей нет** — reference implementation
- **Применение:** тест auth flow coverage и stateful CRUD chains без Docker

---

## Коллекции OpenAPI спецификаций

### APIs.guru OpenAPI Directory
- **GitHub:** https://github.com/APIs-guru/openapi-directory
- **API каталога:** `curl https://api.apis.guru/v2/list.json` — полный список без auth
- **Содержимое:** тысячи реальных OAS 2.0/3.x спецификаций, обновляются еженедельно
- **Провайдеры:** AWS, Azure, Google, Twilio, Stripe, GitHub, Slack
- **Внимание:** это спеки РЕАЛЬНЫХ production API — **фаззить только свои localhost экземпляры**
- **Применение:** стресс-тест парсера spec, edge cases allOf/oneOf/$ref chains; Stripe и Kubernetes спеки — самые сложные для генерации

---

## Практические заметки для shelob-ng

### 1. VAmPI token TTL
По умолчанию 60 сек → фаззер будет работать с истёкшими токенами.
При разработке использовать `tokentimetolive=3600`:
```bash
docker run -e tokentimetolive=3600 -e vulnerable=1 -p 5000:5000 erev0s/vampi:latest
```

### 2. VAmPI database seed
Всегда `GET http://localhost:5000/createdb` перед фаззингом.
Можно добавить как pre-run hook в scenario скрипт.

### 3. crAPI email flow
Регистрация требует email-подтверждения через Mailhog `:8025`.
Для автоматизации: pre-seed аккаунты через API или использовать существующие тестовые.

### 4. Juice Shop spec gap
`swagger.yml` покрывает только `/orders`. Реальная поверхность атаки:
```bash
# Получить полную spec из запущенного сервиса:
curl http://localhost:3000/api-docs -o juice-shop-full.json
```

### 5. FastAPI — нулевой дрейф spec/implementation
DVRestaurant и RESTler Demo сервер — FastAPI auto-gen:
`http://localhost:{port}/openapi.json` ВСЕГДА отражает реальные маршруты.
Идеально для sanity-check тестов фаззера.

### 6. Differential testing с VAmPI Docker Compose
Запустить обе версии и сравнить findings:
```bash
docker-compose up -d
# Фаззить secure version :5001 — baseline (мало findings)
# Фаззить insecure version :5002 — максимум findings
# Diff = реальные уязвимости, не false positives
```

### 7. Producer-consumer test с RESTler Demo
Минимальный тест dependency graph:
```bash
go run . -spec http://localhost:8888/openapi.json \
         -url http://localhost:8888 \
         -csp-disable -duration 60s -debug
# Ожидаем: POST /api/blog/posts → получить postId → GET/PUT/DELETE с этим ID
# Без dependency graph: GET/DELETE вернут 404 (нет postId в path params)
# С dependency graph: ~50% 2xx на consumer operations
```
