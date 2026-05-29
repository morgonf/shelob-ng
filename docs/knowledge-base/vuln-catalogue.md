# Vulnerability Catalogue — Ground Truth for Fuzzer Metrics

Каталог намеренно встроенных уязвимостей в тестовых мишенях.
Используется как эталон для измерения глубины проникновения фаззера.

Дата: 2026-05-29. Источник: официальные репозитории и документация.

---

## Методология измерения

### Метрика: Detection Rate

```
Detection Rate = found_vulns / total_detectable_vulns × 100%
```

Где `total_detectable_vulns` — только уязвимости с `detectable: yes|partial`.

### Уровни detectable

| Уровень | Значение |
|---------|----------|
| `yes` | Фаззер должен находить автоматически при правильной конфигурации |
| `partial` | Находит симптом, но не полную цепочку (например, 500 есть, но не BOLA) |
| `no` | Требует ручного тестирования / UI взаимодействия / клиентского кода |

### Checkers shelob-ng

| Checker | Что детектирует |
|---------|----------------|
| `BehavioralPatterns` | SQL ошибки, stack traces, error strings в теле ответа |
| `NameSpaceRule` | BOLA/IDOR — user2 получает 2xx на ресурс user1 |
| `BFLA` | user2 (low privilege) получает 2xx на admin endpoint |
| `LeakageRule` | POST 4xx + GET 2xx — состояние утекает |
| `UseAfterFree` | DELETE 2xx + повторный GET 2xx |
| `InvalidDynamicObject` | 500 на boundary values (-1, 0, null, "") |
| `SchemaViolation` | Response body не соответствует declared schema |
| `AuthBypassRule` | 401-required endpoint отвечает 2xx без auth |

---

## VAmPI

**GitHub:** https://github.com/erev0s/VAmPI
**Stack:** Python/Flask
**Spec:** `openapi_specs/openapi3.yml` (полная, точная)
**Vuln count:** ~10 намеренных уязвимостей

### Уязвимости

| ID | Название | OWASP API 2019 | Endpoint | Method | Trigger | Detectable |
|----|---------|----------------|----------|--------|---------|-----------|
| V1 | SQL Injection | API8 Injection | `/users/v1/{username}` | GET | `' OR '1'='1` в path param | **yes** |
| V2 | Unauthorized Password Change (BOLA write) | API1 BOLA | `/users/v1/{username}/password` | PUT | Token user A → изменить пароль user B | **yes** |
| V3 | BOLA — Book Secret Leakage | API1 BOLA | `/books/v1/{book_title}` | GET | Token user A → читать книгу user B | **yes** |
| V4 | Mass Assignment — Privilege Escalation | API6 Mass Assignment | `/users/v1/register` | POST | `{"admin":true}` в теле регистрации | **partial** |
| V5 | Excessive Data Exposure — Debug Endpoint | API3 Excessive Data Exposure | `/users/v1/_debug` | GET | GET без auth → все пароли в открытом виде | **yes** |
| V6 | User & Password Enumeration | API2 Broken Auth | `/users/v1/login` | POST | Разные error messages для несущ. user vs. wrong pass | **yes** |
| V7 | RegexDoS | API4 Rate Limiting | `/users/v1/{username}/email` | PUT | Длинная строка вида `aaaa...@` → catastrophic backtracking | **partial** |
| V8 | No Rate Limiting | API4 Rate Limiting | Все endpoint'ы | Any | Rapid requests → никогда нет 429 | **yes** |
| V9 | JWT Weak Signing Key (`"random"`) | API2 Broken Auth | Все authenticated endpoints | Any | Offline crack → forge admin token | **partial** |

### Детали по каждой уязвимости

#### V1 — SQL Injection (`GET /users/v1/{username}`)
- **Код:** `f"SELECT * FROM users WHERE username = '{username}'"` — нет параметризации
- **Trigger:** `GET /users/v1/name1' OR '1'='1`
- **Эффект:** возврат всех строк users; UNION-injection даёт dump всей таблицы включая пароли
- **Checker:** `BehavioralPatterns` (SQL error string) + `SchemaViolation` (лишние rows)

#### V2 — Unauthorized Password Change
- **Код:** handler берёт `username` из URL path вместо JWT `sub` claim
- **Trigger:** token user A + `PUT /users/v1/userB/password {"password":"hacked"}`
- **Эффект:** HTTP 204 + пароль изменён
- **Checker:** `NameSpaceRule` / `BFLA` (cross-user write → 2xx)

#### V3 — BOLA Book Secret
- **Код:** `Book.query.filter_by(book_title=...)` без фильтра по owner
- **Trigger:** token user A + `GET /books/v1/<title_owned_by_userB>`
- **Эффект:** HTTP 200 + `{"secret": "...", "owner": "userB"}`
- **Checker:** `NameSpaceRule` (user2 probe → 2xx с чужим ресурсом)

#### V4 — Mass Assignment
- **Код:** `if vuln and 'admin' in request_data: user.admin = True`
- **Trigger:** `POST /users/v1/register {"username":"x","password":"x","email":"x@x.com","admin":true}`
- **Эффект:** аккаунт создаётся с `admin=True`; `DELETE /users/v1/...` доступен
- **Checker:** требует multi-step correlation (POST → GET → сравнить поля)

#### V5 — Debug Endpoint (ПОСТОЯННО открыт, даже при `vulnerable=0`)
- **Код:** `GET /users/v1/_debug` → `json_debug()` на всех users → plaintext passwords
- **Trigger:** GET без auth
- **Эффект:** JSON массив всех пользователей с паролями
- **Checker:** `AuthBypassRule` + `BehavioralPatterns` (поле `"password"` в открытом ответе)

#### V6 — User Enumeration
- **Код:** два разных error message: `"Username does not exist"` vs `"Password is not correct for the given username."`
- **Trigger:** login с несуществующим user vs. существующим user + wrong pass
- **Эффект:** дифференциальный response body → enum valid usernames
- **Checker:** `BehavioralPatterns` (различные error strings при одинаковом status code)

#### V7 — RegexDoS
- **Regex:** `^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$`
- **Trigger:** `PUT /users/v1/{username}/email {"email":"aaaaaaaaaaaaaaaaaaaa@"}`
- **Эффект:** exponential backtracking → timeout / server hang
- **Checker:** нужен timing-based checker (не реализован в shelob-ng)

#### V8 — No Rate Limiting
- **Trigger:** N rapid requests к любому endpoint → ни одного 429
- **Checker:** `BehavioralPatterns` (отсутствие 429 после burst) — **не реализован**; нужен новый checker

#### V9 — JWT Weak Key
- **Код:** `SECRET_KEY = "random"` в `config.py`; `jwt.decode(..., 'random', algorithms=["HS256"])`
- **Trigger:** offline crack → forge token с `sub: admin`
- **Эффект:** полный admin access
- **Checker:** offline attack — не применимо для black-box fuzzer в реальном времени

### Статистика

| Категория | Кол-во |
|-----------|--------|
| Всего уязвимостей | 9 |
| `detectable: yes` | 5 (V1, V2, V3, V5, V6) |
| `detectable: partial` | 3 (V4, V7, V9) |
| `detectable: no` | 1 (V8 — нет checker'а в shelob-ng) |
| **Теоретический Detection Rate** | **5/9 = 56%** (только yes) |
| С partial | **8/9 = 89%** |

### Конфигурация shelob-ng для максимального покрытия

```bash
./shelob-ng \
  -spec     openapi3.yaml \
  -url      http://localhost:5000 \
  -user     admin1 -password pass1 \
  -user2    user2  -pass2    pass2 \
  -payloads sqli=payloads/sqli.txt,nosql=payloads/nosql.txt \
  -duration 15m
# Ожидаем: V1(BehavioralPatterns), V2+V3(NameSpaceRule), V5(AuthBypassRule+Behavioral), V6(Behavioral)
```

---

## crAPI

**GitHub:** https://github.com/OWASP/crAPI
**Stack:** Java + Go + Python/Django (microservices)
**Spec:** `openapi-spec/crapi-openapi-spec.json` (identity service only)
**Vuln count:** 10 OWASP API Top 10 (2023) + LLM

**Архитектура**: 3 сервиса + chatbot. Spec (`crapi-openapi-spec.json`) покрывает только identity.
**Всего challenges: 18 + 3 secret = 21.** Детектируемых фаззером: 10/21.

### Уязвимости

| ID | Название | OWASP API 2023 | Method | Endpoint | Сервис | Detectable |
|----|---------|---------------|--------|----------|--------|-----------|
| C01 | BOLA: чужой автомобиль | API1 BOLA | GET | `/identity/api/v2/vehicle/{carId}/location` | identity | **partial** |
| C02 | BOLA: чужой отчёт механика | API1 BOLA | GET | `/workshop/api/mechanic/mechanic_report?report_id={id}` | workshop | **yes** |
| C03 | Брутфорс OTP сброса пароля | API2 Auth | POST | `/identity/api/auth/v2/check-otp` | identity | **yes** |
| C04 | Утечка данных в постах | API3 Exposure | GET | `/community/api/v2/community/posts/recent` | community | **yes** |
| C05 | Внутреннее поле видео в ответе | API3 Exposure | GET | `/identity/api/v2/user/videos/{video_id}` | identity | **partial** |
| C06 | Layer-7 DoS через repeat_request | API4 Resource | POST | `/workshop/api/merchant/contact_mechanic` | workshop | **yes** |
| C07 | BFLA: удалить видео другого юзера | API5 BFLA | DELETE | `/identity/api/v2/admin/videos/{video_id}` | identity | **yes** |
| C08 | Mass Assignment: бесплатный товар | API6 Mass Assign | PUT | `/workshop/api/shop/orders/{order_id}` | workshop | **partial** |
| C09 | Mass Assignment: накрутка баланса | API6 Mass Assign | PUT | `/workshop/api/shop/orders/{order_id}` | workshop | **partial** |
| C10 | Mass Assignment: запись internal поля | API6 Mass Assign | PUT | `/identity/api/v2/user/videos/{video_id}` | identity | **partial** |
| C11 | SSRF через mechanic_api | API7 SSRF | POST | `/workshop/api/merchant/contact_mechanic` | workshop | **yes** |
| C12 | NoSQL injection: купоны | API8 Injection | POST | `/community/api/v2/coupon/validate-coupon` | community | **yes** |
| C13 | SQLi: двойное применение купона | API8 Injection | POST | `/workshop/api/shop/apply_coupon` | workshop | **yes** |
| C14 | Unauthenticated endpoints | API2 Auth | GET | `/identity/api/v2/user/dashboard`, `/workshop/api/shop/orders/{id}` | identity/workshop | **yes** |
| C15 | JWT forgery (RS256→HS256, KID, JKU) | API2 Auth | ANY | `/identity/api/auth/jwks.json` + auth endpoints | identity | **yes** |
| C16 | Prompt injection (LLM rendering) | LLM01 | POST | `/genai/ask` | chatbot | **no** |
| C17 | Утечка credentials через LLM | LLM02 | POST | `/genai/ask` | chatbot | **no** |
| C18 | LLM Excessive Agency | LLM08 | POST | `/genai/ask` | chatbot | **no** |
| CS1 | Command injection via convert_video | API8 | GET | `/identity/api/v2/user/videos/convert_video` | identity | **no** |
| CS2 | Path traversal: download_report | API8 | GET | `/workshop/api/mechanic/download_report?filename=` | workshop | **partial** |
| CS3 | BOLA service requests by VIN (no auth) | API1 BOLA | GET | `/workshop/api/merchant/service_requests/{vin}` | workshop | **yes** |

### Детали по ключевым уязвимостям

#### C02 — BOLA: Mechanic Report (report_id — sequential integer)
- **Код:** `GET ?report_id={id}` — нет проверки ownership, ID — целое число (не GUID)
- **Trigger:** инкремент/декремент `report_id`
- **Checker:** `NameSpaceRule` (user2 probe с чужим report_id → 2xx)

#### C03 — OTP Brute Force (v2 vs v3)
- **Код:** `/v2/check-otp` нет rate limiting; 4-значный OTP = 10 000 комбинаций
- **Trigger:** POST с разными OTP без блокировки
- **Checker:** нужен RateLimitChecker (нет в shelob-ng) — 100+ запросов, нет 429

#### C04 — Excessive Data Exposure в постах
- **Код:** `Author` model возвращает `email`, `vehicleid` в каждом посте
- **Trigger:** GET `/community/api/v2/community/posts/recent` — в ответе email+UUID чужих юзеров
- **Checker:** `BehavioralPatterns` (паттерн email regex в ответе на public endpoint)

#### C06 — Layer-7 DoS
- **Код:** `number_of_repeats: 100` → сервер делает 100 outbound HTTP запросов
- **Trigger:** `{"mechanic_api":"http://x.x.x.x","repeat_request_if_failed":true,"number_of_repeats":100}`
- **Checker:** `SchemaViolation` + ручной timing test

#### C07 — BFLA: Delete Video via /admin/ path
- **Код:** `/user/videos/{id}` → 403 (intentional hint); `/admin/videos/{id}` → 200 (no role check)
- **Trigger:** любой auth token + DELETE `/identity/api/v2/admin/videos/{video_id}` чужого юзера
- **Checker:** `BFLA` checker (уже реализован в shelob-ng)

#### C11 — SSRF
- **Код:** `contact_mechanic` делает HTTP GET на `mechanic_api` URL из тела запроса
- **Trigger:** `{"mechanic_api":"http://169.254.169.254/latest/meta-data/",...}`
- **Checker:** нужен SSRFChecker (нет в shelob-ng); `BehavioralPatterns` может детектировать leaked URL content

#### C12 — NoSQL Injection
- **Код:** `bson.M{"coupon_code": coupon_code}` — MongoDB operators не экранируются
- **Trigger:** `{"coupon_code": {"$ne": ""}}`
- **Checker:** `BehavioralPatterns` (изменённый ответ на `$ne` payload)

#### C15 — JWT Attack (3 вектора)
1. **RS256→HS256:** JWKS доступен по `/identity/api/auth/jwks.json` → forge HS256 token с RSA public key
2. **KID injection:** `kid: "/dev/null"` → secret = base64("") → любой token с пустым ключом
3. **JKU injection:** `jku` header → attacker-controlled JWKS
- **Checker:** `AuthBypassRule` + JWT manipulation

### Статистика

| Категория | Yes | Partial | No | Total |
|-----------|-----|---------|-----|-------|
| API1 BOLA | 2 | 1 | 0 | 3 |
| API2 Auth | 3 | 0 | 0 | 3 |
| API3 Exposure | 1 | 1 | 0 | 2 |
| API4 Resource | 1 | 0 | 0 | 1 |
| API5 BFLA | 1 | 0 | 0 | 1 |
| API6 Mass Assign | 0 | 3 | 0 | 3 |
| API7 SSRF | 1 | 0 | 0 | 1 |
| API8 Injection | 2 | 1 | 1 | 4 |
| LLM | 0 | 0 | 3 | 3 |
| **ИТОГО** | **11** | **6** | **4** | **21** |

**Detection Rate:** `11/21 = 52%` (только yes), `17/21 = 81%` (yes+partial)

> ⚠️ Spec `crapi-openapi-spec.json` покрывает только identity service.
> Workshop и community endpoints требуют отдельных spec файлов или ручного discovery.

### Конфигурация shelob-ng для максимального покрытия

```bash
./shelob-ng \
  -spec     /opt/crapi/openapi-spec/crapi-openapi-spec.json \
  -url      http://localhost:8888 \
  -user     fuzzer@shelob.local -password Shelob1! \
  -user2    victim@shelob.local -pass2   Victim1! \
  -payloads sqli=payloads/sqli.txt,nosql=payloads/nosql.txt \
  -duration 15m
# Ожидаем: C02(NameSpaceRule), C04(Behavioral), C07(BFLA),
#          C12+C13(Behavioral), C14(AuthBypass), C15(AuthBypass)
```

---

## OWASP Juice Shop

**GitHub:** https://github.com/juice-shop/juice-shop
**Stack:** Node.js/TypeScript, SQLite
**Spec:** частичная (`swagger.yml` только `/orders`; полная через `/api-docs`)
**Challenge count:** 100+ total; ~30-40 REST-accessible

**Всего challenges: 106.** Только REST-доступные — 60/106 (57%). Ниже — только те, что detectable фаззером.

### Ключевые endpoint'ы (YES — прямая детекция)

| ID | Название | Категория | Endpoint | Method | Checker | Примечание |
|----|---------|-----------|----------|--------|---------|-----------|
| J01 | Login Admin / Bender / Jim | Injection/SQLi | `/rest/user/login` | POST | `BehavioralPatterns` | `' OR 1=1--` в поле email |
| J02 | Database Schema | Injection/SQLi | `/rest/products/search` | GET | `BehavioralPatterns` | UNION SELECT через param `?q=` |
| J03 | Christmas Special | Injection/SQLi | `/rest/products/search` + basket | GET+POST | `BehavioralPatterns` | half-blind SQLi |
| J04 | User Credentials | Injection/SQLi | `/rest/products/search` | GET | `BehavioralPatterns` | UNION SELECT → dump Users |
| J05 | NoSQL Manipulation | Injection/NoSQL | `/rest/products/reviews` | PATCH | `BehavioralPatterns` | MongoDB `$where` operator injection |
| J06 | View Basket (BOLA) | Broken Access | `/rest/basket/{id}` | GET | `NameSpaceRule` | integer ID increment → чужая корзина |
| J07 | Forged Feedback | Broken Access | `/api/Feedbacks` | POST | `NameSpaceRule` | inject `UserId` в тело |
| J08 | Forged Review | Broken Access | `/rest/products/{id}/reviews` | PUT | `NameSpaceRule` | forge author field |
| J09 | Manipulate Basket | Broken Access | `/api/BasketItems` | POST | `NameSpaceRule` | `BasketId` другого юзера |
| J10 | Product Tampering | Broken Access | `/api/Products/{id}` | PUT | `BFLA` | unauthorized PUT resource |
| J11 | Five-Star Feedback | Broken Access | `/api/Feedbacks/{id}` | DELETE | `BFLA` | admin-only DELETE без auth |
| J12 | Change Bender's Password | Broken Auth | `/rest/user/change-password` | GET | `AuthBypassRule` | missing `current` param validation |
| J13 | Admin Registration | Input Validation | `/api/Users` | POST | `SchemaViolation` | `{"role":"admin"}` mass assignment |
| J14 | Zero Stars | Input Validation | `/api/Feedbacks` | POST | `SchemaViolation` | `rating: 0` обходит UI min=1 |
| J15 | Payback Time | Input Validation | `/api/BasketItems` | POST/PUT | `SchemaViolation` | отрицательное количество |
| J16 | Upload Size / Type | Input Validation | `/file-upload` | POST | `SchemaViolation` | файл >100KB или не-pdf/zip MIME |
| J17 | Confidential Document | Sensitive Data | `/ftp/acquisitions.md` | GET | `AuthBypassRule` | прямой доступ к /ftp/ |
| J18 | Forgotten Backups | Sensitive Data | `/ftp/*.bak%2500.md` | GET | `BehavioralPatterns` | null-byte bypass на file server |
| J19 | Password Hash Leak | Sensitive Data | `/rest/user/whoami` | GET | `BehavioralPatterns` | hash в ответе (excessive data) |
| J20 | Exposed Metrics | Observability | `/metrics` | GET | `AuthBypassRule` | Prometheus без auth |
| J21 | Error Handling | Misc | Любой malformed request | ANY | `BehavioralPatterns` | verbose 500 с stack trace |
| J22 | Deprecated Interface | Security Misconfig | `/b2b/v2/orders` | POST | `BehavioralPatterns` | старый XML endpoint |
| J23 | XXE Data Access | XXE | `/b2b/v2/orders` | POST | `BehavioralPatterns` | classic XXE (disabled Docker) |
| J24 | XXE DoS | XXE | `/b2b/v2/orders` | POST | `BehavioralPatterns` | billion laughs (disabled Docker) |
| J25 | Unsigned JWT | Vuln Components | Любой auth endpoint | ANY | `AuthBypassRule` | `alg: none` JWT |
| J26 | Forged Signed JWT | Vuln Components | Любой auth endpoint | ANY | `AuthBypassRule` | RS256→HS256 confusion |
| J27 | CAPTCHA Bypass | Anti-Automation | `/api/Feedbacks` | POST | `SchemaViolation` | reuse CAPTCHA token |
| J28 | Open Redirect | Unvalidated Redirect | `/redirect` | GET | `BehavioralPatterns` | `?to=` allowlist bypass |

### Partial-detectable (нужна дополнительная логика)

| ID | Название | Endpoint | Что мешает автоматизации |
|----|---------|----------|--------------------------|
| J29 | Forged Coupon | `/rest/basket/{id}/coupon/{code}` | надо reverse-engineer coupon algo |
| J30 | GDPR Data Theft | `/rest/user/data-export` | multi-step: знать ID другого user |
| J31 | CAPTCHA Bypass | `/api/Feedbacks` | надо сначала получить валидный CAPTCHA |
| J32 | Multiple Likes (race) | `/rest/products/{id}/reviews/{id}/like` | concurrent requests — race condition |
| J33 | Rate Limit Bypass | `/rest/user/reset-password` | нужен брутфорс OTP |

### Статистика

| Категория | Yes | Partial | No | Total |
|-----------|-----|---------|-----|-------|
| Injection | 9 | 3 | 1 | 13 |
| Broken Access | 7 | 3 | 3 | 13 |
| Broken Auth | 4 | 2 | 4 | 10 |
| XSS | 3 | 3 | 4 | 10 |
| Sensitive Data | 6 | 3 | 8 | 17 |
| Input Validation | 7 | 2 | 3 | 12 |
| Security Misconfig | 3 | 0 | 2 | 5 |
| Vuln Components | 3 | 0 | 5 | 8 |
| Anti-Automation | 2 | 2 | 0 | 4 |
| **ИТОГО** | **38** | **22** | **46** | **106** |

**Detection Rate:** `38/106 = 36%` (только yes), `60/106 = 57%` (yes+partial)

> ⚠️ **14 challenges отключены в Docker-деплое** (NoSQL DoS/Exfil, RCE, XXE, ReflectedXSS,
> Server-side XSS, HTTP-Header XSS, Arbitrary File Write, Local File Read, SSTi, Memory Bomb).
> В стандартном `docker run bkimminich/juice-shop` они не триггерятся.

### Конфигурация shelob-ng для максимального покрытия

```bash
./shelob-ng \
  -spec     juice-shop.openapi.json \
  -url      http://localhost:3000 \
  -user     fuzzer@shelob.local -password Shelob1! \
  -user2    victim@shelob.local -pass2   Victim1! \
  -payloads sqli=payloads/sqli.txt,xss=payloads/xss.txt,nosql=payloads/nosql.txt \
  -duration 1h
# Ожидаем: J01-J05(BehavioralPatterns), J06-J11(NameSpaceRule),
#          J13-J16(SchemaViolation), J17-J20(AuthBypassRule)
```

---

## DVWS-Node

**GitHub:** https://github.com/snoopysecurity/dvws-node
**Stack:** Node.js, MongoDB, MySQL
**Spec:** `swagger-output.json` (auto-generated, 24 endpoints)
**Vuln count:** 39 классов уязвимостей

**Stack:** Node.js/Express, MongoDB, MySQL. Spec: авто-генерированная, 24 endpoints.

### Уязвимости

| ID | Название | Категория | Endpoint | Method | Trigger | Detectable |
|----|---------|-----------|----------|--------|---------|-----------|
| D01 | CORS wildcard reflection | Misconfig | Все | ANY | `Origin: evil.com` → `ACAO: evil.com` + `ACAC: true` | **yes** |
| D02 | Mass Assignment — admin flag | Broken Auth | `/v2/users` | POST | `{"admin":true}` в теле регистрации | **yes** |
| D03 | JWT `alg:none` accepted | Broken Auth | `/v2/users/checkadmin` | GET | `algorithms: ["HS256","none"]` → беззнаковый token | **partial** |
| D04 | Open Redirect | Redirect | `/v2/users/logout/{redirect}` | GET | path param → `res.redirect("http://"+param)` | **yes** |
| D05 | CRLF Injection / Log Pollution | Injection | `/v2/login` | POST | `username: "x\nFAKE_ENTRY"` → `/v2/admin/logs` | **partial** |
| D06 | XML Injection (profile export) | Injection | `/v2/users/profile/export/xml` | POST | XML-метасимволы в полях → reflection в ответе | **yes** |
| D07 | XML Mass Assignment (profile import) | Mass Assign | `/v2/users/profile/import/xml` | POST | `<admin>true</admin>` в XML body | **partial** |
| D08 | LDAP Injection | Injection | `/v2/users/ldap-search` | GET/POST | `user=*` → wildcard return; `)(objectClass=*)` → passwords | **yes** |
| D09 | BOLA/IDOR — Notes | API1 BOLA | `/v2/notes/{noteId}` | GET | sequential ID без ownership check | **yes** |
| D10 | NoSQL Injection `$where` | Injection | `/v2/notesearch` | POST | `{"search":"x' \|\| '1'=='1"}` → все notes | **yes** |
| D11 | XXE / XML Bomb | Injection/DoS | `/v2/notes/import/xml` | POST | `noent:true, dtdload:true, huge:true` | **yes** |
| D12 | XPATH Injection | Injection | `/v2/release/{release}` | GET | `'` → 500; `' or '1'='1` → all releases | **yes** |
| D13 | BOLA — Notes Update/Delete | API1 BOLA | `/v2/notes/{noteId}` | PUT/DELETE | без ownership check → чужая заметка | **yes** |
| D14 | OS Command Injection | Injection | `/v2/sysinfo/{command}` | GET | path param → `exec(param + " -a")` | **yes** |
| D15 | Info Disclosure — env dump | Info Exposure | `/v1/info` | GET | GET без auth → `process.env` + `JWT_SECRET` + DB creds | **yes** |
| D16 | SQL Injection (passphrase) | Injection | `/v2/passphrase/{username}` | GET/POST | прямая строковая интерполяция в SQL | **yes** |
| D17 | Unsafe Deserialization (RCE) | RCE | `/v2/export` | POST | `node-serialize` IIFE gadget в base64 data | **partial** |
| D18 | Prototype Pollution | Injection | `/upload` | POST | `{"__proto__":{"test":true}}` в metadata | **partial** |
| D19 | Path Traversal | Path Traversal | `/download` | POST | `{"filename":"../../../../etc/passwd"}` | **yes** |
| D20 | SSRF (storage fetch) | SSRF | `/download` | POST | URL в filename param | **partial** |
| D21 | Plaintext Password Storage | Data Exposure | `/v2/users` + `/v2/users` admin | GET | GET /v2/users (admin) → plaintext passwords | **yes** |
| D22 | Rate Limit Bypass | Rate Limiting | `/v2/login` | POST | 100 попыток/30 сек — легко обойти | **yes** |
| D23 | Hidden v1 endpoint | Inventory | `/v1/info` vs `/v2/info` | GET | v2 → 403; v1 → full env dump | **yes** |
| D24 | CSRF (cookie auth) | CSRF | `/v2/admin/create-user` | POST | `text/plain` принимается без CSRF token | **partial** |
| D25 | GraphQL Introspection open | Misconfig | `/graphql` | POST | schema полностью доступна | **yes** |
| D26 | GraphQL ACL Bypass | BFLA | `/graphql` mutations | POST | mutations без auth | **yes** |

### Детали по ключевым уязвимостям

#### D08 — LDAP Injection
- `user=*` → возвращает всех юзеров
- `user=admin)(objectClass=*)` → возвращает поле `password` admin'а
- filter: `"(uid=" + user + ")"` — без экранирования

#### D14 — OS Command Injection (прямой путь к RCE)
- `GET /v2/sysinfo/id` → выполняет `id -a` на сервере
- `GET /v2/sysinfo/cat%20/etc/passwd` → читает файл
- Требует auth token

#### D15 — Info Disclosure `/v1/info` (нет auth, не требует ничего)
- Возвращает: `process.env`, включая `JWT_SECRET`, DB credentials, все переменные окружения
- `/v2/info` возвращает 403 — versioning trap

#### D19 — Path Traversal
- `{"filename":"../../../../etc/passwd"}` → читает `/etc/passwd`
- `path.resolve(cwd + '/public/uploads/' + user + "/" + filename)` — без проверки

### Статистика

| Категория | Yes | Partial | No | Total |
|-----------|-----|---------|-----|-------|
| Injection (SQL/NoSQL/LDAP/XPATH/Cmd/XML) | 8 | 2 | 0 | 10 |
| BOLA/IDOR | 2 | 0 | 0 | 2 |
| Broken Auth / JWT | 1 | 1 | 0 | 2 |
| Mass Assignment | 1 | 2 | 0 | 3 |
| Info Disclosure | 2 | 0 | 0 | 2 |
| Path Traversal / SSRF | 1 | 1 | 0 | 2 |
| CORS / Redirect / CSRF | 2 | 1 | 0 | 3 |
| RCE / Deserialization | 0 | 1 | 0 | 1 |
| Rate Limiting | 1 | 0 | 0 | 1 |
| GraphQL | 2 | 0 | 0 | 2 |
| **ИТОГО** | **20** | **8** | **0** | **28** |

**Detection Rate:** `20/28 = 71%` (только yes), `28/28 = 100%` (yes+partial)

### Конфигурация shelob-ng для максимального покрытия

```bash
./shelob-ng \
  -spec     swagger-output.json \
  -url      http://localhost:80 \
  -payloads sqli=payloads/sqli.txt,nosql=payloads/nosql.txt,cmdi=payloads/cmdi.txt \
  -duration 15m
# Ожидаем: D08+D10+D12+D16(Behavioral), D09+D13(NameSpaceRule),
#          D14(Behavioral/cmdi), D15+D21(AuthBypass), D19(Behavioral/lfi)
```

---

## Damn Vulnerable RESTaurant

**GitHub:** https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game
**Stack:** Python/FastAPI, PostgreSQL
**Spec:** FastAPI auto-gen (всегда актуальна)
**Vuln count:** OWASP API Top 10 (2023)

**Stack:** Python/FastAPI, PostgreSQL. Spec: FastAPI auto-gen (всегда точная).
**Роли:** Customer → Employee → Chef. Прогрессивная цепочка эскалации.

### Уязвимости

| ID | Название | OWASP API 2023 | Method | Endpoint | Trigger | Detectable |
|----|---------|---------------|--------|----------|---------|-----------|
| R01 | BOLA — чужой заказ | API1 BOLA | GET | `/orders/{order_id}` | sequential ID, нет user_id фильтра | **yes** |
| R02 | Weak PIN brute-force (password reset) | API2 Auth | POST | `/reset-password/new-password` | 4-digit PIN, нет rate limit, 15 мин окно | **yes** |
| R03 | Mass Assignment — PATCH /profile → role=Chef | API3 Mass Assign | PATCH | `/profile` | `{"role":"Chef"}` — `Extra.allow` в Pydantic | **yes** |
| R04 | No Rate Limit на PIN | API4 Rate Limit | POST | `/reset-password/new-password` | 10000 запросов — нет 429 | **yes** |
| R05 | BFLA — update_role (Customer → Employee) | API5 BFLA | PUT | `/users/update_role` | Customer token → успешная смена роли | **yes** |
| R06 | BFLA — DELETE /menu без auth check | API5 BFLA | DELETE | `/menu/{item_id}` | `auth=Depends(...)` закомментирован | **yes** |
| R07 | Self-referral coupon abuse | API6 Business Flow | POST | `/apply-referral` + `/orders` | self-referral + race condition на `coupon.used` | **partial** |
| R08 | SQLi через external service response | API10 Unsafe APIs | GET | `/orders/status/{order_id}` | status от delivery service → raw SQL concat | **no** |
| R09 | Debug endpoint — env dump | API8 Misconfig | GET | `/debug` (hidden, not in schema) | GET без auth → `os.environ`, `SECRET_KEY`, DB creds | **yes** |
| R10 | Hidden unauthenticated endpoints | API9 Inventory | GET | `/delivery/orders`, `/debug`, `/admin/reset-chef-password` | path wordlist → PII всех заказов | **yes** |
| R11 | Command injection — disk stats | API3 Injection | GET | `/admin/stats/disk?parameters=` | Chef role + `parameters=/ ; id` | **yes** |
| R12 | SSRF — Chef password reset от localhost | API8 SSRF chain | GET | `/admin/reset-chef-password` | IP check `127.0.0.1` only → SSRF chain | **no** |

### Цепочка эскалации привилегий

```
1. POST /register (Customer)
2. PATCH /profile {"role":"Chef"}   ← R03: mass assignment → Chef
3. GET /admin/stats/disk?parameters=/ ; id  ← R11: RCE
```

Это пример как частичные findings складываются в полноценную атаку.

### Детали по ключевым уязвимостям

#### R03 — Mass Assignment (PATCH /profile)
- Pydantic model: `class UserUpdate(BaseModel): class Config: extra = Extra.allow`
- `{"role":"Chef"}` → `db.merge(current_user.update(data))` → роль меняется
- Checker: `SchemaViolation` (поле role в PATCH response) + ручная верификация GET /profile

#### R06 — BFLA: DELETE /menu без auth
- В коде: `# auth=Depends(RolesBasedAuthChecker([UserRole.employee, UserRole.chef]))` — закомментировано
- Customer token + `DELETE /menu/1` → `204 No Content`
- Checker: `BFLA` checker (уже реализован в shelob-ng)

#### R09 — Debug endpoint (не в OpenAPI schema)
- `/debug` возвращает: `os.environ`, `sys.path`, CWD listing, включая `SECRET_KEY`, `CHEF_USERNAME`, DB URL
- Не в `/openapi.json` (`include_in_schema=False`)
- Нужен path discovery за пределами spec → не покрывается shelob-ng по умолчанию

#### R10 — Hidden delivery orders endpoint
- `GET /delivery/orders` — нет auth, нет в schema → все заказы с PII (адрес, телефон, позиции)
- Нужен wordlist-based path discovery

#### R11 — Command Injection (требует Chef role)
```python
command = "df -h " + parameters
subprocess.run(command, shell=True, capture_output=True)
```
- После получения Chef через R03: `GET /admin/stats/disk?parameters=/ ; id`

### Статистика

| Категория | Yes | Partial | No | Total |
|-----------|-----|---------|-----|-------|
| API1 BOLA | 1 | 0 | 0 | 1 |
| API2 Auth | 1 | 0 | 0 | 1 |
| API3 Mass Assign / Injection | 2 | 0 | 0 | 2 |
| API4 Rate Limit | 1 | 0 | 0 | 1 |
| API5 BFLA | 2 | 0 | 0 | 2 |
| API6 Business Flow | 0 | 1 | 0 | 1 |
| API8 Misconfig / SSRF | 1 | 0 | 1 | 2 |
| API9 Inventory | 1 | 0 | 0 | 1 |
| API10 Unsafe APIs | 0 | 0 | 1 | 1 |
| **ИТОГО** | **9** | **1** | **2** | **12** |

**Detection Rate:** `9/12 = 75%` (только yes), `10/12 = 83%` (yes+partial)

> ⚠️ R09 и R10 не покрываются shelob-ng: hidden endpoints не входят в OpenAPI spec.
> Нужен отдельный path-discovery pass с wordlist.

### Конфигурация shelob-ng для максимального покрытия

```bash
./shelob-ng \
  -spec     http://localhost:8091/openapi.json \
  -url      http://localhost:8091 \
  -user     customer@test.com -password Pass1! \
  -duration 10m
# Ожидаем: R01(NameSpaceRule), R03(SchemaViolation), R05+R06(BFLA),
#          R04(нет 429 checker нет в shelob-ng)
```

---

## Сводная таблица по targets

| Target | Total | Yes | Partial | No | Rate (yes) | Rate (yes+partial) |
|--------|-------|-----|---------|-----|-----------|-------------------|
| VAmPI | 9 | 5 | 3 | 1 | **56%** | 89% |
| crAPI | 21 | 11 | 6 | 4 | **52%** | 81% |
| Juice Shop | 106 | 38 | 22 | 46 | **36%** | 57% |
| DVWS-Node | 28 | 20 | 8 | 0 | **71%** | 100% |
| DVRestaurant | 12 | 9 | 1 | 2 | **75%** | 83% |
| **ИТОГО** | **176** | **83** | **40** | **53** | **47%** | **70%** |

### Почему показатели различаются

**VAmPI (56%)** — компактная мишень с точной spec, но 3 уязвимости требуют multi-step логики или offline атак (JWT crack, ReDoS timing, mass-assignment correlation).

**crAPI (52%)** — реалистичная архитектура: 3 LLM-уязвимости не детектируемы никаким REST фаззером; spec покрывает только identity service из трёх.

**Juice Shop (36%)** — 43% challenges требуют UI/OSINT/code analysis; 14 challenges **отключены** в Docker. Из REST-доступных 60/106 — это наиболее богатая мишень.

**DVWS-Node (71%)** — самая высокая доля для yes: все инъекции (`LDAP`, `XPath`, `SQLi`, `NoSQL`, `cmdi`) детектируемы по response anomaly. Нет LLM-only уязвимостей.

**DVRestaurant (75%)** — FastAPI auto-spec = нулевой дрейф; BFLA/BOLA сразу детектируются. Две уязвимости неdetectable без SSRF-цепочки или контроля внешнего сервиса.

### Gap-анализ: чего не хватает в shelob-ng для повышения Detection Rate

| Gap | Затронутые уязвимости | Effort |
|-----|----------------------|--------|
| Rate Limit Checker (нет 429 после N req/s) | V8, C03, R04, D22 | 0.5 дня |
| Path Discovery (hidden endpoints не в spec) | R09, R10, D23, J20 | 1 день |
| SSRF payload injection (`mechanic_api`, URL fields) | C11 | 0.5 дня |
| Multi-step Mass Assignment verify (POST→GET delta) | V4, C08-C10, R03 | 1 день |
| ReDoS / Timing-based checker | V7 | 1 день |
| JWT attack variants (alg:none, RS256→HS256) | V9, D03, C15, J25-J26 | уже есть AuthBypassRule; проверить |
