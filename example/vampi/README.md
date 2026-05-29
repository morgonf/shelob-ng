# shelob-ng / VAmPI — Complete Fuzzing Guide

[VAmPI](https://github.com/erev0s/VAmPI) — намеренно уязвимый REST API (Python/Flask).
Один из лучших targets для shelob-ng: **полная OpenAPI 3.x spec**, все 9 уязвимостей
точно задокументированы, есть switchable vulnerable/secure mode для baseline сравнения.

**Проверено 2026-05-29:** 2-минутный прогон → 33 findings (7 HIGH, 26 MEDIUM), 100% coverage.

---

## Быстрый старт

```bash
cd example/vampi/
make setup    # build fuzzer, start VAmPI, seed DB, fetch spec
make run-2    # BOLA detection (core vulnerability)
make run-1    # базовый скан с новыми checkers
```

---

## Структура директории

```
vampi/
  Makefile
  config.env                      переменные: URL, credentials, пути
  docker-compose.yml              VAmPI с tokentimetolive=3600
  scripts/
    01_setup.sh                   запуск, seed DB, fetch spec
    02_scenario_basic.sh          Scenario 1: базовый аутентифицированный скан
    03_scenario_bola.sh           Scenario 2: BOLA / NameSpaceRule
    04_scenario_payloads.sh       Scenario 3: injection payloads
  results/                        создаётся при запуске
  corpus/                         создаётся при запуске
```

---

## Предварительные требования

| Инструмент | Версия | Назначение |
|-----------|--------|-----------|
| Go | ≥ 1.22 | сборка shelob-ng |
| Docker + Compose v2 | ≥ 20.x | запуск VAmPI |
| Python 3 | любая | парсинг spec в setup скрипте |

---

## Установка и запуск (one-time setup)

```bash
# 1. Скачать и запустить VAmPI с расширенным JWT TTL
cd example/vampi/
make setup
# Что делает setup:
#   - go build -o ../../shelob-ng . (сборка бинарника)
#   - docker compose up -d (запуск erev0s/vampi:latest)
#   - GET /createdb (обязательный seed БД)
#   - проверяет логин admin1/pass1
#   - скачивает openapi3.yaml (12 paths, 12 endpoints)

# 2. Проверить что всё работает
curl http://localhost:5000/
# ожидаем: {"message": "VAmPI the Vulnerable API", "vulnerable": 1}
```

> **Важно:** `tokentimetolive=3600` в docker-compose.yml — без этого JWT истекает
> за 60 сек и фаззер начинает получать 401 в середине прогона.

---

## Уязвимости VAmPI — Каталог

Полный каталог: `docs/knowledge-base/vuln-catalogue.md` (секция VAmPI).

| ID | OWASP API 2019 | Endpoint | Что детектирует |
|----|---------------|----------|----------------|
| V1 | API8 SQLi | `GET /users/v1/{username}` | BehavioralPatterns |
| V2 | API1 BOLA | `PUT /users/v1/{username}/password` | NameSpaceRule |
| V3 | API1 BOLA | `GET /books/v1/{book_title}` | NameSpaceRule |
| V4 | API6 Mass Assignment | `POST /users/v1/register` | MassAssignment |
| V5 | API3 Data Exposure | `GET /users/v1/_debug` | **PathDiscovery** |
| V6 | API2 Auth | `POST /users/v1/login` | BehavioralPatterns |
| V7 | API4 ReDoS | `PUT /users/v1/{username}/email` | **ReDoSChecker** |
| V8 | API4 Rate Limit | все endpoints | **RateLimitChecker** |
| V9 | API2 JWT | все auth endpoints | (offline attack) |

---

## Сценарии запуска

### Сценарий 1 — Базовый скан (все новые checkers)

Проверяет работу PathDiscovery, RateLimitChecker, MassAssignment, ReDoS.

```bash
make run-1
# или вручную:
./../../shelob-ng \
  -spec     openapi3.yaml \
  -url      http://localhost:5000 \
  -user     admin1 -password pass1 \
  -csp-disable \
  -duration 2m \
  -output   results/01_basic
```

**Ожидаемые findings за 2 минуты:**

| Checker | Severity | Finding |
|---------|----------|---------|
| PathDiscovery | **HIGH** | `/users/v1/_debug` — пароли всех пользователей открыты (V5) |
| RateLimitChecker | **HIGH** | `POST /users/v1/login` — нет 429, 8 запросов ответили 200×8 (V8) |
| RateLimitChecker | **HIGH** | `PUT /users/v1/{username}/password` — нет 429 (V8) |
| RateLimitChecker | MEDIUM | все остальные endpoints — нет 429 (V8) |
| BehavioralPatterns | **HIGH** | SQLi в `/users/v1/{username}` — `near "A": syntax error` (V1) |
| MassAssignment | MEDIUM | `POST /register` — поля `admin:true, role:"admin"` приняты без 422 (V4) |
| ReDoSChecker | MEDIUM | `POST /login` — `password` field: ratio 258x/835ms (V7) |

---

### Сценарий 2 — BOLA / NameSpaceRule

Два пользователя: user1 создаёт ресурсы, user2 пытается их читать.

```bash
make run-2
# или вручную:
./../../shelob-ng \
  -spec     openapi3.yaml \
  -url      http://localhost:5000 \
  -user     admin1  -password pass1 \
  -user2    user2   -pass2    pass2 \
  -csp-disable \
  -duration 5m \
  -output   results/02_bola
```

**Как работает NameSpaceRule:**
```
1. admin1 GET /books/v1/admin1-book → 200 (ресурс существует)
2. anonymous probe → 401 (не публичный)
3. user2 GET /books/v1/admin1-book → 200  ← BOLA HIGH (V3)
```

**Ожидаемые findings:**
- `NameSpaceRule HIGH` — `GET /books/v1/{book_title}` (V3: книга admin1 доступна user2)
- `NameSpaceRule HIGH` — `GET /users/v1/{username}` (V2: профиль admin1 доступен user2)

**Почему нужен длинный прогон (5m):**
Corpus должен накопить реальные `book_title` из ответов `GET /books/v1` через
Dynamic Value Pool. В первые 30 сек книг нет — `404` не триггерит checker.

---

### Сценарий 3 — Payload Injection (SQLi/NoSQL/LFI)

Целевой скан с wordlists — максимизирует шанс обнаружить V1.

```bash
make run-3
# или вручную с кастомными wordlists:
./../../shelob-ng \
  -spec     openapi3.yaml \
  -url      http://localhost:5000 \
  -user     admin1 -password pass1 \
  -payloads sqli=../juice-shop/payloads/sqli.txt,\
            nosql=../juice-shop/payloads/nosql.txt,\
            lfi=../juice-shop/payloads/lfi.txt \
  -csp-disable \
  -duration 15m \
  -output   results/03_payloads
```

**Ожидаемые findings:**
- `BehavioralPatterns HIGH` — SQL Error в `/users/v1/{username}`:
  `near "A": syntax error` при UNION SELECT payloads
- `BehavioralPatterns HIGH` — если NoSQL payloads попадут в MongoDB-backed endpoint

---

### Сценарий 4 — Полный аудит

Все checkers + payloads + два пользователя + corpus persistence.

```bash
./../../shelob-ng \
  -spec       openapi3.yaml \
  -url        http://localhost:5000 \
  -user       admin1  -password pass1 \
  -user2      user2   -pass2    pass2 \
  -payloads   sqli=../juice-shop/payloads/sqli.txt,\
              nosql=../juice-shop/payloads/nosql.txt \
  -corpus-dir corpus/full \
  -csp-disable \
  -duration   30m \
  -output     results/04_full_audit
```

**Ожидаемый Detection Rate за 30 минут:**

| Уязвимость | Ожидается |
|-----------|----------|
| V1 SQLi | ✓ BehavioralPatterns HIGH |
| V2 BOLA password | ✓ NameSpaceRule HIGH |
| V3 BOLA books | ✓ NameSpaceRule HIGH |
| V4 Mass Assignment | ✓ MassAssignment MEDIUM |
| V5 Debug endpoint | ✓ PathDiscovery HIGH |
| V7 ReDoS | ✓ ReDoSChecker MEDIUM |
| V8 No Rate Limit | ✓ RateLimitChecker HIGH/MEDIUM |

---

### Сценарий 5 — Differential Testing (vulnerable vs secure)

```bash
# 1. Запустить в vulnerable=1 (по умолчанию)
make run-2
cp -r results/02_bola results/bola_vulnerable

# 2. Перезапустить в secure mode
docker compose down
docker run -d -e vulnerable=0 -e tokentimetolive=3600 \
  -p 5000:5000 erev0s/vampi:latest
curl http://localhost:5000/createdb
make run-2
cp -r results/02_bola results/bola_secure

# 3. Сравнить
echo "Vulnerable mode findings:"
ls results/bola_vulnerable/findings/ | wc -l
echo "Secure mode findings:"
ls results/bola_secure/findings/ | wc -l
# Ожидаем: secure mode — 0-2 findings (только V5 _debug остаётся)
```

> **VAmPI V5 остаётся уязвимым даже в secure mode** — `/users/v1/_debug` всегда
> открыт (закомментировано в app.py). PathDiscovery найдёт его в обоих режимах.

---

### Сценарий 6 — Selective checkers (изоляция по типу)

Запустить только один checker для точной диагностики.

```bash
# Только PathDiscovery (pre-scan — всегда выполняется, нельзя отключить)
# PathDiscovery запускается автоматически перед циклом

# Только Rate Limit
./../../shelob-ng -spec openapi3.yaml -url http://localhost:5000 \
  -user admin1 -password pass1 -checker RateLimitChecker \
  -csp-disable -duration 1m -output results/rate_limit_only

# Только BOLA
./../../shelob-ng -spec openapi3.yaml -url http://localhost:5000 \
  -user admin1 -password pass1 -user2 user2 -pass2 pass2 \
  -checker NameSpaceRule \
  -csp-disable -duration 10m -output results/bola_only

# Только Mass Assignment
./../../shelob-ng -spec openapi3.yaml -url http://localhost:5000 \
  -user admin1 -password pass1 \
  -checker MassAssignment \
  -csp-disable -duration 5m -output results/mass_assignment_only
```

---

## Новые Checkers — подробности

### PathDiscovery (pre-scan)

Запускается автоматически **перед** главным циклом, зондирует 70+ путей.

На VAmPI находит: `GET /users/v1/_debug` → 200 + `"password"` в теле → **HIGH**.

```bash
# Вручную воспроизвести находку:
curl -v http://localhost:5000/users/v1/_debug
# Ответ: [{"admin":false,"email":"admin1@mail.com","password":"pass1",...}, ...]
```

С кастомным wordlist:
```bash
./../../shelob-ng -spec openapi3.yaml -url http://localhost:5000 \
  -user admin1 -password pass1 \
  -path-wordlist my_custom_paths.txt \
  -csp-disable -duration 1m
# Формат my_custom_paths.txt:
# /custom-debug
# /api/admin/users  admin endpoint
# /internal/config  internal config
```

### RateLimitChecker

**Порог:** 5 запросов на auth-путях (`/login`, `/register`, `/password`),
20 запросов на остальных. После порога — burst из 8 запросов.

На VAmPI: ни один endpoint не возвращает 429.

```bash
# Воспроизвести вручную:
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:5000/users/v1/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin1","password":"wrongpass"}'
done
# Ожидаем: 403 403 403 403 403 403 403 403 403 403 — нет 429
```

### MassAssignment

Инжектирует `{"admin":true, "role":"admin", "credits":99999, ...}` в POST/PUT/PATCH.

На VAmPI: `POST /users/v1/register` возвращает 200 с poison fields → **MEDIUM**.
Для подтверждения HIGH нужно проверить через `GET /users/v1/{username}` что
`admin=true` сохранился.

```bash
# Воспроизвести вручную:
curl -X POST http://localhost:5000/users/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"hacker","password":"pass","email":"x@x.com","admin":true}'
# Ожидаем: 200 {"status":"success"}

# Проверить что admin=true сохранился:
TOKEN=$(curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"hacker","password":"pass"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['auth_token'])")
curl http://localhost:5000/me -H "Authorization: Bearer $TOKEN"
# Если admin:true — HIGH finding подтверждён
```

### ReDoSChecker

Сравнивает время ответа для короткой (10 символов) и длинной (80 символов)
строки с паттерном `aaaa...@` (email regex ReDoS).

На VAmPI: `POST /login password` — ratio 258x, 835ms → **MEDIUM**.

```bash
# Воспроизвести:
time curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"name1","password":"aa@"}' -o /dev/null
# ≈ 5ms

time curl -s -X POST http://localhost:5000/users/v1/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"name1\",\"password\":\"$(python3 -c "print('a'*80+'@')")\"}" -o /dev/null
# ≈ 500-900ms (зависит от нагрузки контейнера)
```

---

## Интерпретация результатов

```bash
# Все findings с severity
ls results/*/findings/*.json | while read f; do
  python3 -c "import json; d=json.load(open('$f')); print(d['severity'].upper(), d['checker'], '-', d['title'][:50])"
done | sort

# POC команды для воспроизведения
for f in results/*/findings/*.json; do
  python3 -c "
import json; d=json.load(open('$f'))
if d.get('poc'):
    print('# ' + d['checker'] + ': ' + d['title'])
    print(d['poc'])
    print()
" 2>/dev/null
done

# Coverage report
python3 -c "
import json
d = json.load(open('results/01_basic/api-coverage.json'))
print(f'Reached: {d[\"visited_count\"]}/{d[\"total\"]} ({100*d[\"visited_count\"]//d[\"total\"]}%)')
print(f'Success (2xx): {d[\"succeeded_count\"]}/{d[\"total\"]} ({100*d[\"succeeded_count\"]//d[\"total\"]}%)')
"
```

---

## Troubleshooting

| Проблема | Причина | Решение |
|---------|---------|---------|
| `401` на всех запросах через 1 мин | JWT expired (default 60s TTL) | Использовать docker-compose.yml с `tokentimetolive=3600` |
| Нет BOLA findings за 5 min | Corpus не накопил book_title | Увеличить duration до 10m или запустить с `-corpus-dir` |
| `404` на `/createdb` | БД уже заполнена | Нормально — перезапустить контейнер если нужен clean state |
| ReDoS findings в secure=0 mode | V7 остаётся в обоих режимах | Это ожидаемо — regex не исправлен в secure mode |
| PathDiscovery не находит _debug | spec URL изменился | Убедиться что spec скачан с `http://localhost:5000/openapi.json` |
