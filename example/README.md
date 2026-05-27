# shelob-ng / OWASP Juice Shop — example

Полный контрольный пример для проверки работы фаззера на [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — намеренно уязвимом Node.js-приложении.

Покрывает **все 8 сценариев использования** фаззера.

---

## Содержимое

```
example/
  Makefile                    главный оркестратор (make help)
  config.env                  общая конфигурация (URL, учётные данные, пути)
  docker-compose.yml          стандартный Juice Shop (порт 3000)
  docker-compose.csp.yml      Juice Shop + CSP sidecar (порты 3000 + 8080)
  payloads/
    sqli.txt                  SQL-инъекции (boolean, union, error, time-based)
    xss.txt                   XSS (reflected, DOM, filter bypass)
    ssti.txt                  SSTI (Jinja2, Twig, Handlebars, ERB)
    lfi.txt                   LFI / Path traversal
  csp/
    adapter.js                Node.js CSP-адаптер (V8 Inspector API)
    Dockerfile                образ Juice Shop с CSP-адаптером
  scripts/
    00_check.sh               проверка зависимостей
    01_setup.sh               первичная настройка
    02..09_scenario_*.sh      сценарии 1–8
    10_report.sh              агрегация находок
  results/                    создаётся при запуске (в .gitignore)
  corpus/                     создаётся при запуске (в .gitignore)
```

---

## Быстрый старт (4 команды)

```bash
cd example/

# 1. Проверить зависимости (Go ≥1.22, Docker, curl)
make check

# 2. Собрать фаззер, запустить Juice Shop, создать тестовые аккаунты
make setup

# 3. Запустить полный аудит (все функции, 1 час)
make run-8

# 4. Посмотреть результаты
make report
```

---

## Предварительные требования

| Инструмент | Версия | Зачем |
|-----------|--------|-------|
| Go | ≥ 1.22 | компиляция фаззера |
| Docker | ≥ 20.x | запуск Juice Shop |
| Docker Compose | v2 | оркестрация контейнеров |
| curl | любая | создание аккаунтов, проверки |
| jq | любая | красивый вывод в report.sh (опционально) |

Проверить одной командой:
```bash
make check
```

---

## Сценарии

### Обзор

| # | Сценарий | Функции | Duration |
|---|---------|---------|---------|
| 1 | Pure random | базовые чекеры без авторизации | 5m |
| 2 | Authenticated | авторизация через cookie | 5m |
| 3 | BOLA | два пользователя, NameSpaceRule | 5m |
| 4 | Security payloads | SQLi/XSS/SSTI/LFI вордлисты | 15m |
| 5 | Coverage-guided | CSP + corpus | 15m |
| 6 | Corpus persistence | сохранение и продолжение | 5m+5m |
| 7 | Selective checkers | три суб-сценария по одному чекеру | 5m×3 |
| 8 | Full | все функции одновременно | 1h |

Запуск каждого сценария:
```bash
make run-1   # или run-2, run-3 ... run-8
make run-quick   # сценарии 1–4 подряд
make run-all     # все 8 сценариев
```

---

### Сценарий 1 — Pure random

**Что тестирует:** базовую работу фаззера без аутентификации.

**Как работает:**
```
OpenAPI spec → SeedFromSpec (143 entries) → mutator → HTTP → checkers
```

**Запуск:**
```bash
make run-1
# или напрямую:
./shelob-ng -spec juice-shop.openapi.json -url http://localhost:3000 -duration 5m
```

**Чекеры:** BehavioralPatterns, InvalidDynamicObject, LeakageRule, SchemaViolation  
**Ожидаемые находки:** SQL-ошибки в теле ответа, 500 на граничных значениях

---

### Сценарий 2 — Authenticated

**Что тестирует:** эндпоинты, требующие авторизации.

**Как работает:**
1. `auth.CreateUserWithLoginEndpoint` делает POST /rest/user/login
2. Полученные cookies прикрепляются к каждому запросу
3. Фаззер получает доступ к `/api/BasketItems`, `/api/Orders`, `/rest/user/whoami` и т.д.

**Запуск:**
```bash
make run-2
```

**Дополнительные эндпоинты:** все authenticated-only пути из spec  
**Ожидаемые находки:** те же + баги в endpoint-ах требующих авторизации

---

### Сценарий 3 — BOLA / NameSpaceRule

**Что тестирует:** Broken Object Level Authorization (OWASP API #1).

**Как работает:**
```
User1: GET /api/BasketItems/42  → 200 OK
NameSpaceRule: replay с cookies User2
User2: GET /api/BasketItems/42  → если 200 = FINDING HIGH
```

**Требует:** два аккаунта (создаются в `make setup`)

**Запуск:**
```bash
make run-3
```

**Ожидаемые находки:** BOLA/IDOR — User2 может получить корзину User1

---

### Сценарий 4 — Security payload injection

**Что тестирует:** инъекции через вордлисты.

**Архитектура:**
```
payloads/sqli.txt  ┐
payloads/xss.txt   ├─→ securityMutator → PickStringFields → inject → BehavioralPatterns
payloads/ssti.txt  │
payloads/lfi.txt   ┘
```

**Targets (поля для инъекции):**
- Path params со строковым значением
- Все query / header / cookie params
- String leaves в JSON body (через dotted-path)

**Запуск:**
```bash
make run-4
```

**Ожидаемые находки:**
- SQL-ошибки в `/rest/products/search?q=<payload>`
- Отражённые XSS-строки в некоторых ответах

**Добавление собственных пейлоадов:**
```bash
# Скопировать интересные paylods из PayloadsAllTheThings
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /tmp/patt
cp /tmp/patt/SQL\ Injection/Intruder/Auth_Bypass.txt payloads/sqli_bypass.txt
# Добавить в команду:
PAYLOAD_FLAG=sqli=payloads/sqli.txt,sqlibypass=payloads/sqli_bypass.txt make run-4
```

---

### Сценарий 5 — Coverage-guided (CSP)

**Что тестирует:** работу feedback-цикла покрытия.

**Требует:** CSP-инструментированный образ Juice Shop.

**Сборка и запуск образа:**
```bash
# Собрать образ с CSP-адаптером
docker compose -f docker-compose.yml -f docker-compose.csp.yml build

# Запустить (порты 3000 и 8080)
make start-csp
```

**Как работает CSP-адаптер:**
```
adapter.js загружается через NODE_OPTIONS="--require ./csp-adapter.js"
          ↓
V8 Inspector → Profiler.startPreciseCoverage()
          ↓
POST /csp/reset   → сохранить текущий snapshot как baseline
<Juice Shop обрабатывает запрос от фаззера>
GET  /csp/dump    → вернуть new_since_reset[] = (current - baseline)
          ↓
shelob-ng: если len(new_since_reset) > 0 → corpus.Add(entry, delta)
```

**Запуск:**
```bash
make start-csp    # запустить инструментированный образ
make run-5        # запустить сценарий
```

**Что видно на экране:**
```
#8      NEW      cov:    12  corpus:   144  ...  [GET /api/Users  +12]
#16     NEW      cov:    19  corpus:   145  ...  [POST /api/Orders  +7]
```

Столбец `cov:` растёт по мере обнаружения новых путей.

---

### Сценарий 6 — Corpus persistence

**Что тестирует:** сохранение и восстановление корпуса.

**Run 1** → собирает корпус, сохраняет на диск:
```
corpus/scenario6/
  index.json           {"version":1,"entry_count":89,...}
  entries/
    a3f1b2...json      {"method":"GET","path_pattern":"/api/Users",...}
    ...
```

**Run 2** → загружает корпус, продолжает с места остановки:
```
INFO: corpus: 89 entries total after loading from ./corpus/scenario6
```

**Запуск:**
```bash
make run-6   # два последовательных прогона
```

---

### Сценарий 7 — Selective checkers

**Что тестирует:** гибкость настройки чекеров.

Три суб-сценария:
```
7a: -checker SchemaViolation            — только схема, 0 extra requests
7b: -checker BehavioralPatterns         — только паттерны + пейлоады SQLi/XSS
7c: -checker UseAfterFree,InvalidDynamic — stateful, extra probes
```

**Запуск:**
```bash
make run-7
```

**Когда использовать:**
- `SchemaViolation` — быстрая проверка соответствия spec (нет probe-запросов)
- `BehavioralPatterns` — целевой поиск инъекций с вордлистами
- `UseAfterFree,InvalidDynamicObject` — тест управления ресурсами

---

### Сценарий 8 — Full mode

**Всё включено одновременно.**

```bash
make run-8
# или с короткими таймаутами для быстрой проверки:
DURATION_FULL=10m make run-8
```

Команда фаззера развёрнуто:
```bash
./shelob-ng \
  -spec       juice-shop.openapi.json     \
  -url        http://localhost:3000       \
  -user       fuzzer@shelob.local         \
  -password   Shelob1!                    \
  -user2      victim@shelob.local         \
  -pass2      Victim1!                    \
  -payloads   sqli=payloads/sqli.txt,xss=payloads/xss.txt,\
              ssti=payloads/ssti.txt,lfi=payloads/lfi.txt  \
  -corpus-dir corpus/full                 \
  -duration   1h                          \
  -output     results/08_full
```

---

## Ожидаемые находки на Juice Shop

| Чекер | Находка | Endpoint | Severity |
|-------|---------|---------|---------|
| BehavioralPatterns | SQL/Sequelize error text | `/rest/products/search?q=` | medium |
| BehavioralPatterns | Error object leak | `/api/Users/0`, `/api/Users/-1` | medium |
| InvalidDynamicObject | 500 на граничных ID | `/api/Users/{id}`, `/api/Products/{id}` | medium |
| SchemaViolation | Response does not match spec | разные | low |
| NameSpaceRule | Доступ к корзине другого пользователя | `/api/BasketItems/{id}` | high |
| BehavioralPatterns | Стек-трейс в теле | разные | medium |

---

## Интерпретация вывода

```
INFO: spec: juice-shop.openapi.json
INFO: target: http://localhost:3000
INFO: coverage: disabled (pure-random mode)
INFO: corpus: 143 seed entries
INFO: checkers: BehavioralPatterns UseAfterFree InvalidDynamicObject LeakageRule SchemaViolation

#0      INITED   cov:     0  corpus:   143  req/s:     0  2xx:     0  4xx:     0  5xx:     0
#32     pulse    cov:     0  corpus:   143  req/s:    27  2xx:    15  4xx:    17  5xx:     0
#64     FINDING  ...  [BehavioralPatterns/medium] Error message leaked  http://...
```

| Поле | Значение |
|------|---------|
| `#N` | Номер запроса (включая probe-запросы чекеров) |
| `cov:` | Суммарно новых строк кода (0 в pure-random) |
| `corpus:` | Количество записей в корпусе |
| `req/s:` | Скорость с начала запуска |
| `2xx/4xx/5xx:` | Счётчики статусов ответов |

Находки пишутся в `results/<scenario>/findings/`.

---

## Воспроизведение находки

```bash
# Найти находку
cat results/08_full/findings/BehavioralPatterns_20260527_140001_000.json

# Воспроизвести вручную
curl -v "http://localhost:3000/rest/products/search?q=%27+OR+%271%27%3D%271"

# Воспроизвести sequence-находку из replay-файла
cat results/08_full/replays/CRUD__api_Users_*.json | python3 -m json.tool
```

---

## Добавление собственных пейлоадов

Рекомендуемый источник — [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings):

```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /tmp/patt

# SQL Injection
cp "/tmp/patt/SQL Injection/Intruder/SQL_Bypass.txt" payloads/sqli_advanced.txt

# XSS
cp "/tmp/patt/XSS Injection/Intruder/XSS Polyglots.txt" payloads/xss_poly.txt

# SSTI
cp "/tmp/patt/Server Side Template Injection/Intruder/ssti_polyglot.txt" payloads/ssti_poly.txt

# Запустить с расширенными пейлоадами
PAYLOAD_FLAG="sqli=payloads/sqli.txt,sqlia=payloads/sqli_advanced.txt,\
xss=payloads/xss.txt,xssp=payloads/xss_poly.txt" make run-4
```

---

## Структура выходных файлов

```
results/
  01_pure_random/
    findings/
      BehavioralPatterns_20260527_140001_000.json
  08_full/
    findings/
      NameSpaceRule_20260527_150312_000.json
    replays/
      CRUD__api_Users_20260527_151200_000.json

corpus/
  full/
    index.json
    entries/
      a3f1b2c4...json
```

**Структура finding-файла:**
```json
{
  "checker":    "NameSpaceRule",
  "severity":   "high",
  "title":      "User2 can access User1 resource",
  "detail":     "Replayed as user2; original request by user1 returned 200",
  "method":     "GET",
  "url":        "http://localhost:3000/api/BasketItems/14",
  "status_code": 200
}
```

**Структура replay-файла:**
```json
{
  "sequence":    "CRUD:/api/Users",
  "executed_at": "2026-05-27T15:12:00Z",
  "steps": [
    {"method":"POST","url":"http://localhost:3000/api/Users","status_code":201,
     "extracted":{"id":"7"}},
    {"method":"GET", "url":"http://localhost:3000/api/Users/7","status_code":200},
    {"method":"DELETE","url":"http://localhost:3000/api/Users/7","status_code":204},
    {"method":"GET", "url":"http://localhost:3000/api/Users/7","status_code":200}
  ],
  "findings": [...]
}
```
