# shelob-ng / Swagger Petstore 3 — Complete Fuzzing Guide

[Swagger Petstore 3](https://github.com/swagger-api/swagger-petstore) — официальная
reference implementation OpenAPI 3.x (Java/inflector, 13 endpoints).
**Нет намеренных уязвимостей** — используется для измерения базовых метрик фаззера
и тестирования специфических функций: OAuth2, apiKey, XML bodies, form encoding.

---

## Назначение

| Задача | Что даёт |
|--------|----------|
| Benchmark 2xx rate | Baseline без уязвимостей: 30-50% 2xx (stateless) |
| Тест apiKey auth | `-apikey special-key` → auth header `api_key` |
| Тест OAuth2 | pre-obtained token → `-token <jwt>` |
| Тест XML bodies | Petstore принимает `application/xml` |
| Тест `explode: true` | `/pet/findByTags?tags=tag1&tags=tag2` |
| PathDiscovery baseline | Не должно быть скрытых endpoints (clean impl) |

---

## Быстрый старт

```bash
cd example/petstore/
make setup   # start container + fetch spec
make run-1   # spec coverage baseline
```

---

## Установка

```bash
cd example/petstore/
make setup
# Что делает:
#   - docker compose up -d (swaggerapi/petstore3:unstable)
#   - скачивает spec с http://localhost:8080/api/v3/openapi.json
#   - создаёт output dirs

# Проверить
curl http://localhost:8080/api/v3/openapi.json | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('Version:', d['openapi'])
print('Paths:', len(d.get('paths',{})))
"
# Ожидаем: Version: 3.0.4, Paths: 13
```

---

## Эндпоинты Petstore

| Path | Methods | Auth scheme | Назначение |
|------|---------|------------|-----------|
| `/pet` | GET, POST, PUT | `petstore_auth` (OAuth2) | CRUD для питомцев |
| `/pet/findByStatus` | GET | `petstore_auth` | поиск по статусу |
| `/pet/findByTags` | GET | `petstore_auth` | поиск по тегам |
| `/pet/{petId}` | GET, POST, DELETE | `petstore_auth` + `api_key` | конкретный питомец |
| `/pet/{petId}/uploadFile` | POST | `petstore_auth` | upload изображения |
| `/store/inventory` | GET | `api_key` | инвентарь магазина |
| `/store/order` | POST | none | создать заказ |
| `/store/order/{orderId}` | GET, DELETE | none | заказ по ID |
| `/user` | POST | none | создать пользователя |
| `/user/login` | GET | none | логин |
| `/user/logout` | GET | none | выход |
| `/user/{username}` | GET, PUT, DELETE | none | пользователь |
| `/user/createWithList` | POST | none | batch создание |

---

## Сценарии запуска

### Сценарий 1 — Spec Coverage Baseline

Измерить сколько endpoints достигается и возвращает 2xx без producer-consumer graph.

```bash
make run-1
# или вручную:
./../../shelob-ng \
  -spec     openapi.yaml \
  -url      http://localhost:8080/api/v3 \
  -apikey   special-key \
  -csp-disable \
  -duration 5m \
  -output   results/01_baseline
```

**Ожидаемые метрики:**
```
Reached:       13/13 (100%)
Succeeded 2xx: 4-6/13 (30-50%)
```

Низкий 2xx — ожидаем: Petstore stateless, `GET /pet/{petId}` возвращает 404 без
предварительного `POST /pet`. После реализации producer-consumer graph 2xx rate растёт.

**PathDiscovery:** Чистая реализация — не должно быть находок.
Если Spring Actuator endpoints (`/actuator/*`) недоступны — это правильно.

---

### Сценарий 2 — OAuth2 Implicit Flow (Bearer token)

```bash
# Получить токен из Swagger UI или использовать demo token
# (petstore3.swagger.io использует implicit flow с authorizationUrl)
# Для локального тестирования — использовать любой Bearer token

./../../shelob-ng \
  -spec     openapi.yaml \
  -url      http://localhost:8080/api/v3 \
  -token    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -csp-disable \
  -duration 5m \
  -output   results/02_bearer
```

---

### Сценарий 3 — Тест allOf/oneOf schema generation

Petstore schema содержит `$ref`, вложенные объекты (`Pet → Category, [Tag]`),
array с `explode: true`. Проверяет корректность генерации после багфикса T0.2.

```bash
./../../shelob-ng \
  -spec     openapi.yaml \
  -url      http://localhost:8080/api/v3 \
  -apikey   special-key \
  -csp-disable \
  -duration 2m \
  -output   results/03_schema_generation \
  -debug 2>&1 | grep -E "POST|PUT|body|schema" | head -30
```

**Что проверяем:**
- `POST /pet` с правильным JSON: `{"name":"rex","photoUrls":["http://example.com/photo.jpg"]}`
- `status` enum: только `available`, `pending`, `sold`
- `category.$ref` → правильно генерирует вложенный объект

---

### Сценарий 4 — XML и Form-encoded Bodies

Petstore принимает `application/json`, `application/xml`, и `application/x-www-form-urlencoded`.

```bash
# Проверить вручную XML endpoint
curl -X POST http://localhost:8080/api/v3/pet \
  -H 'Content-Type: application/xml' \
  -H 'api_key: special-key' \
  -d '<Pet><name>max</name><photoUrls><photoUrl>http://img.com/1.jpg</photoUrl></photoUrls></Pet>'
# Ожидаем: 200 OK с created pet

# Form-encoded
curl -X POST "http://localhost:8080/api/v3/pet/1" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'name=max&status=available'
```

---

### Сценарий 5 — Producer-Consumer Baseline

Тест что fuzzer использует ID из POST ответов для последующих GET/DELETE.

```bash
./../../shelob-ng \
  -spec       openapi.yaml \
  -url        http://localhost:8080/api/v3 \
  -apikey     special-key \
  -corpus-dir corpus/petstore \
  -csp-disable \
  -duration   10m \
  -output     results/05_producer_consumer
```

**Что наблюдать:**
```
# После нескольких итераций corpus должен содержать petId из POST /pet ответов
# GET /pet/{petId} и DELETE /pet/{petId} должны начать получать 2xx
# 2xx rate должна вырасти с ~35% до ~60% за 10 минут
```

---

### Сценарий 6 — PathDiscovery Baseline

Проверить что PathDiscovery не даёт ложных срабатываний на чистой реализации.

```bash
./../../shelob-ng \
  -spec     openapi.yaml \
  -url      http://localhost:8080/api/v3 \
  -apikey   special-key \
  -csp-disable \
  -duration 30s \
  -output   results/06_pathscan

ls results/06_pathscan/findings/ 2>/dev/null || echo "No findings (expected for clean implementation)"
```

**Ожидаем:** 0 findings от PathDiscovery. Если `make stop` → `make start` нужен clean state.

---

## Интерпретация результатов

```bash
# Coverage report
python3 -c "
import json
d = json.load(open('results/01_baseline/api-coverage.json'))
print(f'Reached:       {d[\"visited_count\"]}/{d[\"total\"]}')
print(f'Succeeded 2xx: {d[\"succeeded_count\"]}/{d[\"total\"]}')
for u in d.get('unvisited', []):
    print(f'  NOT REACHED: {u[\"method\"]} {u[\"path\"]}')
"

# Сравнить baseline vs corpus-guided
echo "Without corpus (stateless):"
python3 -c "import json; d=json.load(open('results/01_baseline/api-coverage.json')); print(f'  2xx: {d[\"succeeded_count\"]}/{d[\"total\"]}')"

echo "With corpus (after 10m):"
python3 -c "import json; d=json.load(open('results/05_producer_consumer/api-coverage.json')); print(f'  2xx: {d[\"succeeded_count\"]}/{d[\"total\"]}')"
```

---

## Troubleshooting

| Проблема | Решение |
|---------|---------|
| `401 Unauthorized` | Petstore использует OAuth2 scopes — попробовать `-apikey special-key` |
| `422 Unprocessable Entity` | Невалидные enum значения (status: only available/pending/sold) |
| `/pet/{petId}` всегда 404 | Petstore stateless — нужен producer-consumer graph |
| PathDiscovery находит что-то | Проверить — может быть actuator exposed (не норма для petstore) |

> **Не фаззить** `petstore3.swagger.io` (публичный сервер). Только локальный `docker run`.
