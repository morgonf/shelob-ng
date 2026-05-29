# shelob-ng / RESTler Demo Server — Complete Fuzzing Guide

[RESTler Demo Server](https://github.com/microsoft/restler-fuzzer/tree/main/demo_server) —
минимальный FastAPI блог (4 endpoints). Разработан Microsoft для демонстрации RESTler.

**Назначение:** количественный тест **producer-consumer dependency graph**.
Без него 3 из 4 операций возвращают 404. С ним — ≥80% 2xx rate.

---

## Быстрый старт

```bash
cd example/restler-demo/
make setup   # клонировать RESTler, установить deps, запустить сервер
make run-1   # тест producer-consumer
make stop    # остановить сервер
```

---

## Цепочка зависимостей

```
POST /api/blog/posts           → создаёт post, возвращает postId
                                  ↓ corpus pool сохраняет postId
GET    /api/blog/posts          → список всех постов (не зависит)
GET    /api/blog/posts/{postId} → читает конкретный пост (нужен postId)
PUT    /api/blog/posts/{postId} → обновляет пост (нужен postId)
DELETE /api/blog/posts/{postId} → удаляет пост (нужен postId)
```

---

## Установка

```bash
cd example/restler-demo/
make setup DEMO_SRC=/opt/restler-fuzzer
# Что делает:
#   - git clone https://github.com/microsoft/restler-fuzzer.git /opt/restler-fuzzer
#   - python3 -m venv venv && pip install -r requirements.txt
#   - запускает python demo_server/app.py в background (PID в /tmp/restler-demo.pid)
#   - скачивает spec с http://localhost:8888/openapi.json

# Проверить
curl http://localhost:8888/api/doc
curl -s http://localhost:8888/openapi.json | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('Paths:', list(d.get('paths',{}).keys()))
"
# Ожидаем: Paths: ['/api/blog/posts', '/api/blog/posts/{postId}', '/api/doc']
```

---

## Сценарии запуска

### Сценарий 1 — Producer-Consumer Test (основной)

```bash
make run-1
# или вручную:
./../../shelob-ng \
  -spec       openapi.json \
  -url        http://localhost:8888 \
  -corpus-dir corpus/demo \
  -csp-disable \
  -duration   5m \
  -output     results/01_producer_consumer
```

**Интерпретация результатов:**

```bash
python3 - results/01_producer_consumer/api-coverage.json << 'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
total = d['total']
reached = d['visited_count']
succeeded = d['succeeded_count']
rate = succeeded * 100 // total if total else 0
print(f"Total ops:    {total}")
print(f"Reached:      {reached}/{total}")
print(f"Succeeded 2xx: {succeeded}/{total} ({rate}%)")
print()
if rate >= 70:
    print("✓ PASS: producer-consumer graph working correctly")
    print(f"  POST /api/blog/posts создал posts → GET/PUT/DELETE получили postId")
elif rate >= 30:
    print("~ PARTIAL: graph working but needs more time")
    print("  Попробовать -duration 10m для накопления corpus")
else:
    print("✗ FAIL: dependency graph not working")
    print("  GET/DELETE /api/blog/posts/{postId} возвращают 404 (нет postId)")
    print("  Проверить corpus/demo/ — должны быть entries с path_params postId")
EOF
```

**Без работающего graph (ожидаем ~20%):**
```
POST /api/blog/posts → 201 Created, postId returned
GET  /api/blog/posts → 200 (не зависит от graph)
GET  /api/blog/posts/{postId} → 404 (нет postId в corpus)
PUT  /api/blog/posts/{postId} → 404
DELETE /api/blog/posts/{postId} → 404
```

**С работающим graph (ожидаем ~80%):**
```
POST /api/blog/posts → 201, postId=42 сохранён в corpus
GET  /api/blog/posts/{postId} → 200 (postId=42)
PUT  /api/blog/posts/{postId} → 200
DELETE /api/blog/posts/{postId} → 200
```

---

### Сценарий 2 — Без corpus (baseline comparison)

Сравнить производительность с и без corpus persistence.

```bash
# Без corpus
./../../shelob-ng \
  -spec       openapi.json \
  -url        http://localhost:8888 \
  -csp-disable \
  -duration   2m \
  -output     results/02_no_corpus

# С corpus
./../../shelob-ng \
  -spec       openapi.json \
  -url        http://localhost:8888 \
  -corpus-dir corpus/with_corpus \
  -csp-disable \
  -duration   2m \
  -output     results/03_with_corpus

# Сравнить
echo "=== Without corpus ==="
python3 -c "import json; d=json.load(open('results/02_no_corpus/api-coverage.json')); print(f'2xx: {d[\"succeeded_count\"]}/{d[\"total\"]}')"
echo "=== With corpus ==="
python3 -c "import json; d=json.load(open('results/03_with_corpus/api-coverage.json')); print(f'2xx: {d[\"succeeded_count\"]}/{d[\"total\"]}')"
```

---

### Сценарий 3 — Corpus Persistence (resume)

```bash
# Прогон 1 — накопить corpus
./../../shelob-ng \
  -spec       openapi.json \
  -url        http://localhost:8888 \
  -corpus-dir corpus/persistent \
  -csp-disable \
  -duration   3m \
  -output     results/run1

echo "Corpus после run1:"
cat corpus/persistent/index.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  entries: {d.get(\"entry_count\",0)}')"

# Прогон 2 — продолжить с сохранённого corpus
./../../shelob-ng \
  -spec       openapi.json \
  -url        http://localhost:8888 \
  -corpus-dir corpus/persistent \
  -csp-disable \
  -duration   3m \
  -output     results/run2

echo "Run2 должен начать с высокого 2xx rate (corpus загружен)"
```

---

### Сценарий 4 — PathDiscovery (baseline)

RESTler Demo — чистая реализация, не должно быть скрытых endpoints.

```bash
./../../shelob-ng \
  -spec     openapi.json \
  -url      http://localhost:8888 \
  -csp-disable \
  -duration 30s \
  -output   results/04_pathscan

ls results/04_pathscan/findings/ 2>/dev/null | wc -l
# Ожидаем: 0 findings
# Если PathDiscovery что-то нашёл — это баг или неожиданная конфигурация
```

---

### Сценарий 5 — Debug режим (наблюдение за corpus)

```bash
./../../shelob-ng \
  -spec       openapi.json \
  -url        http://localhost:8888 \
  -corpus-dir corpus/debug_run \
  -csp-disable \
  -duration   2m \
  -output     results/05_debug \
  -debug 2>&1 | grep -E "producer|consumer|postId|path_params|corpus" | head -40
```

**Что искать в debug output:**
```
# Corpus seed от spec (postId ещё неизвестен):
corpus: seeded entry POST /api/blog/posts pathParams={}

# После первого успешного POST:
corpus: learned producer POST /api/blog/posts → postId=1
corpus: seeded consumer GET /api/blog/posts/1

# Consumer получает реальный postId:
GET /api/blog/posts/1 → 200 OK ✓
```

---

## Структура Corpus

После запуска с `-corpus-dir`:

```
corpus/demo/
  index.json          {"version":1, "entry_count":8, ...}
  entries/
    abc123.json       {
                        "method": "POST",
                        "path_pattern": "/api/blog/posts",
                        "path_params": {},
                        "body": {"author":"test","title":"post","content":"x"},
                        "coverage_delta": 0,
                        "use_count": 3
                      }
    def456.json       {
                        "method": "GET",
                        "path_pattern": "/api/blog/posts/{postId}",
                        "path_params": {"postId": 1},  ← реальный ID от POST
                        "coverage_delta": 2
                      }
```

---

## Остановить сервер

```bash
make stop
# или:
kill $(cat /tmp/restler-demo.pid)
```

---

## Troubleshooting

| Проблема | Решение |
|---------|---------|
| `connection refused :8888` | Запустить `make setup` или проверить PID: `cat /tmp/restler-demo.pid` |
| 2xx rate ~20% | Producer-consumer не работает — проверить corpus/entries/ на наличие postId |
| ModuleNotFoundError | `cd example/restler-demo && pip install -r /opt/restler-fuzzer/demo_server/requirements.txt` |
| Сервер уже запущен | `make stop` перед повторным `make setup` |
