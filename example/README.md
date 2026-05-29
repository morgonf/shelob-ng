# shelob-ng / examples

Готовые к запуску примеры использования shelob-ng против различных тестовых API.
Каждая мишень — самостоятельная директория со своим `Makefile`, `config.env` и скриптами.

---

## Тестовые мишени

| Директория | Мишень | Тип | Уязвимости | Сложность запуска |
|-----------|--------|-----|-----------|-----------------|
| [`juice-shop/`](juice-shop/) | OWASP Juice Shop | vulnerable | Full OWASP Top 10 + API | Простой (`docker`) |
| [`vampi/`](vampi/) | VAmPI | vulnerable | BOLA, SQLi, mass assign, JWT | Простой (`docker`) |
| [`crapi/`](crapi/) | crAPI (OWASP) | vulnerable | Все OWASP API Top 10 2023 + LLM | Средний (`docker compose`) |
| [`dvws-node/`](dvws-node/) | DVWS-Node | vulnerable | 39 классов: XML, NoSQL, GraphQL | Средний (внешний repo) |
| [`petstore/`](petstore/) | Swagger Petstore 3 | sandbox | Нет (эталонная реализация) | Простой (`docker`) |
| [`restler-demo/`](restler-demo/) | RESTler Demo | demo | Нет (тест producer-consumer) | Простой (Python) |

---

## Быстрый старт по каждой мишени

### Juice Shop (10 сценариев, CSP-покрытие)

```bash
cd juice-shop/
make setup    # build, start, accounts, spec
make run-3    # BOLA detection
make run-8    # full 1-hour audit
```

→ Подробнее: [juice-shop/README.md](juice-shop/README.md)

### VAmPI (лучшая spec, предсказуемые уязвимости)

```bash
cd vampi/
make setup    # build, start, seed DB, fetch spec
make run-2    # BOLA
make run-3    # payload injection
```

→ Подробнее: [vampi/README.md](vampi/README.md)

### crAPI (все OWASP API Top 10, microservices)

```bash
# Сначала запустить crAPI извне:
git clone https://github.com/OWASP/crAPI.git /opt/crapi
cd /opt/crapi/deploy/docker && docker compose -f docker-compose.minimal.yml up -d
# Подтвердить email через Mailhog: http://localhost:8025

cd example/crapi/
make setup && make run-2   # BOLA
```

→ Подробнее: [crapi/README.md](crapi/README.md)

### DVWS-Node (39 уязвимостей, XML, GraphQL)

```bash
git clone https://github.com/snoopysecurity/dvws-node.git /opt/dvws-node
cd /opt/dvws-node && docker-compose up -d

cd example/dvws-node/
make setup && make run-2   # injection payloads
```

→ Подробнее: [dvws-node/README.md](dvws-node/README.md)

### Petstore 3 (benchmark 2xx rate)

```bash
cd petstore/
make setup && make run-1   # spec coverage baseline
```

→ Подробнее: [petstore/README.md](petstore/README.md)

### RESTler Demo (тест producer-consumer graph)

```bash
cd restler-demo/
make setup && make run-1   # producer-consumer test
make stop                   # остановить сервер
```

→ Подробнее: [restler-demo/README.md](restler-demo/README.md)

---

## Структура каждой директории

```
<target>/
  Makefile          make setup / make run-N / make clean
  config.env        URL, credentials, paths — все переменные
  docker-compose.yml (если нужен)
  scripts/
    01_setup.sh     сборка бинарника, запуск, получение spec
    02_scenario_*.sh  сценарии фаззинга
    ...
  results/          findings, api-coverage.json (gitignored)
  corpus/           сохранённый корпус (gitignored)
```

---

## Общие паттерны

### Бинарник фаззера
Все примеры собирают бинарник в корне репозитория (`../../shelob-ng`):

```bash
cd ../..  && go build -o shelob-ng .  # из любой поддиректории example/
```

### Переопределение параметров

```bash
DURATION_QUICK=2m make run-1          # быстрый тест
RPS=5 make run-2                       # снизить нагрузку
FUZZER_USER=myuser FUZZER_PASS=mypass make run-1
```

### Просмотр findings

```bash
ls results/01_basic/findings/
jq . results/01_basic/findings/BehavioralPatterns_GET_*.json
jq -r '.poc' results/*/findings/*.json    # все POC команды
```

---

## Выбор мишени

| Задача | Рекомендуемая мишень |
|--------|---------------------|
| Первый запуск, быстрый результат | `vampi` |
| Полное покрытие OWASP API Top 10 | `crapi` |
| Тест injection (SQLi, cmdi, XML) | `dvws-node` |
| Тест JWT/Bearer auth | `juice-shop` (scenario 9) |
| Тест OAuth2 + apiKey | `petstore` |
| Тест producer-consumer graph | `restler-demo` |
| Тест CSP coverage-guided mode | `juice-shop` (scenario 5, 8) |
