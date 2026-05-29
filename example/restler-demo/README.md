# shelob-ng / RESTler Demo Server — worked example

The [RESTler Demo Server](https://github.com/microsoft/restler-fuzzer/tree/main/demo_server)
is a minimal FastAPI blog (4 endpoints) used in the Microsoft RESTler tutorial.

**Best for:** Testing the producer-consumer dependency graph. The server has exactly
one dependency chain: `POST /api/blog/posts` creates a `postId` that `GET/PUT/DELETE`
must consume. Without the dependency graph, 3 of 4 operations return 404.

---

## Quick start

```bash
cd example/restler-demo/
make setup    # clone RESTler, install deps, start server
make run-1    # producer-consumer test
make stop     # kill background server
```

---

## Contents

```
restler-demo/
  Makefile
  config.env                        shared config
  scripts/
    01_setup.sh                     clone RESTler, start server, fetch spec
    02_scenario_producer_consumer.sh Scenario 1: dependency chain test
  results/                          created at runtime
  corpus/                           created at runtime
  venv/                             Python virtualenv (created by setup, gitignored)
```

---

## How to interpret the results

The demo server has 4 operations:

| Op | Depends on |
|----|-----------|
| `POST /api/blog/posts` | nothing (producer) |
| `GET /api/blog/posts` | nothing (list) |
| `GET /api/blog/posts/{postId}` | `postId` from POST |
| `PUT /api/blog/posts/{postId}` | `postId` from POST |
| `DELETE /api/blog/posts/{postId}` | `postId` from POST |

**Without dependency graph:**
```
Succeeded: 1/5 (20%) — only GET /api/blog/posts (list) and occasional lucky POSTs
```

**With dependency graph working:**
```
Succeeded: 4/5 (80%) — POST creates postId → GET/PUT/DELETE all succeed
```

This is the quantitative test for `corpus/dependency.go`.

---

## Stopping the server

The setup script starts the server in the background:
```bash
make stop
# or:
kill $(cat /tmp/restler-demo.pid)
```
