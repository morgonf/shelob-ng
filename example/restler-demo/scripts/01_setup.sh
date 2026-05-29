#!/usr/bin/env bash
# 01_setup.sh — build fuzzer, install and start RESTler Demo server, fetch spec.
#
# The RESTler Demo server is a minimal FastAPI blog (4 endpoints).
# Purpose: test producer-consumer dependency graph.
#   POST /api/blog/posts → creates a post, returns postId
#   GET/PUT/DELETE /api/blog/posts/{postId} → consume postId
#
# Without the dependency graph, GET/DELETE return 404 (no postId to use).
# With the dependency graph, 50-70% of operations should return 2xx.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
step() { echo -e "\n${BLUE}>>>${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

DEMO_SRC="${DEMO_SRC:-/opt/restler-fuzzer}"

# 1. Build fuzzer
step "Building shelob-ng..."
(cd ../.. && go build -o shelob-ng . && ok "shelob-ng built")

# 2. Check Python 3
step "Checking Python 3..."
python3 --version || { echo "ERROR: Python 3 not found"; exit 1; }
ok "Python 3 available"

# 3. Clone or locate RESTler demo server
step "Locating RESTler demo server (${DEMO_SRC}) ..."
if [ ! -d "${DEMO_SRC}/demo_server" ]; then
    echo "RESTler repo not found at ${DEMO_SRC}. Cloning..."
    git clone --depth=1 https://github.com/microsoft/restler-fuzzer.git "${DEMO_SRC}"
fi
ok "Demo server found: ${DEMO_SRC}/demo_server"

# 4. Create/update virtualenv
step "Setting up Python virtualenv..."
VENV_DIR="$(pwd)/venv"
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install -q -r "${DEMO_SRC}/demo_server/requirements.txt"
ok "Dependencies installed"

# 5. Start the server in background (kill any stale instance first)
step "Starting RESTler demo server on port 8888..."
pkill -f "demo_server/app.py" 2>/dev/null || true
"${VENV_DIR}/bin/python" "${DEMO_SRC}/demo_server/demo_server/app.py" &
SERVER_PID=$!
echo "$SERVER_PID" > /tmp/restler-demo.pid

echo -n "Waiting for server"
for i in $(seq 1 15); do
    if curl -s --connect-timeout 1 "${DEMO_URL}/api/doc" &>/dev/null; then
        echo ""; ok "Server ready at ${DEMO_URL} (PID $SERVER_PID)"; break
    fi
    echo -n "."; sleep 1
    [ "$i" -eq 15 ] && { echo ""; echo "ERROR: server did not start"; exit 1; }
done

# 6. Fetch spec
step "Fetching OpenAPI spec from ${DEMO_URL}/openapi.json ..."
curl -s "${DEMO_URL}/openapi.json" -o "${SPEC_FILE}"
ok "Spec saved: ${SPEC_FILE}"

mkdir -p "${CORPUS_DIR}" "${RESULTS_BASE}"

echo ""
echo -e "${GREEN}=== Setup complete ===${NC}"
echo "  Demo server: ${DEMO_URL} (PID $(cat /tmp/restler-demo.pid 2>/dev/null || echo '?'))"
echo "  Swagger UI:  ${DEMO_URL}/docs"
echo "  Spec:        ${SPEC_FILE}"
echo ""
echo "  Stop server: kill \$(cat /tmp/restler-demo.pid)"
echo "  make run-1   # producer-consumer test"
