#!/usr/bin/env bash
# 01_setup.sh — build fuzzer, start Petstore, fetch spec.
#
# Petstore is a clean reference implementation — no intentional vulnerabilities.
# Use it to verify fuzzer baseline behaviour: request generation, auth handling,
# spec coverage, and content-type negotiation.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
step() { echo -e "\n${BLUE}>>>${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

# 1. Build fuzzer
step "Building shelob-ng..."
(cd ../.. && go build -o shelob-ng . && ok "shelob-ng built")

# 2. Start Petstore
step "Starting Swagger Petstore 3..."
if curl -s --connect-timeout 3 "${PETSTORE_URL}/api/v3/openapi.json" &>/dev/null; then
    ok "Petstore already running at ${PETSTORE_URL}"
else
    docker compose up -d
    echo -n "Waiting for Petstore"
    for i in $(seq 1 30); do
        if curl -s --connect-timeout 2 "${PETSTORE_URL}/api/v3/openapi.json" &>/dev/null; then
            echo ""; ok "Petstore ready at ${PETSTORE_URL}"; break
        fi
        echo -n "."; sleep 2
        [ "$i" -eq 30 ] && { echo ""; echo "ERROR: Petstore did not start"; docker compose logs; exit 1; }
    done
fi

# 3. Fetch spec
step "Fetching OpenAPI spec from ${PETSTORE_URL}/api/v3/openapi.json ..."
curl -s "${PETSTORE_URL}/api/v3/openapi.json" -o "${SPEC_FILE}"
PATHS=$(python3 -c "import json; d=json.load(open('${SPEC_FILE}')); print(len(d.get('paths',{})))" 2>/dev/null || echo "?")
ok "Spec saved: ${SPEC_FILE} (${PATHS} paths)"

mkdir -p "${CORPUS_DIR}" "${RESULTS_BASE}"

echo ""
echo -e "${GREEN}=== Setup complete ===${NC}"
echo "  Petstore:    ${PETSTORE_URL}"
echo "  Swagger UI:  ${PETSTORE_URL}/"
echo "  Spec:        ${SPEC_FILE}"
echo "  API key:     ${API_KEY}"
echo ""
echo "  make run-1   # spec coverage baseline"
echo "  make run-2   # API key auth"
