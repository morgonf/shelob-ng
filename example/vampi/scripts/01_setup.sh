#!/usr/bin/env bash
# 01_setup.sh — build fuzzer, start VAmPI, seed database, fetch spec.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
step() { echo -e "\n${BLUE}>>>${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

# 1. Build fuzzer
step "Building shelob-ng..."
(cd ../.. && go build -o shelob-ng . && ok "shelob-ng built")

# 2. Start VAmPI
step "Starting VAmPI..."
if curl -s --connect-timeout 2 "${VAMPI_URL}/" &>/dev/null; then
    ok "VAmPI already running at ${VAMPI_URL}"
else
    docker compose up -d
    echo -n "Waiting for VAmPI"
    for i in $(seq 1 30); do
        if curl -s --connect-timeout 2 "${VAMPI_URL}/" &>/dev/null; then
            echo ""; ok "VAmPI ready at ${VAMPI_URL}"; break
        fi
        echo -n "."; sleep 2
        [ "$i" -eq 30 ] && { echo ""; echo "ERROR: VAmPI did not start"; docker compose logs; exit 1; }
    done
fi

# 3. Seed the database (REQUIRED before any fuzzing)
step "Seeding database via GET /createdb ..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "${VAMPI_URL}/createdb")
if [ "$HTTP" = "200" ]; then
    ok "Database seeded (HTTP 200)"
else
    echo "WARN: /createdb returned HTTP $HTTP (may already be seeded)"
fi

# 4. Verify default users exist by attempting login
# VAmPI seeds: name1/pass1, name2/pass2, admin/pass1
step "Verifying name1 / pass1 login..."
TOKEN=$(curl -s -X POST "${VAMPI_URL}/users/v1/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"name1","password":"pass1"}' \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('auth_token',''))" 2>/dev/null || true)
if [ -n "$TOKEN" ]; then
    ok "Login OK — token received"
else
    echo "WARN: login failed; token empty. VAmPI may not have seeded correctly."
fi

# 5. Fetch the OpenAPI spec
step "Fetching OpenAPI spec from ${VAMPI_URL}/openapi3 ..."
curl -s "${VAMPI_URL}/openapi3" -o "${SPEC_FILE}"
PATHS=$(python3 -c "import json; d=json.load(open('${SPEC_FILE}')); print(len(d.get('paths',{})))" 2>/dev/null || echo "?")
ok "Spec saved: ${SPEC_FILE} (${PATHS} paths)"

# 6. Create output dirs
mkdir -p "${CORPUS_DIR}" "${RESULTS_BASE}"

echo ""
echo -e "${GREEN}=== Setup complete ===${NC}"
echo "  VAmPI:      ${VAMPI_URL}"
echo "  Spec:       ${SPEC_FILE}"
echo "  User1:      ${FUZZER_USER} / ${FUZZER_PASS}"
echo "  User2:      ${VICTIM_USER} / ${VICTIM_PASS}"
echo "  Token TTL:  3600s (extended in docker-compose.yml)"
echo ""
echo "  make run-1   # basic scan"
echo "  make run-2   # BOLA detection"
echo "  make run-3   # payload injection"
