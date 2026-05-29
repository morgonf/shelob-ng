#!/usr/bin/env bash
# 01_setup.sh — one-time setup: build fuzzer, pull image, wait for readiness,
#               create two test accounts, download OpenAPI spec.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
step() { echo -e "\n${BLUE}>>>${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

# -----------------------------------------------------------------------
# 1. Build fuzzer
# -----------------------------------------------------------------------
step "Building shelob-ng..."
(cd ../.. && go build -o shelob-ng . && ok "shelob-ng built: $(pwd)/shelob-ng")
export FUZZER=../../shelob-ng

# -----------------------------------------------------------------------
# 2. Pull Docker image (skip if already present)
# -----------------------------------------------------------------------
step "Pulling Juice Shop Docker image..."
if docker image inspect bkimminich/juice-shop:latest &>/dev/null; then
    ok "Image bkimminich/juice-shop:latest already present"
else
    docker pull bkimminich/juice-shop:latest
    ok "Image pulled"
fi

# -----------------------------------------------------------------------
# 3. Start Juice Shop (if not already running)
# -----------------------------------------------------------------------
step "Starting Juice Shop..."
if curl -s --connect-timeout 2 "${JUICE_URL}/rest/admin/application-configuration" &>/dev/null; then
    ok "Juice Shop already running at ${JUICE_URL}"
else
    docker compose up -d
    echo -n "Waiting for Juice Shop to become ready"
    for i in $(seq 1 60); do
        if curl -s --connect-timeout 2 "${JUICE_URL}/rest/admin/application-configuration" &>/dev/null; then
            echo ""
            ok "Juice Shop ready at ${JUICE_URL}"
            break
        fi
        echo -n "."
        sleep 3
        if [ "$i" -eq 60 ]; then
            echo ""
            echo "ERROR: Juice Shop did not start within 3 minutes."
            docker compose logs --tail=30
            exit 1
        fi
    done
fi

# -----------------------------------------------------------------------
# 4. Create primary user (fuzzer)
# -----------------------------------------------------------------------
step "Creating primary user: ${FUZZER_USER}..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${JUICE_URL}/api/Users" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"${FUZZER_USER}\",
        \"password\": \"${FUZZER_PASS}\",
        \"passwordRepeat\": \"${FUZZER_PASS}\",
        \"securityQuestion\": {\"id\": 1, \"question\": \"Your eldest siblings middle name?\"},
        \"securityAnswer\": \"shelob\"
    }")

if [ "$STATUS" = "201" ] || [ "$STATUS" = "200" ]; then
    ok "User ${FUZZER_USER} created (HTTP $STATUS)"
elif [ "$STATUS" = "422" ]; then
    ok "User ${FUZZER_USER} already exists (HTTP 422)"
else
    echo "WARN: Unexpected status $STATUS when creating ${FUZZER_USER}"
fi

# -----------------------------------------------------------------------
# 5. Create victim user (BOLA testing)
# -----------------------------------------------------------------------
step "Creating victim user: ${VICTIM_USER}..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${JUICE_URL}/api/Users" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"${VICTIM_USER}\",
        \"password\": \"${VICTIM_PASS}\",
        \"passwordRepeat\": \"${VICTIM_PASS}\",
        \"securityQuestion\": {\"id\": 2, \"question\": \"Mother's maiden name?\"},
        \"securityAnswer\": \"shelob\"
    }")

if [ "$STATUS" = "201" ] || [ "$STATUS" = "200" ]; then
    ok "User ${VICTIM_USER} created (HTTP $STATUS)"
elif [ "$STATUS" = "422" ]; then
    ok "User ${VICTIM_USER} already exists (HTTP 422)"
else
    echo "WARN: Unexpected status $STATUS when creating ${VICTIM_USER}"
fi

# -----------------------------------------------------------------------
# 6. Validate OpenAPI spec (juice-shop exposes only a 1-path B2B spec via
#    /api-docs; the full REST API spec ships with the example directory)
# -----------------------------------------------------------------------
step "Checking OpenAPI spec: ${SPEC_FILE}..."
if [ -f "${SPEC_FILE}" ] && python3 -c "import json,sys; json.load(open('${SPEC_FILE}'))" 2>/dev/null; then
    PATHS=$(python3 -c "import json; spec=json.load(open('${SPEC_FILE}')); print(len(spec.get('paths',{})))")
    ok "Spec OK: ${SPEC_FILE} (${PATHS} paths)"
else
    echo "WARN: Spec file missing or invalid — expected at: ${SPEC_FILE}"
    echo "      The comprehensive Juice Shop spec ships with the example directory."
    echo "      Run: git checkout HEAD -- juice-shop.openapi.json"
fi

# -----------------------------------------------------------------------
# 7. Create output directories
# -----------------------------------------------------------------------
step "Creating output directories..."
mkdir -p "${CORPUS_DIR}" "${RESULTS_BASE}"
ok "Directories ready: ${CORPUS_DIR}/ and ${RESULTS_BASE}/"

# -----------------------------------------------------------------------
# 8. Optional: download PayloadsAllTheThings for richer wordlists
# -----------------------------------------------------------------------
PATT_DIR="/tmp/PayloadsAllTheThings"
if [ "${DOWNLOAD_PATT:-0}" = "1" ]; then
    step "Downloading PayloadsAllTheThings..."
    if [ -d "${PATT_DIR}" ]; then
        ok "Already cloned: ${PATT_DIR}"
    else
        git clone --depth=1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "${PATT_DIR}"
        ok "Cloned to ${PATT_DIR}"
    fi
    # Augment payload files with upstream lists
    cat "${PATT_DIR}/SQL Injection/Intruder/SQL_Bypass.txt" >> "${PAYLOADS_SQLI}" 2>/dev/null && \
        ok "sqli.txt augmented from PayloadsAllTheThings"
    cat "${PATT_DIR}/XSS Injection/Intruder/XSS Polyglots.txt" >> "${PAYLOADS_XSS}" 2>/dev/null && \
        ok "xss.txt augmented from PayloadsAllTheThings"
else
    echo "  (skipping PayloadsAllTheThings — run with DOWNLOAD_PATT=1 to enable)"
    echo "  git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /tmp/PayloadsAllTheThings"
fi

echo ""
echo -e "${GREEN}=== Setup complete ===${NC}"
echo "  Juice Shop:  ${JUICE_URL}"
echo "  Spec:        ${SPEC_FILE}"
echo "  Fuzzer user: ${FUZZER_USER} / ${FUZZER_PASS}"
echo "  Victim user: ${VICTIM_USER} / ${VICTIM_PASS}"
echo ""
echo "Run scenarios:"
echo "  make run-1   # pure random"
echo "  make run-all # all 8 scenarios"
