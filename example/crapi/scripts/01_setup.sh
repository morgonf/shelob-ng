#!/usr/bin/env bash
# 01_setup.sh — verify crAPI is running, create accounts, get spec.
#
# crAPI setup is external to this script (upstream docker-compose).
# See README.md for the full setup procedure.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
step() { echo -e "\n${BLUE}>>>${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}WARN${NC} $*"; }

# 1. Build fuzzer
step "Building shelob-ng..."
(cd ../.. && go build -o shelob-ng . && ok "shelob-ng built")

# 2. Check crAPI is running
step "Checking crAPI at ${CRAPI_URL} ..."
if ! curl -s --connect-timeout 5 "${CRAPI_URL}/identity/api/health" &>/dev/null; then
    echo "ERROR: crAPI is not running at ${CRAPI_URL}"
    echo ""
    echo "Start crAPI first:"
    echo "  git clone https://github.com/OWASP/crAPI.git /opt/crapi"
    echo "  cd /opt/crapi/deploy/docker"
    echo "  docker compose -f docker-compose.minimal.yml up -d"
    echo "  # Wait ~60s for all services to start"
    exit 1
fi
ok "crAPI responding at ${CRAPI_URL}"

# 3. Check Mailhog is available (needed for email verification)
step "Checking Mailhog at ${MAILHOG_URL} ..."
if curl -s --connect-timeout 3 "${MAILHOG_URL}/" &>/dev/null; then
    ok "Mailhog available — open ${MAILHOG_URL} to read verification emails"
else
    warn "Mailhog not available at ${MAILHOG_URL} — email verification will need to be done manually"
fi

# 4. Register primary user
step "Registering primary user: ${FUZZER_USER} ..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${CRAPI_URL}/identity/api/auth/signup" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"Fuzzer\",\"email\":\"${FUZZER_USER}\",\"number\":\"9876543210\",\"password\":\"${FUZZER_PASS}\"}")
case "$HTTP" in
    200|201) ok "Registration request sent for ${FUZZER_USER} (HTTP $HTTP). Check Mailhog to confirm email." ;;
    409)     ok "User ${FUZZER_USER} already exists (HTTP 409)" ;;
    *)       warn "Unexpected HTTP $HTTP for ${FUZZER_USER}" ;;
esac

# 5. Register victim user
step "Registering victim user: ${VICTIM_USER} ..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${CRAPI_URL}/identity/api/auth/signup" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"Victim\",\"email\":\"${VICTIM_USER}\",\"number\":\"1234567890\",\"password\":\"${VICTIM_PASS}\"}")
case "$HTTP" in
    200|201) ok "Registration request sent for ${VICTIM_USER} (HTTP $HTTP). Check Mailhog to confirm email." ;;
    409)     ok "User ${VICTIM_USER} already exists (HTTP 409)" ;;
    *)       warn "Unexpected HTTP $HTTP for ${VICTIM_USER}" ;;
esac

# 6. Check spec file
step "Checking OpenAPI spec: ${SPEC_FILE} ..."
if [ -f "${SPEC_FILE}" ]; then
    PATHS=$(python3 -c "import json; d=json.load(open('${SPEC_FILE}')); print(len(d.get('paths',{})))" 2>/dev/null || echo "?")
    ok "Spec found: ${SPEC_FILE} (${PATHS} paths)"
else
    warn "Spec not found at ${SPEC_FILE}"
    echo "  Download with:"
    echo "    curl -s ${CRAPI_URL}/identity/api/schema -o ${SPEC_FILE}"
    echo "  Or use the spec from the upstream repo:"
    echo "    SPEC_FILE=/opt/crapi/openapi-spec/crapi-openapi-spec.json"
fi

mkdir -p "${CORPUS_DIR}" "${RESULTS_BASE}"

echo ""
echo -e "${GREEN}=== Setup complete ===${NC}"
echo "  crAPI:   ${CRAPI_URL}"
echo "  Mailhog: ${MAILHOG_URL}"
echo "  Spec:    ${SPEC_FILE}"
echo ""
echo "  IMPORTANT: Confirm email for both accounts in Mailhog before fuzzing!"
