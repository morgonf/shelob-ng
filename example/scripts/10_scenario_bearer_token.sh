#!/usr/bin/env bash
# Scenario 9 — Bearer token authentication
#
# Demonstrates the -token flag: a pre-obtained JWT is passed directly
# to shelob-ng instead of using -user/-password cookie login.
#
# Background:
#   Juice Shop's POST /rest/user/login returns a JWT in the response body.
#   The old shelob-ng extracted it into a synthetic cookie; -token bypasses
#   the login step entirely and sets "Authorization: Bearer <token>" on every
#   request — including all checker probe requests.
#
# What this shows vs scenario 2 (cookie-based auth):
#   - Same set of endpoints reached (both methods authenticate successfully)
#   - -token is preferred when the target does not set cookies at all,
#     uses stateless JWT-only auth, or requires a long-lived service token
#   - All checkers (UseAfterFree, LeakageRule, etc.) also carry the token
#     on their probe requests — previously dead, now verified here
#
# Expected output:
#   - Authenticated endpoints (2xx) reached: similar count to scenario 2
#   - INITING message shows no cookie auth attempt
#   - Findings comparable to scenario 2
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/09_bearer_token"
mkdir -p "${OUT}"

echo "=== Scenario 9: Bearer token authentication ==="
echo "  Target:   ${JUICE_URL}"
echo "  Method:   -token (JWT, no cookie login)"
echo "  Duration: ${DURATION_QUICK}"
echo "  Output:   ${OUT}/"
echo ""

# Step 1: obtain a JWT from Juice Shop login endpoint.
# The token lives in response body field: .authentication.token
echo "Step 1: Obtaining JWT from ${JUICE_URL}/rest/user/login ..."
LOGIN_RESP=$(curl -s -X POST "${JUICE_URL}/rest/user/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"${FUZZER_USER}\",\"password\":\"${FUZZER_PASS}\"}")

JWT=$(echo "${LOGIN_RESP}" | python3 -c "
import json, sys
body = json.load(sys.stdin)
token = (body.get('authentication') or {}).get('token') \
     or body.get('token') \
     or body.get('access_token') \
     or ''
print(token)
" 2>/dev/null || true)

if [ -z "${JWT}" ]; then
    echo "ERROR: could not extract JWT from login response."
    echo "Response was: ${LOGIN_RESP}"
    echo ""
    echo "Skipping scenario 9 — Juice Shop may not be running or credentials may be wrong."
    echo "Run 'make setup' first."
    exit 1
fi

# Show only the header+payload part (safe to log; omit signature bytes)
JWT_PREVIEW="${JWT:0:40}…"
echo "  JWT obtained: ${JWT_PREVIEW}"
echo ""

# Step 2: verify the token works on an authenticated endpoint.
echo "Step 2: Smoke-checking Authorization: Bearer on /rest/user/whoami ..."
WHOAMI_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${JWT}" \
    "${JUICE_URL}/rest/user/whoami")
echo "  GET /rest/user/whoami → HTTP ${WHOAMI_STATUS}"
if [ "${WHOAMI_STATUS}" != "200" ]; then
    echo "WARNING: expected 200, got ${WHOAMI_STATUS}. Token may have expired."
fi
echo ""

# Step 3: run the fuzzer with -token (no -user / -password).
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec     %s \\\\\n" "${SPEC_FILE}"
printf "    -url      %s \\\\\n" "${JUICE_URL}"
printf "    -token    %s \\\\\n" "${JWT_PREVIEW}"
printf "    -duration %s \\\\\n" "${DURATION_QUICK}"
printf "    -output   %s \\\\\n" "${OUT}"
printf "    -rps      %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -token    "${JWT}" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "=== Scenario 9 complete ==="
FINDINGS=$(ls "${OUT}/findings/"*.json 2>/dev/null | wc -l)
echo "  Findings: ${FINDINGS}"
echo ""

# Show API coverage: succeeded (2xx) endpoints reveal auth effectiveness.
if [ -f "${OUT}/api-coverage.json" ]; then
    python3 - "${OUT}/api-coverage.json" << 'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
total = d['total']
vis   = d['visited_count']
succ  = d['succeeded_count']
print(f"  API coverage: {vis}/{total} reached, {succ}/{total} succeeded (2xx)")
if succ < 5:
    print("  WARNING: few 2xx responses — token may not be authorising correctly")
PYEOF
fi
