#!/usr/bin/env bash
# Scenario 2 — BOLA/IDOR detection (crAPI)
#
# crAPI is the flagship OWASP BOLA example. Key vulnerable endpoints:
#   GET /workshop/api/mechanic/mechanic_report?report_id=X
#   GET /identity/api/v2/vehicle/{vehicleId}/location
#   GET /community/api/v2/community/posts/{postId}
#
# The NameSpaceRule checker replays user1's requests with user2's session.
# Cross-account 2xx response = BOLA HIGH.
#
# IMPORTANT: Both users must have confirmed emails and added vehicles.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/02_bola"
mkdir -p "${OUT}"

echo "=== Scenario 2: BOLA / NameSpaceRule (crAPI) ==="
echo "  Target:  ${CRAPI_URL}"
echo "  User1:   ${FUZZER_USER}"
echo "  User2:   ${VICTIM_USER}"
echo "  Duration: ${DURATION_STANDARD}"
echo ""

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${CRAPI_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -user2    "${VICTIM_USER}" \
    -pass2    "${VICTIM_PASS}" \
    -duration "${DURATION_STANDARD}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "High-severity findings:"
for f in "${OUT}/findings/"*.json; do
    [ -f "$f" ] || continue
    grep -q '"high"' "$f" && echo "  $f"
done
