#!/usr/bin/env bash
# Scenario 1 — Basic authenticated scan (crAPI identity service)
#
# Fuzzes the identity service endpoints with JWT Bearer auth.
# crAPI covers all OWASP API Security Top 10 (2023) plus LLM injection.
#
# Expected HIGH findings:
#   BOLA: GET /identity/api/v2/vehicle/{vehicleId}/location — own vehicle only
#   BehavioralPatterns: SQL/NoSQL artifacts
#   SchemaViolation: community/workshop service responses
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/01_basic"
mkdir -p "${OUT}"

echo "=== Scenario 1: Basic authenticated scan (crAPI identity) ==="
echo "  Target:   ${CRAPI_URL}"
echo "  User:     ${FUZZER_USER}"
echo "  Duration: ${DURATION_QUICK}"
echo ""

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${CRAPI_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "Findings: ${OUT}/findings/"
ls -lh "${OUT}/findings/" 2>/dev/null || echo "(none)"
