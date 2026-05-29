#!/usr/bin/env bash
# Scenario 1 — Basic authenticated scan
#
# Logs in as name1 and fuzzes all endpoints with random data + all checkers.
#
# Key VAmPI features exercised:
#   - JWT Bearer auth (via -user/-password; auto-detected login endpoint)
#   - BehavioralPatterns — SQL errors in /books/v1/{book} (direct concatenation)
#   - InvalidDynamicObject — 500s on boundary IDs
#   - SchemaViolation — responses that don't match declared schema
#
# Expected HIGH findings:
#   SQL error leakage in book search (GET /books/v1/{book})
#   Stack trace in user registration (POST /users/v1/register — email validation)
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/01_basic"
mkdir -p "${OUT}"

echo "=== Scenario 1: Basic authenticated scan ==="
echo "  Target:   ${VAMPI_URL}"
echo "  User:     ${FUZZER_USER}"
echo "  Duration: ${DURATION_QUICK}"
echo ""

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${VAMPI_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "Findings: ${OUT}/findings/"
ls -lh "${OUT}/findings/" 2>/dev/null || echo "(none)"
