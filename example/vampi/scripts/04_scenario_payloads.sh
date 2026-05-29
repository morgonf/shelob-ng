#!/usr/bin/env bash
# Scenario 3 — Security payload injection
#
# VAmPI has confirmed SQLi in /books/v1/{book} and NoSQL quirks.
# This scenario drives payload injection against all string fields.
#
# Expected HIGH findings:
#   SQL error string in GET /books/v1/{book} response body
#   Possible user enumeration via different error messages
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/03_payloads"
mkdir -p "${OUT}"

# Fall back gracefully if payload files are missing
PAYLOAD_ARGS=""
[ -f "${PAYLOADS_SQLI}" ] && PAYLOAD_ARGS="${PAYLOAD_ARGS} sqli=${PAYLOADS_SQLI}"
[ -f "${PAYLOADS_XSS}" ]  && PAYLOAD_ARGS="${PAYLOAD_ARGS} xss=${PAYLOADS_XSS}"
[ -f "${PAYLOADS_NOSQL}" ] && PAYLOAD_ARGS="${PAYLOAD_ARGS} nosql=${PAYLOADS_NOSQL}"
PAYLOAD_ARGS=$(echo "${PAYLOAD_ARGS}" | xargs | tr ' ' ',')

echo "=== Scenario 3: Payload injection ==="
echo "  Target:   ${VAMPI_URL}"
echo "  Payloads: ${PAYLOAD_ARGS}"
echo "  Duration: ${DURATION_STANDARD}"
echo ""

CMD=("${FUZZER}"
    -spec     "${SPEC_FILE}"
    -url      "${VAMPI_URL}"
    -user     "${FUZZER_USER}"
    -password "${FUZZER_PASS}"
    -duration "${DURATION_STANDARD}"
    -output   "${OUT}"
    -rps      "${RPS}")

[ -n "${PAYLOAD_ARGS}" ] && CMD+=(-payloads "${PAYLOAD_ARGS}")

"${CMD[@]}"

echo ""
echo "Findings: ${OUT}/findings/"
ls -lh "${OUT}/findings/" 2>/dev/null || echo "(none)"
