#!/usr/bin/env bash
# Scenario 2 — Injection payloads (DVWS-Node)
#
# DVWS-Node is vulnerable to SQLi, NoSQL injection, command injection,
# XPATH injection, and LDAP injection. Driving payload wordlists maximises
# the chance of triggering error output that BehavioralPatterns can detect.
#
# Note: XML injection is best tested manually; shelob-ng generates JSON bodies.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/02_injection"
mkdir -p "${OUT}"

PAYLOAD_ARGS=""
[ -f "${PAYLOADS_SQLI}" ]  && PAYLOAD_ARGS="${PAYLOAD_ARGS} sqli=${PAYLOADS_SQLI}"
[ -f "${PAYLOADS_XSS}" ]   && PAYLOAD_ARGS="${PAYLOAD_ARGS} xss=${PAYLOADS_XSS}"
[ -f "${PAYLOADS_NOSQL}" ] && PAYLOAD_ARGS="${PAYLOAD_ARGS} nosql=${PAYLOADS_NOSQL}"
[ -f "${PAYLOADS_CMDI}" ]  && PAYLOAD_ARGS="${PAYLOAD_ARGS} cmdi=${PAYLOADS_CMDI}"
PAYLOAD_ARGS=$(echo "${PAYLOAD_ARGS}" | xargs | tr ' ' ',')

echo "=== Scenario 2: Injection payloads (DVWS-Node) ==="
echo "  Target:   ${DVWS_URL}"
echo "  Payloads: ${PAYLOAD_ARGS}"
echo "  Duration: ${DURATION_STANDARD}"
echo ""

CMD=("${FUZZER}"
    -spec     "${SPEC_FILE}"
    -url      "${DVWS_URL}"
    -duration "${DURATION_STANDARD}"
    -output   "${OUT}"
    -rps      "${RPS}")

[ -n "${PAYLOAD_ARGS}" ] && CMD+=(-payloads "${PAYLOAD_ARGS}")

"${CMD[@]}"

echo ""
echo "Findings: ${OUT}/findings/"
ls -lh "${OUT}/findings/" 2>/dev/null || echo "(none)"
