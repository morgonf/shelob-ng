#!/usr/bin/env bash
# Scenario 1 — Basic scan (DVWS-Node)
#
# DVWS-Node covers 39 vulnerability classes across REST, XML, and GraphQL.
# This scenario runs all checkers against the REST endpoints.
#
# Expected HIGH findings:
#   BehavioralPatterns — OS command injection artifacts (cmdi endpoints)
#   BehavioralPatterns — SQL errors in user/notes endpoints
#   SchemaViolation    — many endpoints return undeclared fields
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/01_basic"
mkdir -p "${OUT}"

echo "=== Scenario 1: Basic scan (DVWS-Node) ==="
echo "  Target:   ${DVWS_URL}"
echo "  Duration: ${DURATION_QUICK}"
echo ""

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${DVWS_URL}" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "Findings: ${OUT}/findings/"
ls -lh "${OUT}/findings/" 2>/dev/null || echo "(none)"
