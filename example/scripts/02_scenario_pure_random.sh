#!/usr/bin/env bash
# Scenario 1 — Pure random mode
#
# The simplest mode of operation. No authentication, no coverage feedback.
# Fuzzer generates random inputs from the OpenAPI spec and runs all
# checkers that don't require a second user.
#
# Finds:
#   BehavioralPatterns  — SQL errors, stack traces in responses
#   InvalidDynamicObject — 500s on boundary values (-1, 0, null, "")
#   LeakageRule         — partial state after failed POSTs
#   SchemaViolation     — responses that don't match the spec
#
# Use this mode when:
#   - You have no credentials
#   - You want a quick initial scan
#   - The target has no source code (black-box)
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/01_pure_random"
mkdir -p "${OUT}"

echo "=== Scenario 1: Pure random mode ==="
echo "  Target:   ${JUICE_URL}"
echo "  Duration: ${DURATION_QUICK}"
echo "  Output:   ${OUT}/"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec     %s \\\\\n" "${SPEC_FILE}"
printf "    -url      %s \\\\\n" "${JUICE_URL}"
printf "    -duration %s \\\\\n" "${DURATION_QUICK}"
printf "    -output   %s \\\\\n" "${OUT}"
printf "    -rps      %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec "${SPEC_FILE}" \
    -url  "${JUICE_URL}" \
    -duration "${DURATION_QUICK}" \
    -output "${OUT}" \
    -rps "${RPS}"

echo ""
echo "Findings written to ${OUT}/findings/"
ls -lh "${OUT}/findings/" 2>/dev/null || echo "(no findings directory)"
