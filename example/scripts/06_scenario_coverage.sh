#!/usr/bin/env bash
# Scenario 5 — Coverage-guided mode (CSP)
#
# Uses the Coverage Sidecar Protocol to receive per-request code coverage
# from the instrumented Juice Shop instance. Inputs that exercise new code
# paths are saved to the corpus with a weight proportional to the coverage
# delta; they are then preferentially selected for future mutations.
#
# This mode requires the CSP-instrumented Juice Shop image. See:
#   docker compose -f docker-compose.yml -f docker-compose.csp.yml build
#   docker compose -f docker-compose.yml -f docker-compose.csp.yml up -d
#
# How the coverage loop works:
#   1. POST /csp/reset  → baseline current coverage
#   2. Send fuzzed request to Juice Shop
#   3. GET  /csp/dump   → response includes new_since_reset[]
#   4. If len(new_since_reset) > 0 → save entry to corpus (weight = delta)
#
# Expected behaviour vs pure-random:
#   - Corpus grows more slowly (only inputs with new coverage are saved)
#   - Over time corpus contains more "interesting" inputs (deep code paths)
#   - Display shows cov: column incrementing as new paths are discovered
#
# Findings:
#   Same as scenario 2, but deeper coverage means rarer bugs surface earlier.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/05_coverage"
mkdir -p "${OUT}"

# Check CSP sidecar is reachable.
if ! curl -s --connect-timeout 3 -X POST "${CSP_URL}/csp/reset" &>/dev/null; then
    echo "ERROR: CSP sidecar not responding at ${CSP_URL}"
    echo ""
    echo "Start the instrumented Juice Shop:"
    echo "  docker compose -f docker-compose.yml -f docker-compose.csp.yml build"
    echo "  docker compose -f docker-compose.yml -f docker-compose.csp.yml up -d"
    exit 1
fi
echo "CSP sidecar: OK (${CSP_URL})"

echo ""
echo "=== Scenario 5: Coverage-guided fuzzing ==="
echo "  Target:   ${JUICE_URL}"
echo "  CSP:      ${CSP_URL}"
echo "  User:     ${FUZZER_USER}"
echo "  Duration: ${DURATION_STANDARD}"
echo "  Output:   ${OUT}/"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec       %s \\\\\n" "${SPEC_FILE}"
printf "    -url        %s \\\\\n" "${JUICE_URL}"
printf "    -user       %s \\\\\n" "${FUZZER_USER}"
printf "    -password   %s \\\\\n" "${FUZZER_PASS}"
printf "    -csp-url    %s \\\\\n" "${CSP_URL}"
printf "    -corpus-dir %s \\\\\n" "${CORPUS_DIR}/csp"
printf "    -duration   %s \\\\\n" "${DURATION_STANDARD}"
printf "    -output     %s \\\\\n" "${OUT}"
printf "    -rps        %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -csp-url  "${CSP_URL}" \
    -corpus-dir "${CORPUS_DIR}/csp" \
    -duration "${DURATION_STANDARD}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "Corpus saved to ${CORPUS_DIR}/csp/"
echo "Findings written to ${OUT}/findings/"
