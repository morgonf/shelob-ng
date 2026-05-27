#!/usr/bin/env bash
# Scenario 2 — Authenticated mode
#
# Logs in as the primary user before fuzzing. Session cookies are attached
# to every request. This unlocks endpoints that require authentication:
#   /api/BasketItems, /api/Orders, /rest/user/whoami, etc.
#
# Finds everything scenario 1 finds, PLUS:
#   - Bugs in authenticated-only endpoints
#   - Authorization errors visible only after login
#   - Schema violations on endpoints that 401 without auth
#
# Use this mode when:
#   - You have valid credentials
#   - The target has authenticated endpoints worth fuzzing
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/02_authenticated"
mkdir -p "${OUT}"

echo "=== Scenario 2: Authenticated mode ==="
echo "  Target:   ${JUICE_URL}"
echo "  User:     ${FUZZER_USER}"
echo "  Duration: ${DURATION_QUICK}"
echo "  Output:   ${OUT}/"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec     %s \\\\\n" "${SPEC_FILE}"
printf "    -url      %s \\\\\n" "${JUICE_URL}"
printf "    -user     %s \\\\\n" "${FUZZER_USER}"
printf "    -password %s \\\\\n" "${FUZZER_PASS}"
printf "    -duration %s \\\\\n" "${DURATION_QUICK}"
printf "    -output   %s \\\\\n" "${OUT}"
printf "    -rps      %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "Findings written to ${OUT}/findings/"
ls -lh "${OUT}/findings/" 2>/dev/null || echo "(no findings)"
