#!/usr/bin/env bash
# Scenario 8 — Full mode (everything enabled)
#
# All features active simultaneously:
#   - Authenticated (primary user session cookies on every request)
#   - BOLA detection (second user for NameSpaceRule replay)
#   - Security payloads (SQLi, XSS, SSTI, LFI wordlists)
#   - Corpus persistence (corpus saved and used across runs)
#   - All 6 checkers enabled
#   - Stateful CRUD sequences (runs every 20 requests)
#
# This is the recommended production configuration for a full audit.
# Run for at least 1 hour for meaningful coverage.
#
# What to expect:
#   - corpus: grows as interesting inputs are saved
#   - NEW events when new parameters/endpoints are exercised
#   - FINDING lines for each discovered vulnerability
#   - Replay files in results/08_full/replays/ for sequence findings
#
# Typical Juice Shop findings in 1 hour:
#   BehavioralPatterns   — SQL error text in /rest/search?q= responses
#   BehavioralPatterns   — Error object leak in /api/Users/0 etc.
#   InvalidDynamicObject — 500 on boundary IDs
#   NameSpaceRule        — Access to other users' basket items
#   SchemaViolation      — Various spec mismatches
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/08_full"
CORP="${CORPUS_DIR}/full"
mkdir -p "${OUT}" "${CORP}"

PAYLOAD_FLAG="sqli=${PAYLOADS_SQLI},xss=${PAYLOADS_XSS},ssti=${PAYLOADS_SSTI},lfi=${PAYLOADS_LFI}"

echo "=== Scenario 8: Full mode ==="
echo "  Target:   ${JUICE_URL}"
echo "  User1:    ${FUZZER_USER}"
echo "  User2:    ${VICTIM_USER}"
echo "  Payloads: sqli, xss, ssti, lfi"
echo "  Checkers: all"
echo "  Corpus:   ${CORP}/"
echo "  Duration: ${DURATION_FULL}"
echo "  Output:   ${OUT}/"
echo ""
echo "Press Ctrl+C to stop early. Corpus and findings are saved continuously."
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec       %s \\\\\n" "${SPEC_FILE}"
printf "    -url        %s \\\\\n" "${JUICE_URL}"
printf "    -user       %s \\\\\n" "${FUZZER_USER}"
printf "    -password   %s \\\\\n" "${FUZZER_PASS}"
printf "    -user2      %s \\\\\n" "${VICTIM_USER}"
printf "    -pass2      %s \\\\\n" "${VICTIM_PASS}"
printf "    -payloads   %s \\\\\n" "${PAYLOAD_FLAG}"
printf "    -corpus-dir %s \\\\\n" "${CORP}"
printf "    -duration   %s \\\\\n" "${DURATION_FULL}"
printf "    -output     %s \\\\\n" "${OUT}"
printf "    -rps        %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec       "${SPEC_FILE}" \
    -url        "${JUICE_URL}" \
    -user       "${FUZZER_USER}" \
    -password   "${FUZZER_PASS}" \
    -user2      "${VICTIM_USER}" \
    -pass2      "${VICTIM_PASS}" \
    -payloads   "${PAYLOAD_FLAG}" \
    -corpus-dir "${CORP}" \
    -duration   "${DURATION_FULL}" \
    -output     "${OUT}" \
    -rps        "${RPS}"

echo ""
echo "=== Scenario 8 complete ==="
TOTAL=$(ls "${OUT}/findings/"*.json 2>/dev/null | wc -l)
REPLAYS=$(ls "${OUT}/replays/"*.json 2>/dev/null | wc -l)
echo "  Findings: ${TOTAL}"
echo "  Replays:  ${REPLAYS}"
echo ""
echo "Run 'make report' for a full summary."
