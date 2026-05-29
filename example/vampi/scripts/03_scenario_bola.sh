#!/usr/bin/env bash
# Scenario 2 — BOLA/IDOR detection (NameSpaceRule)
#
# VAmPI is explicitly designed to be vulnerable to BOLA:
#   admin1 creates a book → user2 can read/update/delete it.
#
# Also exercises the dual docker-compose mode: run with vulnerable=1 and then
# swap to the secure image (vulnerable=0) as a baseline comparison.
#
# OWASP API Security A01:2023 — Broken Object Level Authorization.
#
# Expected HIGH findings:
#   NameSpaceRule: GET /books/v1/{book} — user2 reads admin1's book
#   NameSpaceRule: GET /users/v1/{username} — user2 reads admin1's profile
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/02_bola"
mkdir -p "${OUT}"

echo "=== Scenario 2: BOLA / NameSpaceRule ==="
echo "  Target:  ${VAMPI_URL}"
echo "  User1:   ${FUZZER_USER} (primary)"
echo "  User2:   ${VICTIM_USER} (BOLA probe)"
echo "  Duration: ${DURATION_QUICK}"
echo ""

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${VAMPI_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -user2    "${VICTIM_USER}" \
    -pass2    "${VICTIM_PASS}" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "High-severity findings:"
for f in "${OUT}/findings/"*.json; do
    [ -f "$f" ] || continue
    grep -q '"high"' "$f" && echo "  $f"
done
