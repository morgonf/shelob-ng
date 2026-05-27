#!/usr/bin/env bash
# Scenario 3 — BOLA / IDOR detection (NameSpaceRule)
#
# Two users are required. For each successful (2xx) request made as User1,
# the NameSpaceRule checker replays the exact same request with User2's
# session cookies. A 2xx response from User2 means User2 can access
# User1's resource — this is Broken Object Level Authorization (BOLA/IDOR).
#
# OWASP API Security Top 10 — A01:2023 Broken Object Level Authorization.
#
# How it works:
#   1. Fuzzer sends: GET /api/BasketItems/42 as user1 → 200 OK
#   2. NameSpaceRule replays: GET /api/BasketItems/42 as user2 → ?
#      If 200: user2 can read user1's basket item → FINDING HIGH
#      If 403/404: correct access control
#
# Findings:
#   NameSpaceRule (high severity)  — BOLA/IDOR
#   UseAfterFree  (high severity)  — deleted resource still accessible
#
# Use this mode when:
#   - You have two distinct user accounts
#   - Testing for horizontal privilege escalation
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/03_bola"
mkdir -p "${OUT}"

echo "=== Scenario 3: BOLA / NameSpaceRule ==="
echo "  Target:  ${JUICE_URL}"
echo "  User1:   ${FUZZER_USER}"
echo "  User2:   ${VICTIM_USER}  (victim — replayed for BOLA)"
echo "  Duration: ${DURATION_QUICK}"
echo "  Output:   ${OUT}/"
echo ""

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -user2    "${VICTIM_USER}" \
    -pass2    "${VICTIM_PASS}" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "Findings written to ${OUT}/findings/"
# Show only high-severity (BOLA) findings
if ls "${OUT}/findings/"*.json &>/dev/null; then
    echo ""
    echo "High-severity findings:"
    for f in "${OUT}/findings/"*.json; do
        if grep -q '"high"' "$f" 2>/dev/null; then
            echo "  $f"
            if command -v jq &>/dev/null; then
                jq -r '"\(.checker): \(.title)\n  \(.url)"' "$f" | sed 's/^/  /'
            fi
        fi
    done
fi
