#!/usr/bin/env bash
# Scenario 4 — Security payload injection
#
# Uses external wordlist files to inject SQL injection, XSS, SSTI, and LFI
# payloads into string-valued fields (query params, headers, cookies,
# JSON body string leaves).
#
# The securityMutator picks one string field per mutation and replaces
# its value with a random payload from the loaded wordlists.
# BehavioralPatterns then checks if the server's response contains
# error messages or reflected content that indicates exploitation.
#
# Payload files used:
#   sqli.txt  — SQL injection (boolean, union, error, time-based, NoSQL)
#   xss.txt   — Cross-site scripting (reflected, DOM, filter bypass)
#   ssti.txt  — Server-side template injection (Jinja2, Twig, Handlebars)
#   lfi.txt   — Local file inclusion / path traversal
#
# Findings:
#   BehavioralPatterns (medium) — reflected XSS, SQL error text, stack trace
#
# Use this mode when:
#   - You have customised wordlists for the target technology
#   - Doing a targeted injection campaign
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/04_payloads"
mkdir -p "${OUT}"

# Combine all payload categories into one -payloads flag value.
PAYLOAD_FLAG="sqli=${PAYLOADS_SQLI},xss=${PAYLOADS_XSS},ssti=${PAYLOADS_SSTI},lfi=${PAYLOADS_LFI}"

echo "=== Scenario 4: Security payload injection ==="
echo "  Target:   ${JUICE_URL}"
echo "  User:     ${FUZZER_USER}"
echo "  Payloads: sqli, xss, ssti, lfi"
echo "  Duration: ${DURATION_STANDARD}"
echo "  Output:   ${OUT}/"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec     %s \\\\\n" "${SPEC_FILE}"
printf "    -url      %s \\\\\n" "${JUICE_URL}"
printf "    -user     %s \\\\\n" "${FUZZER_USER}"
printf "    -password %s \\\\\n" "${FUZZER_PASS}"
printf "    -payloads %s \\\\\n" "${PAYLOAD_FLAG}"
printf "    -duration %s \\\\\n" "${DURATION_STANDARD}"
printf "    -output   %s \\\\\n" "${OUT}"
printf "    -rps      %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -payloads "${PAYLOAD_FLAG}" \
    -duration "${DURATION_STANDARD}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "Findings written to ${OUT}/findings/"
COUNT=$(ls "${OUT}/findings/"*.json 2>/dev/null | wc -l)
echo "Total findings: ${COUNT}"
