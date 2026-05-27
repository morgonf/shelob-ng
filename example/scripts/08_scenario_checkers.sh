#!/usr/bin/env bash
# Scenario 7 — Selective checker mode
#
# Runs only specific checkers instead of the full suite.
# Useful when:
#   - You want targeted results (e.g. only schema violations)
#   - The full checker suite is too slow for your RPS budget
#   - You're iterating on one bug class at a time
#
# Available checker names:
#   BehavioralPatterns    — SQL errors, XSS, stack traces in responses
#   UseAfterFree          — resource accessible after DELETE
#   InvalidDynamicObject  — 500 on boundary inputs (-1, 0, null, "")
#   LeakageRule           — partial state after failed POST
#   NameSpaceRule         — BOLA (requires -user2)
#   SchemaViolation       — response does not match OpenAPI schema
#
# This script runs three targeted sub-scenarios in sequence,
# each with a dedicated output directory:
#   7a: Schema violations only (no extra HTTP probes, fast)
#   7b: Behavioral patterns only (looks for injection signatures)
#   7c: UseAfterFree + InvalidDynamicObject (stateful checks)
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

# -----------------------------------------------------------------------
# 7a: Schema violations only — fastest, zero extra requests
# -----------------------------------------------------------------------
OUT="${RESULTS_BASE}/07a_schema"
mkdir -p "${OUT}"

echo "=== Scenario 7a: SchemaViolation only ==="
echo "  Checker:  SchemaViolation"
echo "  Duration: ${DURATION_QUICK}"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec     %s \\\\\n" "${SPEC_FILE}"
printf "    -url      %s \\\\\n" "${JUICE_URL}"
printf "    -user     %s \\\\\n" "${FUZZER_USER}"
printf "    -password %s \\\\\n" "${FUZZER_PASS}"
printf "    -checker  SchemaViolation \\\\\n"
printf "    -duration %s \\\\\n" "${DURATION_QUICK}"
printf "    -output   %s \\\\\n" "${OUT}"
printf "    -rps      %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -checker  "SchemaViolation" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

# -----------------------------------------------------------------------
# 7b: Behavioral patterns — looks for injection artifact signatures
# -----------------------------------------------------------------------
OUT="${RESULTS_BASE}/07b_behavioral"
mkdir -p "${OUT}"
PAYLOAD_FLAG="sqli=${PAYLOADS_SQLI},xss=${PAYLOADS_XSS}"

echo ""
echo "=== Scenario 7b: BehavioralPatterns only + payloads ==="
echo "  Checker:  BehavioralPatterns"
echo "  Duration: ${DURATION_QUICK}"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec     %s \\\\\n" "${SPEC_FILE}"
printf "    -url      %s \\\\\n" "${JUICE_URL}"
printf "    -user     %s \\\\\n" "${FUZZER_USER}"
printf "    -password %s \\\\\n" "${FUZZER_PASS}"
printf "    -checker  BehavioralPatterns \\\\\n"
printf "    -payloads %s \\\\\n" "${PAYLOAD_FLAG}"
printf "    -duration %s \\\\\n" "${DURATION_QUICK}"
printf "    -output   %s \\\\\n" "${OUT}"
printf "    -rps      %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -checker  "BehavioralPatterns" \
    -payloads "${PAYLOAD_FLAG}" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

# -----------------------------------------------------------------------
# 7c: Stateful checkers (UseAfterFree + InvalidDynamicObject)
# -----------------------------------------------------------------------
OUT="${RESULTS_BASE}/07c_stateful"
mkdir -p "${OUT}"

echo ""
echo "=== Scenario 7c: UseAfterFree + InvalidDynamicObject ==="
echo "  Checkers: UseAfterFree,InvalidDynamicObject"
echo "  Duration: ${DURATION_QUICK}"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec     %s \\\\\n" "${SPEC_FILE}"
printf "    -url      %s \\\\\n" "${JUICE_URL}"
printf "    -user     %s \\\\\n" "${FUZZER_USER}"
printf "    -password %s \\\\\n" "${FUZZER_PASS}"
printf "    -checker  UseAfterFree,InvalidDynamicObject \\\\\n"
printf "    -duration %s \\\\\n" "${DURATION_QUICK}"
printf "    -output   %s \\\\\n" "${OUT}"
printf "    -rps      %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -checker  "UseAfterFree,InvalidDynamicObject" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "=== Scenario 7 complete ==="
for d in 07a_schema 07b_behavioral 07c_stateful; do
    COUNT=$(ls "${RESULTS_BASE}/${d}/findings/"*.json 2>/dev/null | wc -l)
    printf "  %-30s %d findings\n" "${d}:" "${COUNT}"
done
