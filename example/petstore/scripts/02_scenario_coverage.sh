#!/usr/bin/env bash
# Scenario 1 — Spec coverage baseline (Petstore)
#
# Petstore has no intentional vulnerabilities. Use this scenario to:
#   1. Verify the fuzzer generates valid requests for all 13 operations
#   2. Measure 2xx rate as a baseline for your fuzzer improvements
#   3. Test apiKey authentication handling (-apikey flag)
#   4. Test XML + form-encoded body generation (Petstore accepts all three)
#
# Expected: 70-90% of endpoints reached; ~30-50% 2xx rate (stateless Petstore
# does not persist state between requests, so dependent ops may return 404).
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/01_coverage"
mkdir -p "${OUT}"

echo "=== Scenario 1: Spec coverage baseline (Petstore) ==="
echo "  Target:   ${PETSTORE_URL}/api/v3"
echo "  API key:  ${API_KEY}"
echo "  Duration: ${DURATION_QUICK}"
echo ""

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${PETSTORE_URL}/api/v3" \
    -apikey   "${API_KEY}" \
    -csp-disable \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""
echo "API coverage:"
if [ -f "${OUT}/api-coverage.json" ]; then
    python3 -c "
import json
d = json.load(open('${OUT}/api-coverage.json'))
print(f\"  Reached:   {d['visited_count']}/{d['total']} ({100*d['visited_count']//d['total']}%)\")
print(f\"  Succeeded: {d['succeeded_count']}/{d['total']} ({100*d['succeeded_count']//d['total']}%)\")
"
fi
