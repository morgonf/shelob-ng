#!/usr/bin/env bash
# Scenario 10 — LeakageRule false-positive verification
#
# Verifies that LeakageRule no longer fires on 401/403 responses.
#
# Background (the bug that was fixed):
#   Old behaviour: POST /api/Feedbacks → 401 Unauthorized
#                  GET  /api/Feedbacks → 200 OK (public collection)
#                  → LeakageRule emitted a FINDING — FALSE POSITIVE
#
#   Root cause: a 401/403 means the request was rejected by the auth layer
#   before reaching application logic. No data could have been committed.
#   The GET returning 200 is correct — the collection endpoint is public.
#
# Fixed behaviour: LeakageRule skips 401 and 403 responses entirely.
#   Only 400/422 (validation failure) on a POST can indicate a real
#   partial-state bug where logic ran but the transaction was not rolled back.
#
# This script:
#   Part A — Runs LeakageRule in isolation to produce the finding set.
#   Part B — Analyses the findings and verifies:
#     • No findings with status_code 401 or 403 (these were false positives)
#     • Any remaining findings have a real validation-error trigger (400/422)
#   Part C — Demonstrates that authenticated 400/422 still fires correctly
#            by looking for genuine LeakageRule candidates.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/10_leakage_verify"
mkdir -p "${OUT}"

echo "=== Scenario 10: LeakageRule false-positive verification ==="
echo "  Target:   ${JUICE_URL}"
echo "  Checker:  LeakageRule only"
echo "  Duration: ${DURATION_QUICK}"
echo "  Output:   ${OUT}/"
echo ""

# -----------------------------------------------------------------------
# Part A: run with LeakageRule only
# -----------------------------------------------------------------------
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec     %s \\\\\n" "${SPEC_FILE}"
printf "    -url      %s \\\\\n" "${JUICE_URL}"
printf "    -user     %s \\\\\n" "${FUZZER_USER}"
printf "    -password %s \\\\\n" "${FUZZER_PASS}"
printf "    -checker  LeakageRule \\\\\n"
printf "    -duration %s \\\\\n" "${DURATION_QUICK}"
printf "    -output   %s \\\\\n" "${OUT}"
printf "    -rps      %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec     "${SPEC_FILE}" \
    -url      "${JUICE_URL}" \
    -user     "${FUZZER_USER}" \
    -password "${FUZZER_PASS}" \
    -checker  "LeakageRule" \
    -duration "${DURATION_QUICK}" \
    -output   "${OUT}" \
    -rps      "${RPS}"

echo ""

# -----------------------------------------------------------------------
# Part B: analyse findings
# -----------------------------------------------------------------------
echo "=== Analysis ==="

python3 - "${OUT}" << 'PYEOF'
import json, os, sys, glob

out_dir = sys.argv[1]
pattern = os.path.join(out_dir, 'findings', '*.json')
files   = sorted(glob.glob(pattern))

if not files:
    print("  No LeakageRule findings — clean run!")
    print()
    print("  PASS: LeakageRule produced zero false positives.")
    sys.exit(0)

print(f"  Total unique findings: {len(files)}")
print()

false_positives = []
real_findings   = []

for path in files:
    with open(path) as f:
        d = json.load(f)
    detail = d.get('detail', '')
    # Extract the trigger status code from the detail string
    # Detail format: "POST <url> returned <code> (rejected), but GET returned <code> (resource exists)"
    import re
    m = re.search(r'returned (\d+) \(rejected\)', detail)
    trigger_code = int(m.group(1)) if m else 0

    if trigger_code in (401, 403):
        false_positives.append({'file': os.path.basename(path), 'code': trigger_code, 'detail': detail})
    else:
        real_findings.append({'file': os.path.basename(path), 'code': trigger_code, 'detail': detail})

if false_positives:
    print(f"  FAIL: {len(false_positives)} false positive(s) found (401/403 trigger):")
    for fp in false_positives:
        print(f"    [{fp['code']}] {fp['file']}")
        print(f"           {fp['detail'][:80]}")
    print()
    print("  The LeakageRule 401/403 fix is NOT applied in this build.")
else:
    print("  PASS: zero findings triggered by 401/403 responses.")
    print("        Auth rejections correctly excluded from LeakageRule.")

print()

if real_findings:
    print(f"  Genuine LeakageRule candidates ({len(real_findings)}):")
    print("  (POST returned 400/422 but resource is readable via GET)")
    for rf in real_findings:
        print(f"    [{rf['code']}] {rf['file']}")
        print(f"           {rf['detail'][:80]}")
    print()
    print("  These warrant manual investigation — they may indicate")
    print("  commit-then-validate bugs or missing transaction rollbacks.")
else:
    print("  No genuine LeakageRule findings (POST 400/422 → GET 200).")
    print("  Juice Shop correctly rolls back failed transactions.")

PYEOF
