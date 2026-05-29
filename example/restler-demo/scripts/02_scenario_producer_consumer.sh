#!/usr/bin/env bash
# Scenario 1 — Producer-consumer dependency chain test
#
# The RESTler demo server has exactly one dependency chain:
#   POST /api/blog/posts  →  returns postId
#   GET    /api/blog/posts/{postId}
#   PUT    /api/blog/posts/{postId}
#   DELETE /api/blog/posts/{postId}
#
# This scenario measures whether the dependency graph works correctly.
# Run in verbose mode (-debug) to see which entries carry a postId.
#
# Expected results:
#   WITHOUT dependency graph: GET/PUT/DELETE mostly 404 (no valid postId)
#   WITH    dependency graph: GET/PUT/DELETE mostly 200 (postId from corpus pool)
#
# 2xx rate target: >50% when dependency graph is active.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/01_producer_consumer"
mkdir -p "${OUT}"

echo "=== Scenario 1: Producer-consumer dependency test ==="
echo "  Target:   ${DEMO_URL}"
echo "  Spec:     ${SPEC_FILE} (4 operations)"
echo "  Duration: ${DURATION_STANDARD}"
echo ""
echo "  This test exercises the dependency graph:"
echo "    POST /api/blog/posts → postId → GET/PUT/DELETE /api/blog/posts/{postId}"
echo ""

"${FUZZER}" \
    -spec       "${SPEC_FILE}" \
    -url        "${DEMO_URL}" \
    -csp-disable \
    -corpus-dir "${CORPUS_DIR}" \
    -duration   "${DURATION_STANDARD}" \
    -output     "${OUT}" \
    -rps        "${RPS}"

echo ""
echo "=== Results ==="
if [ -f "${OUT}/api-coverage.json" ]; then
    python3 - "${OUT}/api-coverage.json" << 'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  Total ops:   {d['total']}")
print(f"  Reached:     {d['visited_count']}/{d['total']}")
print(f"  Succeeded:   {d['succeeded_count']}/{d['total']} (2xx)")
rate = d['succeeded_count'] * 100 // d['total'] if d['total'] else 0
if rate >= 50:
    print(f"  PASS: {rate}% success rate — dependency graph is working")
else:
    print(f"  WARN: {rate}% success rate — low 2xx may indicate missing dependency graph")
EOF
fi
