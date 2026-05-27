#!/usr/bin/env bash
# 11_coverage_report.sh — Generate an HTML coverage report from accumulated
# V8 ScriptCoverage collected by the CSP sidecar during fuzzing.
#
# Prerequisites:
#   - Juice Shop must be running with the CSP sidecar (make start-csp)
#   - At least one fuzzing scenario must have run (to produce coverage data)
#   - The CSP Docker image must have been built after the c8 install was added
#     to csp/Dockerfile (make start-csp does this via docker compose build)
#
# How it works:
#   1. Fetch accumulated V8 ScriptCoverage JSON from GET /csp/v8report
#   2. Copy the JSON into the juice-shop-csp container (which has the source)
#   3. Run `c8 report` inside the container — c8 maps offsets to source lines
#      using the files at /juice-shop/build/
#   4. Copy the generated HTML report back to results/coverage-report/
#
# Output: results/coverage-report/index.html
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

CONTAINER="juice-shop-csp"
OUT="${RESULTS_BASE}/coverage-report"

GREEN='\033[0;32m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

echo -e "${BOLD}=== Coverage report ===${NC}"

# -----------------------------------------------------------------------
# 1. Check CSP sidecar is running
# -----------------------------------------------------------------------
if ! curl -s --connect-timeout 3 "${CSP_URL}/csp/v8report" | grep -q '"result"' 2>/dev/null; then
    err "CSP sidecar not running or no coverage data. Run: make start-csp then a fuzzing scenario."
fi

SCRIPTS=$(curl -s "${CSP_URL}/csp/v8report" | python3 -c \
    "import json,sys; d=json.load(sys.stdin); print(len(d.get('result',[])))" 2>/dev/null || echo 0)
if [ "${SCRIPTS}" -eq 0 ]; then
    err "No coverage data accumulated yet. Run at least one scenario with CSP enabled."
fi
ok "Coverage data: ${SCRIPTS} script(s) tracked"

# -----------------------------------------------------------------------
# 2. Check the container is running
# -----------------------------------------------------------------------
if ! docker inspect "${CONTAINER}" &>/dev/null; then
    err "Container ${CONTAINER} not found. Run: make start-csp"
fi

# -----------------------------------------------------------------------
# 3. Fetch accumulated V8 coverage JSON from CSP sidecar
# -----------------------------------------------------------------------
TMP_JSON="/tmp/shelob-v8-coverage-$$.json"
echo "Fetching coverage JSON from ${CSP_URL}/csp/v8report ..."
curl -s "${CSP_URL}/csp/v8report" > "${TMP_JSON}"
SIZE=$(wc -c < "${TMP_JSON}")
ok "Coverage JSON: ${SIZE} bytes"

# -----------------------------------------------------------------------
# 4. Copy JSON into container and run c8
#
# The juice-shop image has no /bin/sh, so all docker exec calls use exec
# form (no shell). node/npm live at /nodejs/bin/; c8 is installed globally
# there by the Dockerfile. Working directory is set with -w flag.
# -----------------------------------------------------------------------
echo "Generating HTML report inside container ${CONTAINER} ..."

# Create temp dirs via node (no mkdir in image).
docker exec "${CONTAINER}" /nodejs/bin/node \
    -e "const fs=require('fs'); fs.mkdirSync('/tmp/v8cov',{recursive:true}); fs.rmSync('/tmp/cov-report',{recursive:true,force:true})"

docker cp "${TMP_JSON}" "${CONTAINER}:/tmp/v8cov/coverage-0.json"
rm -f "${TMP_JSON}"

docker exec -w /juice-shop "${CONTAINER}" \
    /nodejs/bin/c8 report \
        --temp-dir    /tmp/v8cov \
        --reports-dir /tmp/cov-report \
        --reporter    html \
        --reporter    text \
        --src         /juice-shop/build

# -----------------------------------------------------------------------
# 5. Copy report out of container
# -----------------------------------------------------------------------
mkdir -p "${OUT}"
docker cp "${CONTAINER}:/tmp/cov-report/." "${OUT}/"

echo ""
echo -e "${BOLD}=== Report ready ===${NC}"
echo "  HTML: ${OUT}/index.html"
echo "  Open: xdg-open ${OUT}/index.html"
