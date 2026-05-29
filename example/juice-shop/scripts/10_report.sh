#!/usr/bin/env bash
# 10_report.sh — Aggregate and summarise all findings across scenarios.
# Console: per-scenario summary + checker breakdown.
# File:    ${RESULTS_BASE}/report.md — full report with findings, POCs, coverage.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

REPORT_MD="${RESULTS_BASE}/report.md"

# -----------------------------------------------------------------------
# Pass 1 — collect totals
# -----------------------------------------------------------------------
TOTAL_FINDINGS=0; TOTAL_HIGH=0; TOTAL_MED=0; TOTAL_LOW=0

declare -A SCENARIO_TOTAL SCENARIO_HIGH SCENARIO_MED SCENARIO_LOW
declare -A CHECKER_COUNT

for scenario_dir in "${RESULTS_BASE}"/*/; do
    [ -d "${scenario_dir}/findings" ] || continue
    name=$(basename "${scenario_dir}")
    t=0; h=0; m=0; l=0
    for f in "${scenario_dir}/findings/"*.json; do
        [ -f "$f" ] || continue
        t=$((t+1))
        sev=$(grep -oE '"severity": *"[^"]*"' "$f" 2>/dev/null | cut -d'"' -f4)
        case "$sev" in
            high)   h=$((h+1)) ;;
            medium) m=$((m+1)) ;;
            low)    l=$((l+1)) ;;
        esac
        checker=$(grep -oE '"checker": *"[^"]*"' "$f" 2>/dev/null | cut -d'"' -f4)
        [ -n "$checker" ] && CHECKER_COUNT["$checker"]=$(( ${CHECKER_COUNT["$checker"]:-0} + 1 ))
    done
    SCENARIO_TOTAL[$name]=$t; SCENARIO_HIGH[$name]=$h
    SCENARIO_MED[$name]=$m;  SCENARIO_LOW[$name]=$l
    TOTAL_FINDINGS=$((TOTAL_FINDINGS+t)); TOTAL_HIGH=$((TOTAL_HIGH+h))
    TOTAL_MED=$((TOTAL_MED+m));           TOTAL_LOW=$((TOTAL_LOW+l))
done

# -----------------------------------------------------------------------
# Console output — summary only
# -----------------------------------------------------------------------
echo -e "${BOLD}=== shelob-ng findings report ===${NC}"
echo "  Results directory: ${RESULTS_BASE}/"
echo "  Generated: $(date)"
echo ""

echo -e "${BOLD}Per-scenario summary:${NC}"
printf "  %-35s %6s  %4s %4s %4s\n" "Scenario" "Total" "HIGH" "MED" "LOW"
printf "  %-35s %6s  %4s %4s %4s\n" "-------" "-----" "----" "---" "---"

for name in $(echo "${!SCENARIO_TOTAL[@]}" | tr ' ' '\n' | sort); do
    h=${SCENARIO_HIGH[$name]}; m=${SCENARIO_MED[$name]}
    COLOR="${NC}"
    [ "$h" -gt 0 ] && COLOR="${RED}"
    [ "$h" -eq 0 ] && [ "$m" -gt 0 ] && COLOR="${YELLOW}"
    printf "  ${COLOR}%-35s %6d  %4d %4d %4d${NC}\n" \
        "$name" "${SCENARIO_TOTAL[$name]}" "$h" "$m" "${SCENARIO_LOW[$name]}"
done

echo ""
printf "  ${BOLD}%-35s %6d  %4d %4d %4d${NC}\n" \
    "TOTAL" "$TOTAL_FINDINGS" "$TOTAL_HIGH" "$TOTAL_MED" "$TOTAL_LOW"

echo ""
echo -e "${BOLD}By checker:${NC}"
for checker in "${!CHECKER_COUNT[@]}"; do
    printf "  %-35s %d\n" "$checker" "${CHECKER_COUNT[$checker]}"
done | sort -t' ' -k2 -rn || true

echo ""
echo "  Full report: ${REPORT_MD}"

# -----------------------------------------------------------------------
# Markdown report
# -----------------------------------------------------------------------
_jq() { command -v jq &>/dev/null && jq "$@" || python3 -c "
import json,sys
d=json.load(open(sys.argv[-1]))
print(d.get('${1//\'/}',''))
" 2>/dev/null; }

{
cat <<HEADER
# shelob-ng findings report

- **Results directory:** \`${RESULTS_BASE}/\`
- **Generated:** $(date)

---

## Per-scenario summary

| Scenario | Total | HIGH | MED | LOW |
|---|---:|---:|---:|---:|
HEADER

for name in $(echo "${!SCENARIO_TOTAL[@]}" | tr ' ' '\n' | sort); do
    echo "| \`${name}\` | ${SCENARIO_TOTAL[$name]} | ${SCENARIO_HIGH[$name]} | ${SCENARIO_MED[$name]} | ${SCENARIO_LOW[$name]} |"
done

cat <<SEP
| **TOTAL** | **${TOTAL_FINDINGS}** | **${TOTAL_HIGH}** | **${TOTAL_MED}** | **${TOTAL_LOW}** |

---

## By checker

| Checker | Count |
|---|---:|
SEP

for checker in "${!CHECKER_COUNT[@]}"; do
    printf "| \`%s\` | %d |\n" "$checker" "${CHECKER_COUNT[$checker]}"
done | sort -t'|' -k3 -rn || true

echo ""
echo "---"
echo ""
echo "## Unique findings (deduplicated)"

_md_finding() {
    local f="$1"
    if command -v jq &>/dev/null; then
        jq -r '
          "### [\(.severity | ascii_upcase)] \(.checker) — \(.title)\n",
          "| Field | Value |",
          "|---|---|",
          "| **Operation** | `\(.method) \(.path_pattern // "-")` |",
          "| **URL** | `\(.url)` |",
          "| **Status** | \(.status_code) |",
          "| **Detail** | \(.detail) |",
          "",
          (if .poc then
            "**POC:**\n```bash\n" + .poc + "\n```"
          else empty end),
          ""
        ' "$f"
    else
        echo "- \`$f\`"
        echo ""
    fi
}

if [ "$TOTAL_HIGH" -gt 0 ]; then
    echo ""
    echo "### HIGH severity"
    echo ""
    for f in "${RESULTS_BASE}"/**/findings/*.json; do
        [ -f "$f" ] || continue
        sev=$(jq -r '.severity' "$f" 2>/dev/null) || continue
        [ "$sev" = "high" ] || continue
        _md_finding "$f"
    done
fi

if [ "$TOTAL_MED" -gt 0 ]; then
    echo ""
    echo "### MEDIUM severity"
    echo ""
    for f in "${RESULTS_BASE}"/**/findings/*.json; do
        [ -f "$f" ] || continue
        sev=$(jq -r '.severity' "$f" 2>/dev/null) || continue
        [ "$sev" = "medium" ] || continue
        _md_finding "$f"
    done
fi

REPLAY_COUNT=$(find "${RESULTS_BASE}" -path "*/replays/*.json" 2>/dev/null | wc -l)
if [ "$REPLAY_COUNT" -gt 0 ]; then
    echo ""
    echo "---"
    echo ""
    echo "## Sequence replays"
    echo ""
    echo "| Sequence | Failed at step |"
    echo "|---|---:|"
    find "${RESULTS_BASE}" -path "*/replays/*.json" | while read -r f; do
        seq=$(grep -o '"sequence":"[^"]*"' "$f" 2>/dev/null | cut -d'"' -f4)
        step=$(grep -o '"step_index":[0-9]*' "$f" 2>/dev/null | tail -1 | grep -o '[0-9]*')
        echo "| \`${seq:-?}\` | ${step:-?} |"
    done
fi

echo ""
echo "---"
echo ""
echo "## API spec coverage"
echo ""
echo "| Scenario | Reached | Succeeded (2xx) | Unvisited | Total | % |"
echo "|---|---:|---:|---:|---:|---:|"

HAVE_COV=0
for cov_file in "${RESULTS_BASE}"/*/api-coverage.json; do
    [ -f "$cov_file" ] || continue
    HAVE_COV=1
    scenario=$(basename "$(dirname "$cov_file")")
    python3 - "$cov_file" "$scenario" << 'PYEOF'
import json, sys
path, name = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = json.load(f)
total = d.get("total", 0)
vis   = d.get("visited_count", 0)
succ  = d.get("succeeded_count", 0)
unvis = d.get("unvisited_count", total - vis)
pct   = int(100 * vis / total) if total else 0
print(f"| `{name}` | {vis} | {succ} | {unvis} | {total} | {pct}% |")
PYEOF
done

if [ "$HAVE_COV" -eq 0 ]; then
    echo "| — | — | — | — | — | — |"
fi

# Unvisited operations per scenario
if [ "$HAVE_COV" -gt 0 ]; then
    for cov_file in "${RESULTS_BASE}"/*/api-coverage.json; do
        [ -f "$cov_file" ] || continue
        scenario=$(basename "$(dirname "$cov_file")")
        python3 - "$cov_file" "$scenario" << 'PYEOF'
import json, sys
path, name = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = json.load(f)
unvis = d.get("unvisited", [])
if unvis:
    print(f"\n**`{name}` — not reached ({len(unvis)} operations):**\n")
    for op in sorted(unvis, key=lambda o: (o['path'], o['method'])):
        opid = f"  `{op['operationId']}`" if op.get('operationId') else ""
        print(f"- `{op['method']:<8} {op['path']}`{opid}")
PYEOF
    done
fi

cat <<FOOTER

---

## Reproducing findings

All finding files are in \`${RESULTS_BASE}/*/findings/\`.

\`\`\`bash
# List all findings
find ${RESULTS_BASE} -name '*.json' -path '*/findings/*'

# Extract all POC commands
jq -r 'select(.poc) | "# [\(.severity | ascii_upcase)] \(.checker) \(.title)\\n" + .poc + "\\n"' \\
    ${RESULTS_BASE}/*/findings/*.json

# HIGH findings only
jq -r 'select(.severity=="high") | .poc // empty' \\
    ${RESULTS_BASE}/*/findings/*.json
\`\`\`
FOOTER

} > "${REPORT_MD}"
