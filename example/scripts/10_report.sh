#!/usr/bin/env bash
# 10_report.sh — Aggregate and summarise all findings across scenarios.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}=== shelob-ng findings report ===${NC}"
echo "  Results directory: ${RESULTS_BASE}/"
echo "  Generated: $(date)"
echo ""

TOTAL_FINDINGS=0
TOTAL_HIGH=0
TOTAL_MED=0
TOTAL_LOW=0

# -----------------------------------------------------------------------
# Per-scenario summary
# -----------------------------------------------------------------------
echo -e "${BOLD}Per-scenario summary:${NC}"
printf "  %-35s %6s  %4s %4s %4s\n" "Scenario" "Total" "HIGH" "MED" "LOW"
printf "  %-35s %6s  %4s %4s %4s\n" "-------" "-----" "----" "---" "---"

for scenario_dir in "${RESULTS_BASE}"/*/; do
    [ -d "${scenario_dir}/findings" ] || continue
    name=$(basename "${scenario_dir}")
    total=0; high=0; med=0; low=0

    for f in "${scenario_dir}/findings/"*.json; do
        [ -f "$f" ] || continue
        ((total++))
        sev=$(grep -o '"severity":"[^"]*"' "$f" 2>/dev/null | cut -d'"' -f4)
        case "$sev" in
            high)   ((high++)) ;;
            medium) ((med++))  ;;
            low)    ((low++))  ;;
        esac
    done

    ((TOTAL_FINDINGS+=total))
    ((TOTAL_HIGH+=high))
    ((TOTAL_MED+=med))
    ((TOTAL_LOW+=low))

    COLOR="${NC}"
    [ "$high" -gt 0 ] && COLOR="${RED}"
    [ "$high" -eq 0 ] && [ "$med" -gt 0 ] && COLOR="${YELLOW}"

    printf "  ${COLOR}%-35s %6d  %4d %4d %4d${NC}\n" "$name" "$total" "$high" "$med" "$low"
done

echo ""
printf "  ${BOLD}%-35s %6d  %4d %4d %4d${NC}\n" "TOTAL" "$TOTAL_FINDINGS" "$TOTAL_HIGH" "$TOTAL_MED" "$TOTAL_LOW"

# -----------------------------------------------------------------------
# Breakdown by checker
# -----------------------------------------------------------------------
echo ""
echo -e "${BOLD}By checker:${NC}"

declare -A CHECKER_COUNT
for f in "${RESULTS_BASE}"/**/findings/*.json; do
    [ -f "$f" ] || continue
    checker=$(grep -o '"checker":"[^"]*"' "$f" 2>/dev/null | cut -d'"' -f4)
    [ -n "$checker" ] && CHECKER_COUNT["$checker"]=$(( ${CHECKER_COUNT["$checker"]:-0} + 1 ))
done
for checker in "${!CHECKER_COUNT[@]}"; do
    printf "  %-35s %d\n" "$checker" "${CHECKER_COUNT[$checker]}"
done | sort -t' ' -k2 -rn

# -----------------------------------------------------------------------
# High-severity findings detail
# -----------------------------------------------------------------------
if [ "$TOTAL_HIGH" -gt 0 ]; then
    echo ""
    echo -e "${BOLD}${RED}High-severity findings:${NC}"
    for f in "${RESULTS_BASE}"/**/findings/*.json; do
        [ -f "$f" ] || continue
        sev=$(grep -o '"severity":"[^"]*"' "$f" 2>/dev/null | cut -d'"' -f4)
        [ "$sev" = "high" ] || continue

        if command -v jq &>/dev/null; then
            jq -r '"  [\(.checker)] \(.title)\n  URL: \(.url)\n  Detail: \(.detail)\n"' "$f"
        else
            echo "  File: $f"
            grep -o '"title":"[^"]*"' "$f" | cut -d'"' -f4
            grep -o '"url":"[^"]*"' "$f" | cut -d'"' -f4
            echo ""
        fi
    done
fi

# -----------------------------------------------------------------------
# Replays (sequence findings)
# -----------------------------------------------------------------------
REPLAY_COUNT=$(find "${RESULTS_BASE}" -path "*/replays/*.json" 2>/dev/null | wc -l)
if [ "$REPLAY_COUNT" -gt 0 ]; then
    echo ""
    echo -e "${BOLD}Sequence replays:${NC} ${REPLAY_COUNT} file(s)"
    find "${RESULTS_BASE}" -path "*/replays/*.json" | while read -r f; do
        seq=$(grep -o '"sequence":"[^"]*"' "$f" 2>/dev/null | cut -d'"' -f4)
        steps=$(grep -o '"step_index":[0-9]*' "$f" 2>/dev/null | tail -1 | grep -o '[0-9]*')
        echo "  ${seq}  (failed at step ${steps:-?})"
    done
fi

# -----------------------------------------------------------------------
# Quick reproduction guide
# -----------------------------------------------------------------------
if [ "$TOTAL_FINDINGS" -gt 0 ]; then
    echo ""
    echo -e "${BOLD}Reproducing a finding manually:${NC}"
    # Pick the first high-sev finding, or any finding.
    SAMPLE=$(find "${RESULTS_BASE}" -path "*/findings/*.json" 2>/dev/null | head -1)
    if [ -n "$SAMPLE" ] && command -v jq &>/dev/null; then
        METHOD=$(jq -r '.method' "$SAMPLE")
        URL=$(jq -r '.url' "$SAMPLE")
        echo "  # Example (${SAMPLE##*/}):"
        echo "  curl -v -X ${METHOD} '${URL}'"
    fi
fi

echo ""
echo -e "${BOLD}Raw finding files:${NC}"
echo "  find ${RESULTS_BASE} -name '*.json' | head -20"
