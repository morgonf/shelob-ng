#!/usr/bin/env bash
# Scenario 6 — Corpus persistence (save and resume)
#
# Demonstrates that the corpus survives across fuzzing sessions.
# Run 1: fuzzes for DURATION_QUICK, saves corpus to disk.
# Run 2: loads the saved corpus, continues where Run 1 left off.
#
# Why this matters:
#   - The second run starts with inputs that already exercised interesting
#     code paths, so it finds bugs faster than starting from scratch.
#   - Long-running campaigns can be split across multiple sessions.
#   - The corpus can be shared between team members.
#
# Corpus storage format:
#   corpus/<dir>/
#     index.json           — manifest (hashes, count, version)
#     entries/<hash>.json  — one file per CorpusEntry
#
# Findings:
#   Same as scenario 2. The interesting part is speed: display shows
#   "corpus: NNN seed entries" at startup vs "corpus: 0" in scenario 1.
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT_1="${RESULTS_BASE}/06_corpus_run1"
OUT_2="${RESULTS_BASE}/06_corpus_run2"
CORP="${CORPUS_DIR}/scenario6"

mkdir -p "${OUT_1}" "${OUT_2}" "${CORP}"

# -----------------------------------------------------------------------
# Run 1: build initial corpus
# -----------------------------------------------------------------------
echo "=== Scenario 6a: Corpus — Run 1 (building corpus) ==="
echo "  Duration: ${DURATION_QUICK}"
echo "  Corpus:   ${CORP}/"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec       %s \\\\\n" "${SPEC_FILE}"
printf "    -url        %s \\\\\n" "${JUICE_URL}"
printf "    -user       %s \\\\\n" "${FUZZER_USER}"
printf "    -password   %s \\\\\n" "${FUZZER_PASS}"
printf "    -corpus-dir %s \\\\\n" "${CORP}"
printf "    -duration   %s \\\\\n" "${DURATION_QUICK}"
printf "    -output     %s \\\\\n" "${OUT_1}"
printf "    -rps        %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec       "${SPEC_FILE}" \
    -url        "${JUICE_URL}" \
    -user       "${FUZZER_USER}" \
    -password   "${FUZZER_PASS}" \
    -corpus-dir "${CORP}" \
    -duration   "${DURATION_QUICK}" \
    -output     "${OUT_1}" \
    -rps        "${RPS}"

CORPUS_SIZE=$(cat "${CORP}/index.json" 2>/dev/null | grep entry_count | grep -o '[0-9]*' | head -1 || echo "?")
echo ""
echo "Run 1 complete. Corpus saved: ${CORPUS_SIZE} entries in ${CORP}/"

# -----------------------------------------------------------------------
# Run 2: resume from saved corpus
# -----------------------------------------------------------------------
echo ""
echo "=== Scenario 6b: Corpus — Run 2 (resuming from saved corpus) ==="
echo "  Corpus loaded: ${CORPUS_SIZE} entries"
echo "  Duration: ${DURATION_QUICK}"
echo ""
printf "Command:\n"
printf "  %s \\\\\n"      "${FUZZER}"
printf "    -spec       %s \\\\\n" "${SPEC_FILE}"
printf "    -url        %s \\\\\n" "${JUICE_URL}"
printf "    -user       %s \\\\\n" "${FUZZER_USER}"
printf "    -password   %s \\\\\n" "${FUZZER_PASS}"
printf "    -corpus-dir %s \\\\\n" "${CORP}"
printf "    -duration   %s \\\\\n" "${DURATION_QUICK}"
printf "    -output     %s \\\\\n" "${OUT_2}"
printf "    -rps        %s\n"      "${RPS}"
printf "\n"

"${FUZZER}" \
    -spec       "${SPEC_FILE}" \
    -url        "${JUICE_URL}" \
    -user       "${FUZZER_USER}" \
    -password   "${FUZZER_PASS}" \
    -corpus-dir "${CORP}" \
    -duration   "${DURATION_QUICK}" \
    -output     "${OUT_2}" \
    -rps        "${RPS}"

echo ""
echo "Run 2 complete."
echo "  Run 1 findings: $(ls ${OUT_1}/findings/*.json 2>/dev/null | wc -l)"
echo "  Run 2 findings: $(ls ${OUT_2}/findings/*.json 2>/dev/null | wc -l)"
