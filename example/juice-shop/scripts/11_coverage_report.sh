#!/usr/bin/env bash
# 11_coverage_report.sh — Generate an HTML coverage report from accumulated
# V8 ScriptCoverage collected by the CSP sidecar during fuzzing.
#
# Prerequisites:
#   - Juice Shop must be running with the CSP sidecar (make start-csp)
#   - At least one fuzzing scenario must have run (to produce coverage data)
#
# How it works:
#   1. Fetch accumulated V8 ScriptCoverage JSON from GET /csp/v8report
#   2. Parse the function-level coverage ranges with Python
#   3. Render a standalone HTML report sorted by coverage % (lowest first)
#      so the least-tested files are at the top
#
# Output: results/coverage-report/index.html
set -euo pipefail
cd "$(dirname "$0")/.."
source ./config.env

OUT="${RESULTS_BASE}/coverage-report"

GREEN='\033[0;32m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

echo -e "${BOLD}=== Coverage report ===${NC}"

# -----------------------------------------------------------------------
# 1. Check CSP sidecar is running and has data
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
# 2. Fetch JSON and generate HTML report with Python
# -----------------------------------------------------------------------
mkdir -p "${OUT}"
TMP_JSON="/tmp/shelob-v8-coverage-$$.json"
echo "Fetching coverage JSON from ${CSP_URL}/csp/v8report ..."
curl -s "${CSP_URL}/csp/v8report" > "${TMP_JSON}"
SIZE=$(wc -c < "${TMP_JSON}")
ok "Coverage JSON: ${SIZE} bytes"

echo "Generating HTML report ..."
python3 - "${TMP_JSON}" "${OUT}/index.html" << 'PYEOF'
import json, sys, html, os, re
from datetime import datetime

src_path, out_path = sys.argv[1], sys.argv[2]
with open(src_path) as f:
    data = json.load(f)

scripts = data.get("result", [])
timestamp = data.get("timestamp", 0)
ts_str = datetime.fromtimestamp(timestamp / 1000).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "unknown"

def strip_url(url):
    """Extract a short readable path from a script URL."""
    # file:///juice-shop/build/routes/login.js -> build/routes/login.js
    url = re.sub(r'^file://', '', url)
    # strip common prefix
    for prefix in ['/juice-shop/', '/app/']:
        if prefix in url:
            return url[url.index(prefix) + len(prefix):]
    return os.path.basename(url) or url

def compute_coverage(script):
    """
    Compute byte-level coverage for a script from its function ranges.
    Returns (covered_bytes, total_bytes).
    """
    url = script.get("url", "")
    functions = script.get("functions", [])
    if not functions:
        return 0, 0

    # Collect all range endpoints to find total span.
    all_starts = []
    all_ends = []
    for fn in functions:
        for r in fn.get("ranges", []):
            all_starts.append(r["startOffset"])
            all_ends.append(r["endOffset"])
    if not all_starts:
        return 0, 0

    total_end = max(all_ends)
    total_start = min(all_starts)
    total = total_end - total_start
    if total <= 0:
        return 0, 0

    # Build a covered byte map using range count > 0.
    covered = bytearray(total)
    for fn in functions:
        for r in fn.get("ranges", []):
            if r.get("count", 0) > 0:
                s = r["startOffset"] - total_start
                e = r["endOffset"] - total_start
                for i in range(max(0, s), min(total, e)):
                    covered[i] = 1

    return sum(covered), total

rows = []
for script in scripts:
    url = script.get("url", "")
    # Skip node internals, adapter itself, and anonymous scripts.
    if not url or url.startswith("node:") or "csp-adapter" in url or url == "node_modules":
        continue
    if "node_modules" in url:
        continue
    covered, total = compute_coverage(script)
    if total == 0:
        continue
    pct = 100.0 * covered / total
    label = strip_url(url)
    fn_count = len(script.get("functions", []))
    rows.append((pct, label, covered, total, fn_count, url))

# Sort: lowest coverage first (most interesting gap at top).
rows.sort(key=lambda r: r[0])

# -----------------------------------------------------------------------
# HTML generation
# -----------------------------------------------------------------------
def pct_color(p):
    if p >= 80:
        return "#2ecc71"  # green
    if p >= 50:
        return "#f39c12"  # orange
    return "#e74c3c"      # red

summary_covered = sum(r[2] for r in rows)
summary_total   = sum(r[3] for r in rows)
summary_pct     = 100.0 * summary_covered / summary_total if summary_total else 0

table_rows = ""
for pct, label, covered, total, fn_count, url in rows:
    bar_w = int(pct)
    color = pct_color(pct)
    table_rows += f"""
    <tr>
      <td class="label" title="{html.escape(url)}">{html.escape(label)}</td>
      <td class="pct" style="color:{color}">{pct:.1f}%</td>
      <td class="bar"><div class="bar-bg"><div class="bar-fill" style="width:{bar_w}%;background:{color}"></div></div></td>
      <td class="nums">{covered:,} / {total:,}</td>
      <td class="fns">{fn_count}</td>
    </tr>"""

report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>shelob-ng — V8 Coverage Report</title>
<style>
  body {{ font-family: monospace; background:#1a1a2e; color:#eee; margin:0; padding:20px; }}
  h1 {{ color:#00d2ff; margin-bottom:4px; }}
  .meta {{ color:#888; font-size:.85em; margin-bottom:20px; }}
  .summary {{ background:#16213e; border:1px solid #0f3460; border-radius:6px;
              padding:12px 20px; margin-bottom:20px; display:flex; gap:40px; }}
  .summary .val {{ font-size:1.6em; font-weight:bold; color:{pct_color(summary_pct)}; }}
  .summary .lbl {{ font-size:.8em; color:#888; }}
  table {{ border-collapse:collapse; width:100%; }}
  th {{ background:#0f3460; color:#00d2ff; padding:8px 12px; text-align:left;
        position:sticky; top:0; }}
  tr:nth-child(even) {{ background:#16213e; }}
  tr:hover {{ background:#0f3460; }}
  td {{ padding:6px 12px; font-size:.88em; }}
  td.label {{ max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  td.pct {{ width:60px; font-weight:bold; }}
  td.bar {{ width:200px; }}
  td.nums {{ width:140px; color:#aaa; }}
  td.fns {{ width:60px; color:#aaa; text-align:right; }}
  .bar-bg {{ background:#333; border-radius:3px; height:12px; }}
  .bar-fill {{ height:12px; border-radius:3px; transition:width .3s; }}
  .note {{ color:#888; font-size:.8em; margin-top:16px; }}
</style>
</head>
<body>
<h1>shelob-ng — V8 Coverage Report</h1>
<div class="meta">Generated: {ts_str} &nbsp;|&nbsp; {len(rows)} scripts tracked</div>

<div class="summary">
  <div>
    <div class="val">{summary_pct:.1f}%</div>
    <div class="lbl">overall byte coverage</div>
  </div>
  <div>
    <div class="val">{summary_covered:,}</div>
    <div class="lbl">covered bytes</div>
  </div>
  <div>
    <div class="val">{summary_total:,}</div>
    <div class="lbl">total bytes</div>
  </div>
  <div>
    <div class="val">{len(rows)}</div>
    <div class="lbl">files</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th>File</th>
      <th>Coverage</th>
      <th>Bar</th>
      <th>Bytes (cov/total)</th>
      <th>Fns</th>
    </tr>
  </thead>
  <tbody>{table_rows}
  </tbody>
</table>
<div class="note">
  Coverage is computed from V8 function ranges accumulated by the CSP adapter.
  Rows sorted by coverage % ascending (least-tested files first).
</div>
</body>
</html>"""

with open(out_path, "w") as f:
    f.write(report)

print(f"  Files tracked : {len(rows)}")
print(f"  Overall       : {summary_pct:.1f}%  ({summary_covered:,} / {summary_total:,} bytes)")
PYEOF

rm -f "${TMP_JSON}"

echo ""
echo -e "${BOLD}=== Report ready ===${NC}"
echo "  HTML: ${OUT}/index.html"
echo "  Open: xdg-open ${OUT}/index.html"
