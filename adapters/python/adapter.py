"""
CSP adapter for Python — exposes coverage.py data via HTTP.

Usage
-----
Install dependencies:
    pip install coverage flask

Wrap your application startup:
    python adapter.py --app "gunicorn myapp:app" --port 8080

Or import and embed in your own code:
    from adapter import start_csp_server
    import threading
    threading.Thread(target=start_csp_server, args=(":8080",), daemon=True).start()

The adapter exposes:
    POST /csp/reset  — snapshot current coverage as baseline
    GET  /csp/dump   — return new coverage since last reset
"""

import threading
import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import coverage as coverage_module
    COV = coverage_module.Coverage()
    COV.start()
except ImportError:
    COV = None
    print("[CSP] WARNING: 'coverage' not installed; coverage data will be empty", file=sys.stderr)

_lock = threading.Lock()
_baseline: set[str] = set()
_total_seen: set[str] = set()


def _snapshot() -> set[str]:
    """Return the set of 'file:line' strings executed so far."""
    if COV is None:
        return set()
    data = COV.get_data()
    lines: set[str] = set()
    for fname in data.measured_files():
        for lineno in data.lines(fname) or []:
            lines.add(f"{fname}:{lineno}")
    return lines


class CSPHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # suppress access log

    def do_POST(self):
        if self.path != "/csp/reset":
            self._respond(404, "Not found")
            return
        with _lock:
            global _baseline
            _baseline = _snapshot()
        self._respond(200, "OK\n")

    def do_GET(self):
        if self.path != "/csp/dump":
            self._respond(404, "Not found")
            return
        with _lock:
            current = _snapshot()
            new_lines = list(current - _baseline)
            for line in new_lines:
                _total_seen.add(line)
            payload = {
                "total_lines":     len(current),
                "covered_lines":   len(_total_seen),
                "new_since_reset": new_lines,
            }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond(self, code: int, body: str):
        encoded = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def start_csp_server(addr: str = "0.0.0.0", port: int = 8080):
    """Start the CSP HTTP server. Blocks until interrupted."""
    server = HTTPServer((addr, port), CSPHandler)
    print(f"[CSP] adapter ready on {addr}:{port}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="shelob-ng CSP adapter for Python")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    t = threading.Thread(target=start_csp_server, args=(args.host, args.port), daemon=True)
    t.start()
    t.join()
