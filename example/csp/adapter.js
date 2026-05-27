'use strict';
/**
 * CSP adapter for OWASP Juice Shop (Node.js 16+).
 *
 * Loaded via NODE_OPTIONS="--require /path/to/adapter.js" before the app starts.
 * Starts a separate HTTP server on CSP_PORT (default 8080) that exposes:
 *
 *   POST /csp/reset  — snapshot current coverage as baseline
 *   GET  /csp/dump   — return lines covered since last reset
 *
 * Uses the V8 Inspector Profiler API (Profiler.startPreciseCoverage /
 * Profiler.takePreciseCoverage) which is available in all Node.js 12+
 * builds without additional flags.
 */

const http      = require('http');
const inspector = require('inspector');
const path      = require('path');

const CSP_PORT = parseInt(process.env.CSP_PORT || '8080', 10);

// --- V8 coverage session ---

const session = new inspector.Session();
session.connect();

// Enable the Profiler domain and start precise (non-blocking) coverage.
session.post('Profiler.enable');
session.post('Profiler.startPreciseCoverage', {
  callCount: false,   // we only need hit/miss, not per-call counts
  detailed:  false,   // function-level granularity is enough for delta detection
});

/**
 * Returns the set of "file:offset" strings currently covered by V8,
 * excluding node internals and node_modules.
 */
function takeCoverageSnapshot(callback) {
  session.post('Profiler.takePreciseCoverage', (err, data) => {
    if (err || !data) {
      return callback(null, new Set());
    }

    const lines = new Set();
    for (const script of data.result) {
      const url = script.url || '';

      // Skip node builtins, this adapter itself, and third-party modules.
      if (!url
          || url.startsWith('node:')
          || url.includes('node_modules')
          || url.includes('csp/adapter')
          || url.includes('adapter.js')) {
        continue;
      }

      // Normalise to a short relative path for readability in /csp/dump output.
      let fname = url.replace(/^file:\/\//, '');
      try {
        fname = path.relative(process.cwd(), fname);
      } catch (_) { /* keep absolute path */ }

      for (const func of script.functions) {
        for (const range of func.ranges) {
          if (range.count > 0) {
            lines.add(`${fname}:${range.startOffset}`);
          }
        }
      }
    }
    callback(null, lines);
  });
}

// --- State ---

// baseline: coverage snapshot taken at the last /csp/reset call.
// delta = (current snapshot) - baseline
let baseline   = new Set();
let totalSeen  = new Set(); // cumulative across all requests

// --- HTTP server ---

function readBody(req, callback) {
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end',  () => callback(body));
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/csp/reset') {
    // Drain body (shelob-ng sends an empty POST).
    readBody(req, () => {
      takeCoverageSnapshot((err, snap) => {
        baseline = snap;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK\n');
      });
    });

  } else if (req.method === 'GET' && req.url === '/csp/dump') {
    takeCoverageSnapshot((err, current) => {
      const newLines = [];
      for (const line of current) {
        if (!baseline.has(line)) {
          newLines.push(line);
          totalSeen.add(line);
        }
      }

      const payload = {
        total_lines:     current.size,
        covered_lines:   totalSeen.size,
        bitmap:          '',          // not used by shelob-ng
        new_since_reset: newLines,
      };

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload) + '\n');
    });

  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found\n');
  }
});

server.listen(CSP_PORT, '0.0.0.0', () => {
  // Use stderr so this line does not pollute JSON API responses.
  process.stderr.write(`[CSP] adapter ready on port ${CSP_PORT}\n`);
});

// Graceful shutdown: disconnect inspector session when process exits.
process.on('SIGTERM', () => {
  server.close();
  session.post('Profiler.stopPreciseCoverage', () => {
    session.disconnect();
  });
});
