'use strict';
/**
 * CSP adapter for OWASP Juice Shop (Node.js 16+).
 *
 * Loaded via NODE_OPTIONS="--require /path/to/adapter.js" before the app starts.
 * Starts a separate HTTP server on CSP_PORT (default 8080) that exposes:
 *
 *   POST /csp/reset    — snapshot current coverage as baseline
 *   GET  /csp/dump     — return lines covered since last reset
 *   GET  /csp/v8report — full accumulated V8 ScriptCoverage (for c8 HTML report)
 *   POST /csp/v8clear  — reset accumulated coverage
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

// callCount + detailed: needed for block-level coverage with hit counts,
// used both for delta detection (count > 0) and c8 HTML report generation.
session.post('Profiler.enable');
session.post('Profiler.startPreciseCoverage', {
  callCount: true,
  detailed:  true,
});

// --- Accumulated V8 ScriptCoverage ---
//
// Stores the running sum of coverage counts across all takePreciseCoverage()
// calls. Keys: scriptId. Values: ScriptCoverage with accumulated counts.
// Consumed by GET /csp/v8report → fed to c8 to produce an HTML report.
const accumulated = new Map();

const SKIP_URL = url =>
  !url
  || url.startsWith('node:')
  || url.includes('node_modules')
  || url.includes('csp/adapter')
  || url.includes('adapter.js');

// fnKey builds a stable identity for a function within a script.
const fnKey = fn => fn.functionName + '\x00' + (fn.ranges[0] ? fn.ranges[0].startOffset : -1);

function mergeIntoAccumulated(results) {
  for (const script of results) {
    if (SKIP_URL(script.url || '')) continue;

    if (!accumulated.has(script.scriptId)) {
      accumulated.set(script.scriptId, {
        scriptId: script.scriptId,
        url:      script.url,
        functions: script.functions.map(fn => ({
          functionName:    fn.functionName,
          isBlockCoverage: fn.isBlockCoverage,
          ranges:          fn.ranges.map(r => ({ startOffset: r.startOffset, endOffset: r.endOffset, count: r.count })),
        })),
      });
      continue;
    }

    const existing = accumulated.get(script.scriptId);
    const fnMap = new Map(existing.functions.map(fn => [fnKey(fn), fn]));

    for (const fn of script.functions) {
      const key = fnKey(fn);
      if (!fnMap.has(key)) {
        existing.functions.push({
          functionName:    fn.functionName,
          isBlockCoverage: fn.isBlockCoverage,
          ranges:          fn.ranges.map(r => ({ startOffset: r.startOffset, endOffset: r.endOffset, count: r.count })),
        });
      } else {
        const ex = fnMap.get(key);
        for (let i = 0; i < fn.ranges.length && i < ex.ranges.length; i++) {
          ex.ranges[i].count += fn.ranges[i].count;
        }
      }
    }
  }
}

// --- Delta snapshot (for /csp/dump) ---

/**
 * Returns the set of "file:offset" strings currently covered by V8,
 * excluding node internals and node_modules.
 * Side-effect: merges raw results into the accumulated coverage map.
 */
function takeCoverageSnapshot(callback) {
  session.post('Profiler.takePreciseCoverage', (err, data) => {
    if (err || !data) {
      return callback(null, new Set());
    }

    mergeIntoAccumulated(data.result);

    const lines = new Set();
    for (const script of data.result) {
      const url = script.url || '';
      if (SKIP_URL(url)) continue;

      let fname = url.replace(/^file:\/\//, '');
      try { fname = path.relative(process.cwd(), fname); } catch (_) {}

      for (const func of script.functions) {
        for (const range of func.ranges) {
          if (range.count > 0) lines.add(`${fname}:${range.startOffset}`);
        }
      }
    }
    callback(null, lines);
  });
}

// --- State ---

let baseline  = new Set();
let totalSeen = new Set();

// --- HTTP server ---

function readBody(req, callback) {
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end',  () => callback(body));
}

const server = http.createServer((req, res) => {

  if (req.method === 'POST' && req.url === '/csp/reset') {
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
        bitmap:          '',
        new_since_reset: newLines,
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload) + '\n');
    });

  } else if (req.method === 'GET' && req.url === '/csp/v8report') {
    // Return accumulated V8 ScriptCoverage in the format expected by c8.
    // Save to a file with:
    //   curl http://localhost:8080/csp/v8report > /tmp/v8cov/coverage-0.json
    // then run:
    //   c8 report --temp-dir /tmp/v8cov --reporter html
    const payload = {
      result:    Array.from(accumulated.values()),
      timestamp: Date.now(),
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload) + '\n');

  } else if (req.method === 'POST' && req.url === '/csp/v8clear') {
    readBody(req, () => {
      accumulated.clear();
      totalSeen.clear();
      baseline = new Set();
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('OK\n');
    });

  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found\n');
  }
});

server.listen(CSP_PORT, '0.0.0.0', () => {
  process.stderr.write(`[CSP] adapter ready on port ${CSP_PORT}\n`);
});

process.on('SIGTERM', () => {
  server.close();
  session.post('Profiler.stopPreciseCoverage', () => session.disconnect());
});
