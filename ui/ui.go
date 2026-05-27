// Package ui implements a libfuzzer-style status display for shelob-ng.
//
// Output format (one new line per significant event):
//
//	INFO: spec: juice-shop.openapi.json
//	INFO: target: http://localhost:3000
//	INFO: coverage: disabled (pure-random mode)
//	INFO: corpus: 47 seed entries
//	INFO: checkers: BehavioralPatterns UseAfterFree InvalidDynamicObject LeakageRule SchemaViolation
//
//	#0      INITED   cov:    0  corpus:   47  req/s:    0  2xx:    0  4xx:    0  5xx:    0
//	#2      pulse    cov:    0  corpus:   47  req/s:    3  2xx:    1  4xx:    1  5xx:    0
//	#8      NEW      cov:   12  corpus:   48  req/s:    8  2xx:    5  4xx:    3  5xx:    0  [GET /users/{id} +12]
//	#8      FINDING  cov:   12  corpus:   48  req/s:    8  2xx:    5  4xx:    3  5xx:    0  [UseAfterFree/high] Resource accessible after DELETE
//	#16     pulse    cov:   12  corpus:   48  req/s:   14  2xx:    9  4xx:    7  5xx:    0
//
//	DONE    #10000   cov:  247  corpus:  312  req/s:  27.3  findings:   3  elapsed: 6m10s
//
// Status line key:
//   - INITED  — printed once at startup
//   - NEW     — new coverage found (corpus grew); shows endpoint and delta
//   - pulse   — periodic heartbeat every 3 s (also at powers of 2)
//   - FINDING — security issue detected by a checker (always printed)
//   - DONE    — printed once at shutdown
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI escape codes — only emitted when noColor is false.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// pulseEvery controls the minimum interval between timed "pulse" lines.
// Powers-of-2 heartbeats fill in the gaps between timed pulses.
const pulseEvery = 3 * time.Second

// Logger writes libfuzzer-style status lines. All methods are safe for
// concurrent use from the fuzzing goroutine.
type Logger struct {
	mu      sync.Mutex
	out     io.Writer
	noColor bool

	// running totals updated by Request()
	n          int64 // total requests sent
	coverage   int   // cumulative new coverage lines (sum of per-request deltas)
	corpusSize int
	findings   int
	s2xx       int64
	s4xx       int64
	s5xx       int64

	// API spec coverage: updated by UpdateOps()
	opsVisited int
	opsTotal   int

	startTime time.Time
	lastPrint time.Time
}

// New creates a Logger writing to w.
// Pass nil to default to os.Stdout.
// noColor disables all ANSI escape codes (useful for log files or CI).
func New(w io.Writer, noColor bool) *Logger {
	if w == nil {
		w = os.Stdout
	}
	return &Logger{
		out:       w,
		noColor:   noColor,
		startTime: time.Now(),
		lastPrint: time.Now(),
	}
}

// UpdateOps updates the API spec coverage counters shown in status lines.
// Call after each Mark() to keep the display current.
func (l *Logger) UpdateOps(visited, total int) {
	l.mu.Lock()
	l.opsVisited = visited
	l.opsTotal = total
	l.mu.Unlock()
}

// Start prints the INFO: preamble and the initial INITED status line.
// Call once before entering the fuzzing loop.
func (l *Logger) Start(spec, target, cspURL string, corpusSize int, checkerNames []string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.corpusSize = corpusSize

	inf := l.colorize(ansiCyan, "INFO:")
	fmt.Fprintf(l.out, "%s spec: %s\n", inf, spec)
	fmt.Fprintf(l.out, "%s target: %s\n", inf, target)
	if cspURL != "" {
		fmt.Fprintf(l.out, "%s coverage: %s (CSP)\n", inf, cspURL)
	} else {
		fmt.Fprintf(l.out, "%s coverage: disabled (pure-random mode)\n", inf)
	}
	fmt.Fprintf(l.out, "%s corpus: %d seed entries\n", inf, corpusSize)
	fmt.Fprintf(l.out, "%s checkers: %s\n", inf, strings.Join(checkerNames, " "))
	fmt.Fprintln(l.out)

	// Print initial INITED line (n=0 before first request).
	l.emit("INITED", ansiCyan, "")
}

// Request updates running totals and conditionally emits a status line.
//
//   - covDelta: coverage lines newly covered by this request (0 when CSP disabled).
//   - corpusSize: current corpus size after attempting to add this entry.
//   - method / pathPattern: endpoint identity shown on NEW lines.
//
// A line is printed when:
//   - covDelta > 0 (NEW event — always shown)
//   - n is a power of 2 (classic libfuzzer heartbeat)
//   - 3 seconds have elapsed since the last printed line
func (l *Logger) Request(statusCode, covDelta, corpusSize int, method, pathPattern string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.n++
	l.coverage += covDelta
	l.corpusSize = corpusSize

	switch {
	case statusCode >= 200 && statusCode < 300:
		l.s2xx++
	case statusCode >= 400 && statusCode < 500:
		l.s4xx++
	case statusCode >= 500:
		l.s5xx++
	}

	isNew := covDelta > 0
	isPow2 := l.n&(l.n-1) == 0 // true iff n is a power of 2
	timedOut := time.Since(l.lastPrint) >= pulseEvery

	if isNew {
		extra := fmt.Sprintf("  [%s %s  +%d]", method, pathPattern, covDelta)
		l.emit("NEW", ansiGreen, extra)
	} else if isPow2 || timedOut {
		l.emit("pulse", ansiDim, "")
	}
}

// Finding increments the finding counter and always emits a FINDING status line.
// url may be empty; it is appended after title when non-empty.
func (l *Logger) Finding(checker, severity, title, url string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.findings++
	extra := fmt.Sprintf("  [%s/%s] %s", checker, severity, title)
	if url != "" {
		extra += "  " + url
	}
	l.emit("FINDING", ansiRed, extra)
}

// Warn emits a WARN: line outside the normal status line format.
// Used for non-fatal errors during fuzzing (e.g. CSP timeouts).
func (l *Logger) Warn(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s %s\n", l.colorize(ansiYellow, "WARN:"), msg)
}

// Done prints the final DONE summary line. Call after the fuzzing loop exits.
func (l *Logger) Done() {
	l.mu.Lock()
	defer l.mu.Unlock()

	elapsed := time.Since(l.startTime)
	rps := 0.0
	if s := elapsed.Seconds(); s > 0 {
		rps = float64(l.n) / s
	}

	opsStr := ""
	if l.opsTotal > 0 {
		pct := 100 * l.opsVisited / l.opsTotal
		opsStr = fmt.Sprintf("  ops: %d/%d (%d%%)", l.opsVisited, l.opsTotal, pct)
	}

	fmt.Fprintln(l.out)
	tag := l.colorize(ansiCyan+ansiBold, "DONE")
	fmt.Fprintf(l.out,
		"%s    #%-8d cov: %5d  corpus: %5d%s  req/s: %5.1f  findings: %3d  elapsed: %v\n",
		tag, l.n, l.coverage, l.corpusSize, opsStr, rps, l.findings,
		elapsed.Round(time.Second),
	)
}

// emit prints one formatted status row. Must be called under l.mu.
func (l *Logger) emit(event, eventColor, extra string) {
	elapsed := time.Since(l.startTime)
	rps := int64(0)
	if s := int64(elapsed.Seconds()); s > 0 {
		rps = l.n / s
	}

	// Left-align #N in 8 chars (matches libfuzzer: "#1      NEW ...").
	nStr := fmt.Sprintf("#%-7d", l.n)

	// Pad event name to 8 chars, then optionally wrap with color codes.
	// Padding must be computed BEFORE adding ANSI codes (codes are zero display-width
	// but have non-zero byte length, which confuses fmt width specifiers).
	evPadded := fmt.Sprintf("%-8s", event)
	evStr := l.colorize(eventColor, evPadded)

	opsStr := ""
	if l.opsTotal > 0 {
		opsStr = fmt.Sprintf("  ops: %3d/%-3d", l.opsVisited, l.opsTotal)
	}

	fmt.Fprintf(l.out,
		"%s %s cov: %5d  corpus: %5d%s  req/s: %5d  2xx: %5d  4xx: %5d  5xx: %5d%s\n",
		nStr, evStr,
		l.coverage, l.corpusSize, opsStr, rps,
		l.s2xx, l.s4xx, l.s5xx,
		extra,
	)
	l.lastPrint = time.Now()
}

// colorize wraps s in ANSI escape codes when color output is enabled.
func (l *Logger) colorize(code, s string) string {
	if l.noColor {
		return s
	}
	return code + s + ansiReset
}
