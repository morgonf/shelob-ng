package checkers

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"shelob-ng/corpus"
)

// behavioralPattern is a compiled regex plus metadata about the vulnerability class it detects.
type behavioralPattern struct {
	re       *regexp.Regexp
	title    string
	severity string
	// htmlOnly: skip this pattern when the response Content-Type is not text/html.
	// Used for XSS patterns that produce false positives against JSON endpoints
	// whose payloads contain example XSS strings (challenge descriptions, API docs).
	htmlOnly bool
}

// patterns are ordered from most severe to least. Each pattern targets a common
// class of vulnerability artifacts that leak into HTTP response bodies.
var patterns = []behavioralPattern{
	// SQL errors — indicates the query string reached the database layer unescaped.
	{
		regexp.MustCompile(`(?i)(sql syntax|mysql_fetch_array|mysql_num_rows|ORA-\d{5}|PostgreSQL.*ERROR|pg_query|sqlite_.*error|SQLSTATE\[|Unclosed quotation mark|near ".*": syntax error|You have an error in your SQL|supplied argument is not a valid MySQL)`),
		"SQL Error Leakage", SeverityHigh, false,
	},
	// XSS artifacts — injected script fragments reflected unescaped in HTML.
	// htmlOnly=true: JSON APIs (e.g. challenge lists, API docs) legitimately contain
	// example XSS strings such as javascript:alert('xss') in educational descriptions.
	// <script> pattern excludes tags with a src= attribute to avoid matching framework
	// script imports like <script src="/vendor/beer.min.js"> in SPA shells.
	{
		regexp.MustCompile(`(?i)(<script(?![^>]*\bsrc\s*=)[^>]*>|javascript:\s*alert|onerror\s*=\s*['"(]|onload\s*=\s*['"(]|document\.cookie\s*=|eval\s*\(['"]\s*<)`),
		"XSS Artifact", SeverityHigh, true,
	},
	// Path traversal / LFI — server returned contents of a system file.
	{
		regexp.MustCompile(`(root:x:0:0|/etc/shadow|\[boot loader\]|\[operating systems\]|WINDOWS\\system32)`),
		"Path Traversal / LFI", SeverityHigh, false,
	},
	// Command injection — shell executed injected input and leaked output.
	// uid=…(…) gid=… is the canonical output of the `id` command.
	// sh/bash error lines appear when the shell is invoked but the command
	// is missing or denied — still confirms shell metacharacter processing.
	{
		regexp.MustCompile(`(uid=\d+\(\w+\)\s+gid=\d+|(?:sh|bash|dash|zsh):\s*[\w/.-]+:\s*(?:not found|command not found|Permission denied)|Command '[\w/.-]+' not found)`),
		"Command Injection", SeverityHigh, false,
	},
	// SSTI — template engine evaluated user input ({{7*7}}=49 is the classic canary).
	// Narrow pattern: only match engine-specific artifacts, not plain Mustache/Handlebars templates.
	{
		regexp.MustCompile(`(FreeMarker template error|Error evaluating FTL|freemarker\.template|Velocity error|org\.apache\.velocity|jinja2\.exceptions|TemplateSyntaxError:.*template)`),
		"Server-Side Template Injection", SeverityHigh, false,
	},
	// Go runtime panics — goroutine dumps or runtime errors in the response.
	{
		regexp.MustCompile(`(goroutine \d+ \[running\]|goroutine \d+ \[syscall\]|panic: runtime error|runtime: .*goroutine|SIGABRT|SIGSEGV)`),
		"Go Panic / Stack Trace", SeverityMedium, false,
	},
	// Python exceptions — traceback in the response body.
	{
		regexp.MustCompile(`(Traceback \(most recent call last\):\n|File ".*", line \d+, in |AttributeError: |ImportError: |NameError: '.*' is not defined)`),
		"Python Stack Trace", SeverityMedium, false,
	},
	// Java exceptions — JVM stack trace or Spring/Hibernate error.
	{
		regexp.MustCompile(`(at java\.lang\.|at com\.[a-z]+\.[a-z]+\.|java\.lang\.(NullPointerException|IllegalArgumentException|ClassCastException)|org\.hibernate\.|org\.springframework\.)`),
		"Java Stack Trace", SeverityMedium, false,
	},
	// Node.js runtime errors — V8 stack trace format.
	{
		regexp.MustCompile(`(TypeError: Cannot read propert|ReferenceError: \w+ is not defined|at Object\.<anonymous> \(|at Module\._compile |\.js:\d+:\d+\))`),
		"Node.js Stack Trace", SeverityMedium, false,
	},
}

// BehavioralPatterns scans response bodies for known vulnerability artifact patterns.
// No additional HTTP requests are issued — this is a pure text analysis checker.
//
// Rationale: many production APIs leak database errors, stack traces, or injected
// fragments directly in JSON error fields. Regex matching on every response is
// low-overhead and catches artifacts that schema validation cannot detect.
type BehavioralPatterns struct{}

func (BehavioralPatterns) Name() string { return "BehavioralPatterns" }

func (BehavioralPatterns) Check(_ context.Context, _ CheckContext, entry *corpus.CorpusEntry, req *http.Request, resp *http.Response, body []byte) []Finding {
	if len(body) == 0 {
		return nil
	}

	isHTML := strings.Contains(resp.Header.Get("Content-Type"), "text/html")

	var findings []Finding
	for _, p := range patterns {
		if p.htmlOnly && !isHTML {
			continue
		}
		match := p.re.Find(body)
		if match == nil {
			continue
		}
		// Truncate match to 120 bytes to keep the finding detail readable.
		detail := string(match)
		if len(detail) > 120 {
			detail = detail[:120] + "..."
		}
		findings = append(findings, Finding{
			Checker:    "BehavioralPatterns",
			Severity:   p.severity,
			Title:      p.title,
			Detail:     "pattern matched: " + detail,
			Method:     entry.Method,
			URL:        req.URL.String(),
			StatusCode: resp.StatusCode,
		})
	}
	return findings
}
