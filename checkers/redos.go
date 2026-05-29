package checkers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"shelob-ng/corpus"

	log "github.com/sirupsen/logrus"
)

// reDoSProbes are string patterns designed to trigger catastrophic backtracking
// in common vulnerable regular expressions (email, URL, IP, date validators).
var reDoSProbes = []struct {
	short string
	long  string
	hint  string
}{
	{
		short: "a@",
		long:  strings.Repeat("a", 80) + "@",
		hint:  "email validation (common catastrophic backtracking target)",
	},
	{
		short: "aaaaaaaaaa.",
		long:  strings.Repeat("a", 80) + ".",
		hint:  "URL/hostname validation",
	},
	{
		short: "1.1.1.1.1.",
		long:  strings.Repeat("1.", 40),
		hint:  "IP address validation",
	},
}

// reDoS timing thresholds. Both conditions must hold to reduce false positives.
const (
	reDoSTimeRatio   = 5.0                  // long probe must be ≥5× slower than short
	reDoSMinAbsDelay = 500 * time.Millisecond // long probe must be ≥500 ms
	reDoSMaxShort    = 200 * time.Millisecond // short probe must be <200 ms (rule out slow server)
)

// ReDosChecker detects ReDoS (Regular Expression Denial of Service) by comparing
// server response time for a short vs a long input designed for catastrophic
// backtracking.
//
// Detection sequence:
//  1. Find a string-typed parameter in the entry.
//  2. Send a short probe (~10 chars) and record T_short.
//  3. Skip if T_short > reDoSMaxShort (server already slow — too noisy).
//  4. Send a long probe (~80 chars designed for backtracking) and record T_long.
//  5. If T_long > T_short * reDoSTimeRatio AND T_long > reDoSMinAbsDelay → report.
//
// Severity: MEDIUM — ReDoS causes availability impact but no direct data exposure.
type ReDosChecker struct{}

func (ReDosChecker) Name() string { return "ReDoSChecker" }

func (ReDosChecker) Check(
	ctx context.Context,
	cctx CheckContext,
	entry *corpus.CorpusEntry,
	req *http.Request,
	resp *http.Response,
	_ []byte,
) []Finding {
	if resp.StatusCode >= 500 {
		return nil
	}

	targets := collectStringTargets(entry)
	if len(targets) == 0 {
		return nil
	}

	// Test every collected target against every probe pattern.
	// collectStringTargets returns at most 3 candidates; returning on the first
	// confirmed finding avoids sending unnecessary probes.
	for _, target := range targets {
		for _, probe := range reDoSProbes {
			f := testTimingDelta(ctx, cctx, entry, req, target, probe.short, probe.long, probe.hint)
			if f != nil {
				return []Finding{*f}
			}
		}
	}
	return nil
}

func testTimingDelta(
	ctx context.Context,
	cctx CheckContext,
	entry *corpus.CorpusEntry,
	orig *http.Request,
	target rdFieldTarget,
	short, long, hint string,
) *Finding {
	tShort, ok := rdMeasure(ctx, cctx.Client, orig, entry, target, short)
	// tShort == 0 means the clock resolution is finer than the response time;
	// skip to avoid division by zero (float64(x)/0 = +Inf ≥ any threshold).
	if !ok || tShort == 0 || tShort > reDoSMaxShort {
		return nil
	}

	tLong, ok := rdMeasure(ctx, cctx.Client, orig, entry, target, long)
	if !ok {
		return nil
	}

	ratio := float64(tLong) / float64(tShort)
	if ratio < reDoSTimeRatio || tLong < reDoSMinAbsDelay {
		return nil
	}

	return &Finding{
		Checker:  "ReDoSChecker",
		Severity: SeverityMedium,
		Title:    "ReDoS: Catastrophic Regex Backtracking Detected",
		Detail: fmt.Sprintf(
			"field %q: short=%dms long=%dms ratio=%.1fx — %s",
			target.Key, tShort.Milliseconds(), tLong.Milliseconds(), ratio, hint,
		),
		Method:      orig.Method,
		URL:         orig.URL.String(),
		PathPattern: entry.PathPattern,
		POC: fmt.Sprintf(
			"# Trigger ReDoS: replace field %q with long repetitive string\n"+
				"curl -v -X %s '%s' --data-binary '%s'",
			target.Key, orig.Method, orig.URL.String(), long,
		),
	}
}

func rdMeasure(ctx context.Context, client *http.Client, orig *http.Request, entry *corpus.CorpusEntry, t rdFieldTarget, value string) (time.Duration, bool) {
	clone := entry.Clone()
	rdSetField(clone, t, value)

	var bodyReader io.Reader
	if len(clone.Body) > 0 {
		bodyReader = bytes.NewReader(clone.Body)
	}

	req, err := http.NewRequestWithContext(ctx, orig.Method, orig.URL.String(), bodyReader)
	if err != nil {
		log.Debugf("redos: build probe: %v", err)
		return 0, false
	}
	for k, vals := range orig.Header {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if len(clone.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	// Remove any stale Content-Length copied from the original request;
	// Go's HTTP client will compute the correct value from the body.
	req.Header.Del("Content-Length")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return 0, false
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	return elapsed, true
}

type rdFieldKind int

const (
	rdPath rdFieldKind = iota
	rdQuery
	rdBody
)

type rdFieldTarget struct {
	Kind rdFieldKind
	Key  string
}

func collectStringTargets(entry *corpus.CorpusEntry) []rdFieldTarget {
	var targets []rdFieldTarget
	for k, v := range entry.PathParams {
		if _, ok := v.(string); ok {
			targets = append(targets, rdFieldTarget{rdPath, k})
		}
		if len(targets) >= 3 {
			return targets
		}
	}
	for k := range entry.QueryParams {
		targets = append(targets, rdFieldTarget{rdQuery, k})
		if len(targets) >= 3 {
			return targets
		}
	}
	if len(entry.Body) > 0 {
		var obj map[string]interface{}
		if err := json.Unmarshal(entry.Body, &obj); err == nil {
			for k, v := range obj {
				if _, ok := v.(string); ok {
					targets = append(targets, rdFieldTarget{rdBody, k})
					break
				}
			}
		}
	}
	return targets
}

func rdSetField(entry *corpus.CorpusEntry, t rdFieldTarget, value string) {
	switch t.Kind {
	case rdPath:
		entry.PathParams[t.Key] = value
	case rdQuery:
		entry.QueryParams[t.Key] = value
	case rdBody:
		var obj map[string]interface{}
		if err := json.Unmarshal(entry.Body, &obj); err != nil {
			return
		}
		obj[t.Key] = value
		if b, err := json.Marshal(obj); err == nil {
			entry.Body = b
		}
	}
}
