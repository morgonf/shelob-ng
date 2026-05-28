// Package run implements the main fuzzing loop for shelob-ng.
//
// The loop is corpus-guided and coverage-aware:
//  1. Select a CorpusEntry by weighted random (higher coverage delta = higher weight)
//  2. Mutate it with one of three strategies (structural / byte-level / security)
//  3. POST /csp/reset to the target's Coverage Sidecar Protocol endpoint
//  4. Send the mutated HTTP request to the target API
//  5. GET /csp/dump to read coverage delta
//  6. If delta > 0 → store entry in corpus for future mutation
//  7. Extract values from response → DynamicValuePool (future path-param reuse)
//  8. Run all enabled checkers and write findings to the output directory
//
// When -csp-url is empty (or -csp-disable is set), coverage feedback is
// disabled and the loop degrades to pure-random mode (original Shelob behaviour).
package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shelob-ng/apicov"
	"shelob-ng/auth"
	"shelob-ng/checkers"
	"shelob-ng/cliArgs"
	"shelob-ng/corpus"
	"shelob-ng/coverage"
	"shelob-ng/logging"
	"shelob-ng/mutator"
	"shelob-ng/mutator/payloads"
	"shelob-ng/openapi"
	"shelob-ng/request"
	"shelob-ng/sequence"
	"shelob-ng/ui"

	"github.com/getkin/kin-openapi/openapi3"
	log "github.com/sirupsen/logrus"
)

// Run is the entry point called from main(). It parses CLI args, bootstraps all
// subsystems, and then runs the fuzzing loop until the duration expires.
func Run() {
	cfg := cliArgs.ParseCliArgs()

	if cfg.EnableDebug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	ctx, spec, routerPtr := openapi.ParseOpenapiSpec(cfg.Spec, cfg.TargetURL)

	// Resolve effective target URL: CLI flag takes precedence, then first server in spec.
	targetURL := cfg.TargetURL
	if targetURL == "" && spec.Servers != nil && len(spec.Servers) > 0 && spec.Servers[0] != nil {
		targetURL = strings.TrimSuffix(spec.Servers[0].URL, "/")
		log.Infof("using target URL from spec: %s", targetURL)
	}
	if targetURL == "" {
		log.Fatal("no target URL: provide -url or add a servers[] entry to the OpenAPI spec")
	}

	// Auth: primary user login.
	loginEndpoint := getLoginEndpoint(spec)
	authCookies := auth.CreateUserWithLoginEndpoint(cfg.Username, cfg.Password, targetURL, loginEndpoint)
	log.Infof("auth: %d session cookie(s) obtained", len(authCookies))

	// Auth: optional second user for BOLA/NameSpaceRule checker.
	var user2Cookies []*http.Cookie
	if cfg.User2 != "" {
		user2Cookies = auth.CreateUserWithLoginEndpoint(cfg.User2, cfg.Pass2, targetURL, loginEndpoint)
		log.Infof("auth (user2): %d session cookie(s) obtained", len(user2Cookies))
	}

	// Corpus: seed from OpenAPI spec, then optionally load persisted entries.
	mgr := corpus.NewCorpusManager()
	seeded, err := corpus.SeedFromSpec(*ctx, spec, mgr, corpus.DefaultSeedOptions())
	if err != nil {
		log.Warnf("corpus seed: %v", err)
	}
	log.Infof("corpus: %d seed entries generated", seeded)

	if cfg.CorpusDir != "" {
		if err := mgr.Load(cfg.CorpusDir); err != nil {
			log.Warnf("corpus load from %s: %v", cfg.CorpusDir, err)
		} else {
			log.Infof("corpus: %d entries total after loading from %s", mgr.Size(), cfg.CorpusDir)
		}
	}

	// Dynamic value pool: accumulates IDs/tokens from responses for path-param reuse.
	pool := corpus.NewDynamicValuePool()

	// Mutator: weighted combination of structural / byte-level / security strategies.
	pls := loadPayloads(cfg.Payloads)
	mut := mutator.NewMutator(mutator.Config{
		Payloads: pls,
	})

	// Coverage client: CSP or no-op when disabled.
	var covClient coverage.Client
	if cfg.CSPDisable || cfg.CSPUrl == "" {
		covClient = coverage.NewClient(coverage.Config{}) // no-op
		log.Info("coverage feedback disabled (pure-random mode)")
	} else {
		covClient = coverage.NewClient(coverage.Config{BaseURL: cfg.CSPUrl})
		log.Infof("coverage feedback enabled: %s", cfg.CSPUrl)
	}

	// HTTP client shared by the main loop and all checkers.
	httpClient := &http.Client{Timeout: 15 * time.Second}

	// Checkers setup.
	checkCtx := checkers.CheckContext{
		Client:       httpClient,
		TargetURL:    targetURL,
		AuthCookies:  authCookies,
		User2Cookies: user2Cookies,
		OASRouter:    *routerPtr,
		APIKey:       cfg.ApiKey,
		Token:        cfg.Token,
	}
	activeCheckers := selectCheckers(cfg.Checker, checkCtx)

	// Sequence runner: stateful CRUD sequences derived from the OpenAPI spec.
	seqs := sequence.BuildSequences(spec)
	seqRunner := &sequence.Runner{
		Client:      httpClient,
		TargetURL:   targetURL,
		AuthCookies: authCookies,
		APIKey:      cfg.ApiKey,
		Token:       cfg.Token,
	}

	// Output directory.
	logging.CreateDir(cfg.OutputDir)

	// API spec coverage tracker: records which spec operations were exercised.
	opTracker := apicov.NewTracker(spec)

	// Status display: libfuzzer-style event-driven output.
	display := ui.New(nil, cfg.NoColor)
	checkerNames := make([]string, len(activeCheckers))
	for i, c := range activeCheckers {
		checkerNames[i] = c.Name()
	}
	display.Start(cfg.Spec, targetURL, cfg.CSPUrl, mgr.Size(), checkerNames)

	// After the display starts, suppress logrus INFO messages so they don't
	// interleave with the status lines on the terminal.
	// In debug mode the user explicitly asked for verbose output, so keep it.
	if !cfg.EnableDebug {
		log.SetLevel(log.WarnLevel)
	}

	// RPS rate limiter.
	var ticker *time.Ticker
	if cfg.RPS > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(cfg.RPS))
		defer ticker.Stop()
	}

	// Checker goroutine pool: checkers run asynchronously so their probe
	// requests don't block the main fuzzing loop. The semaphore caps
	// outstanding goroutines to avoid unbounded memory/connection growth.
	const checkerConcurrency = 8
	checkerSem := make(chan struct{}, checkerConcurrency)
	var checkerWg sync.WaitGroup

	// Dedup set for findings: keyed by Finding.DedupeKey() so the same class
	// of issue on the same endpoint is written exactly once per session.
	// sync.Map is safe for concurrent access from checker goroutines.
	var seenFindings sync.Map

	start := time.Now()
	var seqTick int

	for time.Since(start) < cfg.Duration {
		if ticker != nil {
			<-ticker.C
		}

		entry := mgr.Select()
		if entry == nil {
			log.Warn("run: corpus is empty; waiting for seed entries")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Mutate: clone + apply one strategy. On error fall back to original entry.
		mutated, err := mut.Mutate(entry)
		if err != nil {
			log.Debugf("run: mutate %s %s: %v; using entry as-is", entry.Method, entry.PathPattern, err)
			mutated = entry.Clone()
		}

		// Reset coverage counters before the request.
		if err := covClient.Reset(context.Background()); err != nil {
			log.Debugf("run: CSP reset: %v", err)
		}

		// Build and send the HTTP request.
		req, err := request.FromCorpusEntry(mutated, targetURL, authCookies, cfg.ApiKey, cfg.Token)
		if err != nil {
			log.Debugf("run: build request: %v", err)
			continue
		}

		resp, body, err := doRequest(httpClient, req)
		if err != nil {
			log.Debugf("run: send request: %v", err)
			continue
		}

		// Detect the first 2xx for this operation BEFORE marking so we can use
		// it as a corpus admission signal (see below).
		isFirstSuccess := resp.StatusCode >= 200 && resp.StatusCode < 300 &&
			!opTracker.HasSuccess(mutated.Method, mutated.PathPattern)

		// Mark this operation as visited (any HTTP response counts).
		opTracker.Mark(mutated.Method, mutated.PathPattern, resp.StatusCode)
		opsVisited, opsTotal := opTracker.Stats()
		display.UpdateOps(opsVisited, opsTotal)

		// Dump coverage after the request.
		snap, err := covClient.Dump(context.Background())
		if err != nil {
			log.Debugf("run: CSP dump: %v", err)
		}

		// Determine the effective delta used for corpus admission:
		//   - Primary signal: CSP code coverage delta (new basic blocks since reset).
		//   - Fallback signal: first 2xx for this API operation. Ensures the corpus
		//     grows based on API-level novelty even when CSP is disabled or returns 0.
		//     A synthetic delta of 1 is enough to pass corpus.Add's delta>0 guard;
		//     the entry gets minimum weight and will be superseded by higher-delta
		//     entries once the same endpoint produces real coverage data.
		delta := snap.Delta()
		if isFirstSuccess && delta == 0 {
			delta = 1
		}

		// Add to corpus if coverage increased. Only entries actually stored
		// contribute to the displayed cov counter so NEW lines are not emitted
		// for duplicate mutations that were rejected by the dedup filter.
		mutated.CoverageDelta = delta
		added := mgr.Add(mutated, delta)

		effectiveDelta := 0
		if added {
			effectiveDelta = int(snap.Delta())
		}

		// Feed response values into the dynamic pool for future path-param reuse.
		pool.Extract(body)

		// Update display after every request.
		display.Request(resp.StatusCode, effectiveDelta, mgr.Size(), mutated.Method, mutated.PathPattern)

		// Run all enabled checkers concurrently. Each checker captures its own
		// copies of the per-iteration values; the main loop is free to advance
		// while probes are in flight.
		for _, chk := range activeCheckers {
			chk := chk
			ent, r, rs, b := mutated, req, resp, body
			outDir := cfg.OutputDir

			checkerSem <- struct{}{} // acquire slot; blocks only if 8 goroutines already running
			checkerWg.Add(1)
			go func() {
				defer func() {
					<-checkerSem
					checkerWg.Done()
				}()
				findings := chk.Check(context.Background(), checkCtx, ent, r, rs, b)
				for _, f := range findings {
					if logFinding(f, outDir, &seenFindings) {
						display.Finding(f.Checker, f.Severity, f.Title, f.URL)
					}
				}
			}()
		}

		// Run one CRUD sequence every 20 requests to exercise stateful flows.
		seqTick++
		if len(seqs) > 0 && seqTick%20 == 0 {
			idx := (seqTick/20 - 1) % len(seqs)
			seqFindings, replay := seqRunner.Run(context.Background(), seqs[idx])
			sequence.SaveReplay(replay, cfg.OutputDir)
			for _, f := range seqFindings {
				logSequenceFinding(f, cfg.OutputDir)
				display.Finding("Sequence:"+f.SequenceName, f.Severity, f.Title, f.URL)
			}
		}
	}

	// Wait for all outstanding checker goroutines before printing DONE.
	checkerWg.Wait()
	display.Done()

	// Print and save API spec coverage summary.
	opTracker.Print(os.Stdout)
	covPath := filepath.Join(cfg.OutputDir, "api-coverage.json")
	if err := opTracker.SaveJSON(covPath); err != nil {
		log.Warnf("api-coverage: save %s: %v", covPath, err)
	} else {
		fmt.Printf("API coverage report: %s\n", covPath)
	}

	// Persist corpus if a directory was configured.
	if cfg.CorpusDir != "" {
		if err := mgr.Save(cfg.CorpusDir); err != nil {
			log.Warnf("corpus save to %s: %v", cfg.CorpusDir, err)
		} else {
			log.Infof("corpus saved to %s", cfg.CorpusDir)
		}
	}
}

// doRequest sends req and reads the full response body.
// Returns (nil, nil, err) on network failure.
// The caller owns resp and must not close Body — doRequest already reads and closes it.
func doRequest(client *http.Client, req *http.Request) (*http.Response, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024)) // 4 MiB cap
	if err != nil {
		return resp, body, fmt.Errorf("read body: %w", err)
	}
	return resp, body, nil
}

// logFinding writes a Finding as a JSON file in outputDir/findings/ if it has
// not been seen before (dedup). Returns true when the finding was new and written.
// The file is named by DedupeKey so identical findings overwrite each other
// rather than accumulating. seen is a *sync.Map shared across all checker goroutines.
func logFinding(f checkers.Finding, outputDir string, seen *sync.Map) bool {
	key := f.DedupeKey()
	if _, loaded := seen.LoadOrStore(key, struct{}{}); loaded {
		return false // duplicate
	}

	dir := filepath.Join(outputDir, "findings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warnf("logFinding: mkdir %s: %v", dir, err)
		return true // new finding, even if we can't write it
	}

	// Filename derived from dedup key (checker + method + path) — stable across runs,
	// so re-running the fuzzer overwrites rather than duplicates the same finding.
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '_'
	}, key)
	if len(safe) > 120 {
		safe = safe[:120]
	}
	path := filepath.Join(dir, safe+".json")

	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Warnf("logFinding: marshal: %v", err)
		return true
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Warnf("logFinding: write %s: %v", path, err)
	}
	return true
}

// logSequenceFinding writes a sequence.Finding as a timestamped JSON file.
func logSequenceFinding(f sequence.Finding, outputDir string) {
	dir := filepath.Join(outputDir, "findings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warnf("logSequenceFinding: mkdir %s: %v", dir, err)
		return
	}

	ts := time.Now().Format("20060102_150405_000")
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, f.SequenceName)
	path := filepath.Join(dir, "seq_"+safe+"_"+ts+".json")

	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Warnf("logSequenceFinding: marshal: %v", err)
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Warnf("logSequenceFinding: write %s: %v", path, err)
	}
}

// loadPayloads parses the -payloads flag value ("sqli=/tmp/sqli.txt,xss=/tmp/xss.txt")
// and loads the payload files. Returns nil on empty input (security strategy disabled).
func loadPayloads(flag string) *payloads.Set {
	if flag == "" {
		return nil
	}

	paths := make(map[string]string)
	for _, pair := range strings.Split(flag, ",") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			log.Warnf("payloads: ignoring malformed pair %q (expected key=path)", pair)
			continue
		}
		paths[kv[0]] = kv[1]
	}

	if len(paths) == 0 {
		return nil
	}

	s, err := payloads.Load(paths)
	if err != nil {
		log.Warnf("payloads: load failed: %v", err)
		return nil
	}
	log.Infof("payloads: loaded %d entries across %d categories", s.Size(), len(s.Categories()))
	return s
}

// selectCheckers filters the global checker list by the -checker flag.
// An empty filter string enables all checkers.
// Checkers that require User2Cookies (NameSpaceRule) are automatically
// disabled when no second user is configured, regardless of the filter.
func selectCheckers(filter string, cctx checkers.CheckContext) []checkers.Checker {
	all := checkers.All()

	// Build an allow-set from the comma-separated filter.
	var allowed map[string]bool
	if filter != "" {
		allowed = make(map[string]bool)
		for _, name := range strings.Split(filter, ",") {
			allowed[strings.TrimSpace(name)] = true
		}
	}

	var active []checkers.Checker
	for _, chk := range all {
		if allowed != nil && !allowed[chk.Name()] {
			continue
		}
		// NameSpaceRule needs a second user; skip it if none is configured.
		if chk.Name() == "NameSpaceRule" && len(cctx.User2Cookies) == 0 {
			log.Debug("NameSpaceRule disabled: no -user2 / -pass2 provided")
			continue
		}
		active = append(active, chk)
	}
	return active
}

// getLoginEndpoint finds the login endpoint path in the OpenAPI spec by scanning
// common path patterns and operationIDs. Falls back to a hardcoded default.
// Kept from the original Shelob; no changes needed here.
func getLoginEndpoint(spec *openapi3.T) string {
	loginPatterns := []string{"/login", "/users/login", "/user/login", "/api/login", "/auth/login", "/users/v1/login", "/api/v3/user/login"}

	for path, pathItem := range spec.Paths.Map() {
		if pathItem == nil {
			continue
		}
		lowerPath := strings.ToLower(path)
		for _, pattern := range loginPatterns {
			if strings.Contains(lowerPath, pattern) && pathItem.Post != nil {
				log.Infof("login endpoint detected: %s", path)
				return path
			}
		}
		for method, op := range pathItem.Operations() {
			if op == nil || op.OperationID == "" {
				continue
			}
			id := strings.ToLower(op.OperationID)
			if method == "POST" && (strings.Contains(id, "login") || strings.Contains(id, "authenticate")) {
				log.Infof("login endpoint detected from operationID: %s", path)
				return path
			}
		}
	}

	log.Warn("no login endpoint found in spec; using default /api/v3/user/login")
	return "/api/v3/user/login"
}
