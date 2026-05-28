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
	"crypto/sha256"
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

	// Dependency graph: maps consumer operations to their producers.
	// Used to pre-execute producers before consumers so path params carry real IDs.
	depGraph := sequence.BuildDependencyGraph(spec)

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

		// Producer-consumer: if this entry is a known consumer, pre-execute its
		// producer to obtain a real resource ID and inject it into the path params.
		// This replaces the random/pooled ID with one that actually exists on the
		// server, raising the 2xx rate for CRUD endpoints dramatically.
		if prod, ok := depGraph.ProducerFor(mutated.Method, mutated.PathPattern); ok {
			if id, prodBody, err := executeProducer(httpClient, prod, targetURL, authCookies, cfg.ApiKey, cfg.Token); err == nil {
				mutated.PathParams[prod.ParamName] = id
				pool.Extract(prodBody) // also feed the pool for other consumers
				log.Debugf("run: producer-consumer: bound %s=%v for %s %s", prod.ParamName, id, mutated.Method, mutated.PathPattern)
			} else {
				log.Debugf("run: producer-consumer: %s %s: %v", mutated.Method, mutated.PathPattern, err)
			}
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
			// Use delta (not snap.Delta()) so that API-novelty entries
			// (synthetic delta=1) also fire a NEW event and increment cov:.
			// Without this, corpus growth from first-2xx signals is silent:
			// corpus size grows but cov: stays at 0 and no NEW line appears.
			effectiveDelta = int(delta)
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
				if logSequenceFinding(f, cfg.OutputDir, &seenFindings) {
					display.Finding("Sequence:"+f.SequenceName, f.Severity, f.Title, f.URL)
				}
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

// executeProducer sends the producer request from binding and returns the extracted
// resource ID and raw response body. The ID is typed (int64 or string) so it can
// be assigned directly to corpus.PathParams.
//
// Returns a non-nil error when the producer request fails at the network level,
// returns a non-2xx status, or the IDField is absent from the response JSON.
// On error the caller proceeds with whatever path param was already in the entry.
func executeProducer(
	client *http.Client,
	binding *corpus.ProducerBinding,
	targetURL string,
	authCookies []*http.Cookie,
	apiKey, token string,
) (id interface{}, body []byte, err error) {
	req, err := request.FromCorpusEntry(binding.ProducerEntry.Clone(), targetURL, authCookies, apiKey, token)
	if err != nil {
		return nil, nil, fmt.Errorf("build producer request: %w", err)
	}
	resp, body, err := doRequest(client, req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, body, fmt.Errorf("producer %s %s: status %d", binding.ProducerMethod, binding.ProducerPathPattern, resp.StatusCode)
	}
	id = sequence.ExtractJSONField(body, binding.IDField)
	if id == nil {
		return nil, body, fmt.Errorf("field %q not found in producer response", binding.IDField)
	}
	return id, body, nil
}

// safeFileName converts an arbitrary string into a filesystem-safe name.
// Characters outside [a-zA-Z0-9-] are replaced with '_'. The first 80 bytes
// of the sanitized form are kept for human readability; a 8-character SHA-256
// prefix is appended to guarantee uniqueness even when two keys share those
// first 80 bytes.
func safeFileName(key string) string {
	clean := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '_'
	}, key)
	prefix := clean
	if len(prefix) > 80 {
		prefix = prefix[:80]
	}
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s_%x", prefix, h[:4])
}

// logFinding writes a Finding as a JSON file in outputDir/findings/ if it has
// not been seen before (dedup). Returns true when the finding was new AND written.
//
// Error-handling contract: the dedup key is stored in seen only after both
// MkdirAll and MarshalIndent succeed. On WriteFile failure the key is deleted
// from seen so the finding can be retried on the next occurrence. This ensures
// display.Finding is called only when a JSON file exists on disk.
// seen is a *sync.Map shared across all checker goroutines.
func logFinding(f checkers.Finding, outputDir string, seen *sync.Map) bool {
	dir := filepath.Join(outputDir, "findings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warnf("logFinding: mkdir %s: %v", dir, err)
		return false // key not stored — retryable
	}

	// Marshal before claiming the key: if serialization fails the finding is
	// not suppressed and will be retried on the next occurrence.
	key := f.DedupeKey()
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Warnf("logFinding: marshal: %v", err)
		return false // key not stored — retryable
	}

	if _, loaded := seen.LoadOrStore(key, struct{}{}); loaded {
		return false // duplicate
	}

	path := filepath.Join(dir, safeFileName(key)+".json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Warnf("logFinding: write %s: %v", path, err)
		seen.Delete(key) // release the key so the next occurrence can retry
		return false
	}
	return true
}

// logSequenceFinding writes a sequence.Finding as a JSON file in outputDir/findings/
// if it has not been seen before (dedup). Uses the same seen map as logFinding so
// the dedup is consistent across checker and sequence findings.
// Returns true when the finding was new AND written.
//
// Same error-handling contract as logFinding: marshal before claiming the key;
// delete key on WriteFile failure so the finding can be retried.
func logSequenceFinding(f sequence.Finding, outputDir string, seen *sync.Map) bool {
	dir := filepath.Join(outputDir, "findings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Warnf("logSequenceFinding: mkdir %s: %v", dir, err)
		return false
	}

	// Build the dedup key from the URL path only — strip any query string.
	// f.URL is req.URL.String() from sendStep, which includes the full URL with
	// query parameters. Using the full URL as the key means two sequence runs
	// against the same endpoint but different mutated query strings get different
	// keys and both write separate finding files. Stripping the query string
	// collapses them to one finding per logical (sequence, method, path) tuple.
	baseURL := f.URL
	if idx := strings.IndexByte(f.URL, '?'); idx >= 0 {
		baseURL = f.URL[:idx]
	}
	key := "Sequence:" + f.SequenceName + "\x00" + f.Method + "\x00" + baseURL

	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Warnf("logSequenceFinding: marshal: %v", err)
		return false // key not stored — retryable
	}

	if _, loaded := seen.LoadOrStore(key, struct{}{}); loaded {
		return false // duplicate
	}

	path := filepath.Join(dir, "seq_"+safeFileName(key)+".json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Warnf("logSequenceFinding: write %s: %v", path, err)
		seen.Delete(key)
		return false
	}
	return true
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
