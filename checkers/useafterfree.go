package checkers

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"shelob-ng/corpus"

	log "github.com/sirupsen/logrus"
)

// UseAfterFree detects resources that remain accessible after a successful deletion.
//
// Trigger: any DELETE request that returns 2xx (the server claimed success).
// Probe:   issue GET to the same URL with the same auth cookies.
// Finding: GET returns 2xx — the resource was not actually removed.
//
// The name mirrors the memory-safety term: the caller "freed" the resource via
// DELETE but can still "use" it via GET. Common root cause: soft-delete
// implementations that set deleted_at but forget to filter on it in read paths.
//
// RESTler reference: UseAfterFree checker.
type UseAfterFree struct{}

func (UseAfterFree) Name() string { return "UseAfterFree" }

func (UseAfterFree) Check(ctx context.Context, cctx CheckContext, entry *corpus.CorpusEntry, req *http.Request, resp *http.Response, _ []byte) []Finding {
	if entry.Method != "DELETE" {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil // DELETE did not succeed — nothing to probe
	}

	probeURL := req.URL.String()
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		log.Debugf("useafterfree: build probe request: %v", err)
		return nil
	}
	for _, c := range cctx.AuthCookies {
		probe.AddCookie(c)
	}
	ApplyAuth(probe, cctx.APIKey, cctx.Token)

	probeResp, err := cctx.Client.Do(probe)
	if err != nil {
		log.Debugf("useafterfree: probe failed: %v", err)
		return nil
	}
	defer probeResp.Body.Close()
	io.Copy(io.Discard, probeResp.Body) //nolint:errcheck

	if probeResp.StatusCode >= 200 && probeResp.StatusCode < 300 {
		return []Finding{{
			Checker:    "UseAfterFree",
			Severity:   SeverityHigh,
			Title:      "Resource accessible after DELETE",
			Detail:     fmt.Sprintf("DELETE returned %d; subsequent GET returned %d (expected 404)", resp.StatusCode, probeResp.StatusCode),
			Method:     http.MethodGet,
			URL:        probeURL,
			StatusCode:  probeResp.StatusCode,
			PathPattern: entry.PathPattern,
			POC:         BuildCurlPOC(probe, nil),
		}}
	}
	return nil
}
