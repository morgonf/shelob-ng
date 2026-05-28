package checkers

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"shelob-ng/corpus"
	"shelob-ng/request"

	log "github.com/sirupsen/logrus"
)

// invalidPathValues are boundary and edge-case values substituted for every path
// parameter independently. A well-implemented API should return 400 or 404 for
// these inputs; a 5xx means the server crashed on unexpected input.
var invalidPathValues = []interface{}{
	int64(-1),
	int64(0),
	int64(999_999_999),
	"null",
	"",
}

// InvalidDynamicObject probes path parameters with boundary/edge-case values.
//
// Trigger: any request that has at least one path parameter.
// Probe:   for each path param × each invalid value, send the mutated request.
// Finding: server returns 5xx — the application did not validate the input
//          and crashed instead of returning a proper 400/404.
//
// RESTler reference: InvalidDynamicObject checker, which has historically found
// server crashes in many production REST APIs that omit input validation.
type InvalidDynamicObject struct{}

func (InvalidDynamicObject) Name() string { return "InvalidDynamicObject" }

func (InvalidDynamicObject) Check(ctx context.Context, cctx CheckContext, entry *corpus.CorpusEntry, _ *http.Request, _ *http.Response, _ []byte) []Finding {
	if len(entry.PathParams) == 0 {
		return nil
	}

	var findings []Finding

	for paramName := range entry.PathParams {
		for _, badVal := range invalidPathValues {
			probe := entry.Clone()
			probe.PathParams[paramName] = badVal

			probeReq, err := request.FromCorpusEntry(probe, cctx.TargetURL, cctx.AuthCookies, cctx.APIKey, cctx.Token)
			if err != nil {
				continue
			}
			probeReq = probeReq.WithContext(ctx)

			probeResp, err := cctx.Client.Do(probeReq)
			if err != nil {
				log.Debugf("invaliddyn: probe %s=%v: %v", paramName, badVal, err)
				continue
			}
			io.Copy(io.Discard, probeResp.Body) //nolint:errcheck
			probeResp.Body.Close()

			if probeResp.StatusCode >= 500 {
				findings = append(findings, Finding{
					Checker:    "InvalidDynamicObject",
					Severity:   SeverityMedium,
					Title:      "Server 5xx on invalid path parameter",
					Detail:     fmt.Sprintf("param %q set to %v caused HTTP %d", paramName, badVal, probeResp.StatusCode),
					Method:     probe.Method,
					URL:        probeReq.URL.String(),
					StatusCode:  probeResp.StatusCode,
				PathPattern: entry.PathPattern,
				POC:         BuildCurlPOC(probeReq, nil),
				})
			}
		}
	}
	return findings
}
