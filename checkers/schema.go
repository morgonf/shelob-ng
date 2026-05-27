package checkers

import (
	"context"
	"fmt"
	"net/http"

	"shelob-ng/corpus"

	"github.com/getkin/kin-openapi/openapi3filter"
	log "github.com/sirupsen/logrus"
)

// SchemaViolation validates the actual HTTP response body against the OpenAPI spec.
//
// The original Shelob always passed "{}" as the body to ValidateResponse, which
// caused it to miss all body-content violations (wrong field types, extra/missing
// required fields, undeclared status codes). This checker passes the real body.
//
// Trigger: any completed request+response pair.
// Finding: the response body or status code does not match the declared schema.
//
// Requires OASRouter in CheckContext; skipped when nil (e.g. when -schema-check=false).
type SchemaViolation struct{}

func (SchemaViolation) Name() string { return "SchemaViolation" }

func (SchemaViolation) Check(ctx context.Context, cctx CheckContext, _ *corpus.CorpusEntry, req *http.Request, resp *http.Response, body []byte) []Finding {
	if cctx.OASRouter == nil {
		return nil
	}

	route, pathParams, err := cctx.OASRouter.FindRoute(req)
	if err != nil {
		// Path not found in spec — could be a dynamically resolved path that
		// the router can't match. Not a finding; just skip.
		log.Debugf("schema: FindRoute %s %s: %v", req.Method, req.URL.Path, err)
		return nil
	}

	requestInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			// Skip request body validation here — we are only checking the response.
			ExcludeRequestBody: true,
			// Bypass auth validation: fuzzer may not carry valid credentials.
			AuthenticationFunc: func(_ context.Context, _ *openapi3filter.AuthenticationInput) error {
				return nil
			},
		},
	}

	responseInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestInput,
		Status:                 resp.StatusCode,
		Header:                 resp.Header,
		Options: &openapi3filter.Options{
			ExcludeResponseBody:   false,
			IncludeResponseStatus: true,
			MultiError:            true,
		},
	}
	responseInput.SetBodyBytes(body)

	if err := openapi3filter.ValidateResponse(ctx, responseInput); err != nil {
		return []Finding{{
			Checker:    "SchemaViolation",
			Severity:   SeverityMedium,
			Title:      "Response violates OpenAPI schema",
			Detail:     fmt.Sprintf("%s %s → %d: %v", req.Method, req.URL.Path, resp.StatusCode, err),
			Method:     req.Method,
			URL:        req.URL.String(),
			StatusCode: resp.StatusCode,
		}}
	}
	return nil
}
