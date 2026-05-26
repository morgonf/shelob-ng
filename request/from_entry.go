package request

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"shelob-ng/corpus"
)

// FromCorpusEntry builds an *http.Request from a CorpusEntry.
// It substitutes path parameters into the PathPattern template,
// encodes query parameters, sets all headers and cookies, and
// attaches the body if present.
//
// targetURL is the base URL of the target (e.g. "http://localhost:3000").
// authCookies are the session cookies obtained during login; they are
// appended after any per-entry cookie parameters.
func FromCorpusEntry(
	entry *corpus.CorpusEntry,
	targetURL string,
	authCookies []*http.Cookie,
) (*http.Request, error) {
	// Substitute {param} placeholders in the path template.
	resolvedPath := resolvePath(entry.PathPattern, entry.PathParams)
	fullURL := targetURL + resolvedPath

	// Build query string.
	if len(entry.QueryParams) > 0 {
		fullURL += "?" + encodeQueryParams(entry.QueryParams)
	}

	var bodyReader *bytes.Reader
	if len(entry.Body) > 0 {
		bodyReader = bytes.NewReader(entry.Body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(entry.Method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("from_entry: build request %s %s: %w", entry.Method, fullURL, err)
	}

	// Set content type and accept headers.
	if entry.ContentType != "" {
		req.Header.Set("Content-Type", entry.ContentType)
		req.Header.Set("Accept", entry.ContentType)
	}

	// Apply per-entry header parameters.
	for k, v := range entry.HeaderParams {
		req.Header.Set(k, v)
	}

	// Apply per-entry cookie parameters.
	for k, v := range entry.CookieParams {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	// Append session cookies from the auth login step.
	for _, c := range authCookies {
		req.AddCookie(c)
	}

	return req, nil
}

// resolvePath substitutes {paramName} placeholders in a path template
// with the corresponding values from pathParams.
// Example: "/users/{id}" + {"id": 42} → "/users/42"
// Uses strings.ReplaceAll (no regex needed: braces are literal delimiters,
// not a pattern), which avoids per-call regexp compilation overhead.
func resolvePath(pattern string, params map[string]interface{}) string {
	result := pattern
	for key, val := range params {
		result = strings.ReplaceAll(result, "{"+key+"}", fmt.Sprintf("%v", val))
	}
	return result
}

// encodeQueryParams serialises a map[string]string into a percent-encoded
// URL query string. url.Values.Encode() handles special characters (spaces,
// &, =, %) correctly and sorts keys for deterministic output.
func encodeQueryParams(params map[string]string) string {
	vals := make(url.Values, len(params))
	for k, v := range params {
		vals.Set(k, v)
	}
	return vals.Encode()
}
