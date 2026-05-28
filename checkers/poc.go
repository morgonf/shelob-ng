package checkers

import (
	"fmt"
	"net/http"
	"strings"

	"shelob-ng/request"
)

// ApplyAuth sets static authentication headers on a probe request.
// Delegates to request.ApplyAuth — the canonical implementation — so that
// checker probes and main-loop requests always use identical auth logic.
func ApplyAuth(req *http.Request, apiKey, token string) {
	request.ApplyAuth(req, apiKey, token)
}

// BuildCurlPOC generates a minimal curl command that reproduces req.
// Only security-relevant headers (Cookie, Authorization, Content-Type) are
// included so the output stays readable. Body is truncated at 400 bytes.
func BuildCurlPOC(req *http.Request, body []byte) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "curl -v -X %s '%s'", req.Method, req.URL.String())

	// Include headers that affect auth and content negotiation.
	for _, name := range []string{"Cookie", "Authorization", "Content-Type", "Accept"} {
		if v := req.Header.Get(name); v != "" {
			fmt.Fprintf(&sb, " \\\n  -H '%s: %s'", name, shellEscape(v))
		}
	}

	// Include body for state-changing methods.
	if len(body) > 0 {
		snippet := body
		truncated := false
		if len(snippet) > 400 {
			snippet = snippet[:400]
			truncated = true
		}
		suffix := ""
		if truncated {
			suffix = "...(truncated)"
		}
		fmt.Fprintf(&sb, " \\\n  --data-binary '%s%s'", shellEscape(string(snippet)), suffix)
	}

	return sb.String()
}

// shellEscape replaces single quotes so the string is safe inside '…'.
func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", `'\''`)
}
