package pathscan

import "strings"

// builtinPaths returns the built-in list of sensitive paths to probe.
// Organised by category; paths are tried unauthenticated.
func builtinPaths() []Candidate {
	return []Candidate{
		// Debug / development
		{"/debug", "application debug endpoint"},
		{"/api/debug", "application debug endpoint"},
		{"/_debug", "application debug endpoint"},
		{"/v1/debug", "versioned debug endpoint"},
		{"/v2/debug", "versioned debug endpoint"},
		{"/console", "development console"},
		{"/test", "test endpoint"},

		// Environment / config leakage
		{"/env", "environment variables dump"},
		{"/.env", "dotenv file"},
		{"/config", "configuration dump"},
		{"/v1/info", "app info (v1 may expose more than v2)"},
		{"/v2/info", "app info"},
		{"/info", "app info / Spring Actuator"},
		{"/api/info", "api info"},
		{"/status", "status endpoint"},
		{"/api/status", "api status"},

		// Spring Boot Actuator (Java)
		{"/actuator", "Spring Actuator index"},
		{"/actuator/env", "Spring Actuator: full environment"},
		{"/actuator/beans", "Spring Actuator: all beans"},
		{"/actuator/mappings", "Spring Actuator: URL mappings"},
		{"/actuator/heapdump", "Spring Actuator: heap dump"},
		{"/actuator/health", "Spring Actuator: health"},
		{"/actuator/metrics", "Spring Actuator: metrics"},
		{"/actuator/loggers", "Spring Actuator: log levels"},
		{"/actuator/httptrace", "Spring Actuator: HTTP trace"},

		// Metrics / monitoring
		{"/metrics", "Prometheus metrics"},
		{"/api/metrics", "API metrics"},
		{"/health", "health check"},
		{"/healthz", "Kubernetes health check"},
		{"/readyz", "Kubernetes readiness"},
		{"/livez", "Kubernetes liveness"},

		// Admin interfaces
		{"/admin", "admin panel"},
		{"/admin/users", "admin user management"},
		{"/admin/debug", "admin debug"},
		{"/admin/stats", "admin statistics"},
		{"/admin/config", "admin configuration"},
		{"/admin/reset-chef-password", "admin password reset (DVRestaurant)"},
		{"/api/admin", "admin API"},
		{"/management", "management endpoint"},
		{"/internal", "internal endpoint"},
		{"/private", "private endpoint"},
		{"/backoffice", "back office endpoint"},

		// Hidden API versions
		{"/v1/users", "v1 users (may differ from v2 in auth)"},
		{"/api/v1/users", "api v1 users"},

		// Target-specific hidden endpoints (from vuln catalogue)
		{"/delivery/orders", "delivery orders (DVRestaurant hidden endpoint)"},
		{"/users/v1/_debug", "VAmPI debug: exposes all passwords"},
		{"/api/users/debug", "user debug endpoint"},
		{"/exports", "data export endpoint"},
		{"/dump", "data dump endpoint"},

		// Security disclosure
		{"/.well-known/security.txt", "security policy"},
		{"/security.txt", "security policy"},

		// GraphQL
		{"/graphql", "GraphQL endpoint"},
		{"/graphiql", "GraphQL IDE"},
		{"/api/graphql", "GraphQL API"},

		// File server / backups
		{"/ftp", "FTP-style file server"},
		{"/backup", "backup files"},
		{"/logs", "application logs"},
		{"/support/logs", "support log files"},
	}
}

// ParseWordlistLine parses one line from a user-provided wordlist file.
// Lines starting with '#' are comments. Each non-empty line is a path,
// optionally followed by a tab and a description.
// Returns (Candidate{}, false) for blank or comment lines.
func ParseWordlistLine(line string) (Candidate, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return Candidate{}, false
	}
	parts := strings.SplitN(line, "\t", 2)
	path := parts[0]
	desc := "user-supplied wordlist entry"
	if len(parts) == 2 && parts[1] != "" {
		desc = strings.TrimSpace(parts[1])
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return Candidate{Path: path, Description: desc}, true
}
