package cliArgs

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Config holds all parsed command-line arguments.
// Returned by ParseCliArgs so callers receive a single struct instead of a
// long positional return list.
type Config struct {
	// Core options (present in original Shelob)
	Spec        string
	TargetURL   string
	Username    string
	Password    string
	ApiKey      string
	Token       string
	OutputDir   string
	Detailed    bool
	Duration    time.Duration
	ExtraArgs   []string
	EnableDebug bool
	RPS         int

	// Coverage Sidecar Protocol (new)
	CSPUrl     string // base URL of the CSP endpoint, e.g. "http://localhost:8080"
	CSPDisable bool   // disable coverage feedback (pure-random mode, original Shelob behaviour)

	// Corpus (new)
	CorpusDir string // directory for corpus persistence; empty = in-memory only

	// Security payloads (new)
	// Format: "sqli=/path/to/sqli.txt,xss=/path/to/xss.txt"
	Payloads string

	// Checkers (new)
	// Comma-separated list of checker names to enable.
	// Empty string means all checkers are enabled.
	Checker string

	// Second user for NameSpaceRule / BOLA detection (new)
	User2 string
	Pass2 string

	// SarifOut is the path for the SARIF 2.1.0 output file.
	// Empty string disables SARIF output.
	SarifOut string

	// NoColor disables ANSI escape codes in the status display.
	// Set automatically when NO_COLOR env var is set or TERM=dumb.
	NoColor bool
}

// ParseCliArgs parses os.Args and returns a populated Config.
// Exits the process on missing required flags.
func ParseCliArgs() Config {
	spec := flag.String("spec", "", "OpenAPI file specification (JSON or YAML format, required)")
	targetURL := flag.String("url", "", "target URL (overrides spec servers[])")
	username := flag.String("user", "", "username for Basic auth / cookie login")
	password := flag.String("password", "", "password for Basic auth / cookie login")
	apikey := flag.String("apikey", "", "API key for authentication")
	token := flag.String("token", "", "Bearer token for authentication")
	outputDir := flag.String("output", "fuzzer_output", "output directory for findings and logs")
	detailedOutput := flag.Bool("detailed", false, "include successful test cases in logs")
	duration := flag.Duration("duration", time.Hour, "fuzzing duration (e.g. 30m, 2h)")
	enableDebug := flag.Bool("debug", false, "enable debug-level logging")
	rps := flag.Int("rps", 0, "requests per second limit (0 = unlimited)")

	// New flags
	noColor := flag.Bool("no-color", false, "disable ANSI colors in output (auto-set when NO_COLOR env var is present or TERM=dumb)")
	cspURL := flag.String("csp-url", "", "Coverage Sidecar Protocol base URL (e.g. http://localhost:8080); empty disables coverage feedback")
	cspDisable := flag.Bool("csp-disable", false, "disable coverage feedback (run in pure-random mode)")
	corpusDir := flag.String("corpus-dir", "", "directory for corpus persistence; empty = in-memory only")
	payloads := flag.String("payloads", "", "security payload files as key=path pairs (e.g. sqli=/tmp/sqli.txt,xss=/tmp/xss.txt)")
	checker := flag.String("checker", "", "comma-separated checkers to enable (empty = all); valid names: BehavioralPatterns,UseAfterFree,InvalidDynamicObject,LeakageRule,NameSpaceRule,BFLA,AuthBypassRule,SchemaViolation,RateLimitChecker")
	user2 := flag.String("user2", "", "second user for BOLA/NameSpaceRule checker")
	pass2 := flag.String("pass2", "", "second user password for BOLA/NameSpaceRule checker")
	sarifOut := flag.String("sarif", "", "write SARIF 2.1.0 report to this path (e.g. results.sarif)")

	flag.Parse()

	if *spec == "" {
		flag.PrintDefaults()
		log.Fatal("provide -spec <openapi-file>")
	}

	if *targetURL == "" {
		log.Info("no -url provided; will use server URLs from the OpenAPI spec")
	}

	validateSpecFileExtension(*spec)

	// Strip trailing slash from target URL.
	re := regexp.MustCompile("/$")
	if re.FindString(*targetURL) != "" {
		*targetURL = re.ReplaceAllString(*targetURL, "")
	}

	log.Info("[+++] CLI arguments parsed")

	return Config{
		Spec:        *spec,
		TargetURL:   *targetURL,
		Username:    *username,
		Password:    *password,
		ApiKey:      *apikey,
		Token:       *token,
		OutputDir:   *outputDir,
		Detailed:    *detailedOutput,
		Duration:    *duration,
		ExtraArgs:   flag.Args(),
		EnableDebug: *enableDebug,
		RPS:         *rps,

		CSPUrl:     *cspURL,
		CSPDisable: *cspDisable,
		CorpusDir:  *corpusDir,
		Payloads:   *payloads,
		Checker:    *checker,
		User2:    *user2,
		Pass2:    *pass2,
		SarifOut: *sarifOut,
		NoColor:  *noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb",
	}
}

// validateSpecFileExtension checks for a supported OpenAPI file extension.
func validateSpecFileExtension(specFile string) {
	ext := strings.ToLower(filepath.Ext(specFile))
	if ext != ".json" && ext != ".yaml" && ext != ".yml" {
		log.Fatalf("unsupported spec extension %q; use .json, .yaml, or .yml", ext)
	}
}
