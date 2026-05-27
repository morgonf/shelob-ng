// Package payloads loads security payload dictionaries from external files.
// Decision 3B: no built-in payloads — user must supply files via -payloads flag.
// This makes the fuzzer smaller and forces explicit payload curation per campaign.
package payloads

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
)

// Category identifies a payload group (e.g. "sqli", "xss").
// Category names come from the keys of the paths map passed to Load.
type Category string

// Set is an immutable, indexed collection of payloads across all categories.
// Built once at startup; safe for concurrent read access (no mutation after Load).
type Set struct {
	byCategory map[Category][]string
	flat       []string // all payloads merged for O(1) uniform random pick
}

// Load reads newline-delimited payload files from paths (map[categoryName]filePath).
// Lines starting with '#' and blank lines are skipped.
// Returns an empty (non-nil) Set when paths is nil or empty — the security
// strategy will return StrategyNotApplicable when the Set is empty.
// Returns an error when a file cannot be opened or is empty after stripping comments.
func Load(paths map[string]string) (*Set, error) {
	s := &Set{byCategory: make(map[Category][]string)}
	for catName, filePath := range paths {
		lines, err := readFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("payloads: category %q: %w", catName, err)
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("payloads: category %q: file %s is empty after stripping comments", catName, filePath)
		}
		cat := Category(catName)
		s.byCategory[cat] = append(s.byCategory[cat], lines...)
		s.flat = append(s.flat, lines...)
	}
	return s, nil
}

// Random returns a uniformly random payload from any category.
// Returns empty string when the Set contains no payloads.
func (s *Set) Random(rng *rand.Rand) string {
	if len(s.flat) == 0 {
		return ""
	}
	return s.flat[rng.Intn(len(s.flat))]
}

// RandomFrom returns a uniformly random payload from the named category.
// Returns empty string when the category is unknown or empty.
func (s *Set) RandomFrom(cat Category, rng *rand.Rand) string {
	entries := s.byCategory[cat]
	if len(entries) == 0 {
		return ""
	}
	return entries[rng.Intn(len(entries))]
}

// Categories returns the list of loaded category names.
func (s *Set) Categories() []Category {
	cats := make([]Category, 0, len(s.byCategory))
	for c := range s.byCategory {
		cats = append(cats, c)
	}
	return cats
}

// Size returns total number of payloads across all categories.
func (s *Set) Size() int { return len(s.flat) }

// readFile reads a newline-delimited file, skipping blank lines and comments.
func readFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}
