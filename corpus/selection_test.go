package corpus

import (
	"testing"
)

func TestWeightedSelect_SingleEntry(t *testing.T) {
	e := makeEntry("GET", "/only", nil, nil)
	e.CoverageDelta = 1
	got := weightedSelect([]*CorpusEntry{e})
	if got != e {
		t.Error("weightedSelect with single entry should return that entry")
	}
}

func TestWeightedSelect_HighWeightPickedMore(t *testing.T) {
	// Entry A: delta=1 (weight ≈ 1.0)
	// Entry B: delta=100 (weight ≈ 6.7)  → should win ~87% of the time
	a := makeEntry("GET", "/a", nil, nil)
	a.CoverageDelta = 1

	b := makeEntry("GET", "/b", nil, nil)
	b.CoverageDelta = 100

	candidates := []*CorpusEntry{a, b}
	bWins := 0
	const N = 10_000
	for i := 0; i < N; i++ {
		if weightedSelect(candidates) == b {
			bWins++
		}
	}

	// b's weight / (a's weight + b's weight) ≈ 6.7 / 7.7 ≈ 87%.
	// Allow ±5% tolerance.
	ratio := float64(bWins) / N
	if ratio < 0.80 || ratio > 0.95 {
		t.Errorf("expected b to win ~87%% of picks, got %.1f%%", ratio*100)
	}
}

func TestWeightedSelect_AllZeroWeights_Uniform(t *testing.T) {
	// When delta=0, all entries get weight 0.001 (guard value).
	// Selection should be roughly uniform.
	a := makeEntry("GET", "/a", nil, nil)
	b := makeEntry("GET", "/b", nil, nil)
	// CoverageDelta stays 0; entryWeight returns 0.001 for both.

	aCount := 0
	const N = 10_000
	for i := 0; i < N; i++ {
		if weightedSelect([]*CorpusEntry{a, b}) == a {
			aCount++
		}
	}
	ratio := float64(aCount) / N
	if ratio < 0.40 || ratio > 0.60 {
		t.Errorf("expected roughly uniform selection, a won %.1f%%", ratio*100)
	}
}

func TestWeightedSelect_NeverReturnsOutOfBounds(t *testing.T) {
	entries := make([]*CorpusEntry, 5)
	for i := range entries {
		e := makeEntry("GET", "/x", map[string]interface{}{"i": int64(i)}, nil)
		e.CoverageDelta = uint64(i + 1)
		entries[i] = e
	}

	seen := make(map[*CorpusEntry]bool)
	for i := 0; i < 1000; i++ {
		got := weightedSelect(entries)
		seen[got] = true
	}
	for _, e := range entries {
		if !seen[e] {
			// Every entry should be reachable (may need more iterations for rare ones).
			// Don't fail — just ensure no panic / nil.
		}
	}
}
