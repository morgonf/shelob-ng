package corpus

import (
	"math/rand"
	"sort"
)

// weightedSelect picks one entry from candidates using weighted random selection.
//
// Algorithm: prefix-sum + binary search (O(n) build, O(log n) select).
//   1. Build cumulative weight array: cum[i] = sum of weights[0..i].
//   2. Draw r = rand.Float64() * cum[last].
//   3. Binary-search for the first index where cum[i] >= r.
//
// This is equivalent to picking a random point on a number line where each
// entry occupies a segment proportional to its weight.
//
// Called under write lock from Select(), so no additional synchronisation needed.
func weightedSelect(candidates []*CorpusEntry) *CorpusEntry {
	if len(candidates) == 1 {
		return candidates[0]
	}

	// Build prefix-sum of weights.
	cum := make([]float64, len(candidates))
	cum[0] = candidates[0].Weight()
	for i := 1; i < len(candidates); i++ {
		cum[i] = cum[i-1] + candidates[i].Weight()
	}

	total := cum[len(cum)-1]
	if total <= 0 {
		// All weights are zero (degenerate case): uniform random fallback.
		return candidates[rand.Intn(len(candidates))]
	}

	r := rand.Float64() * total

	// Binary search: first index where cum[i] >= r.
	idx := sort.SearchFloat64s(cum, r)
	if idx >= len(candidates) {
		idx = len(candidates) - 1
	}
	return candidates[idx]
}
