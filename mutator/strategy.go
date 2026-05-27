package mutator

import (
	"errors"
	"math/rand"
	"sort"

	"shelob-ng/corpus"
)

// StrategyNotApplicable is returned by Strategy.Apply when the strategy
// cannot act on this particular entry (e.g. ByteLevel on an entry with no body,
// Security when no payloads are loaded). The dispatcher tries the next strategy.
var StrategyNotApplicable = errors.New("strategy not applicable to this entry")

// Strategy is a single mutation algorithm. Implementations must be safe for
// concurrent use.
type Strategy interface {
	// Name returns a short identifier used in logs ("structural", "byte_level", "security").
	Name() string

	// Apply mutates entry in place and returns it.
	// entry is guaranteed to be a Clone() — Apply may modify it freely.
	// Returns StrategyNotApplicable when this strategy cannot act on entry;
	// the dispatcher will try another strategy instead.
	Apply(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error)
}

// weightedStrategy pairs a strategy with its unnormalised selection weight.
type weightedStrategy struct {
	strategy Strategy
	weight   float64
}

// weightedSelector picks strategies by weighted random selection.
// Built once; safe for concurrent use when using an external *rand.Rand under lock.
type weightedSelector struct {
	items      []weightedStrategy
	cumulative []float64 // prefix sums of normalised weights for binary search
}

// newWeightedSelector builds a selector from the provided weighted strategies.
// Panics when items is empty — callers must ensure at least one strategy has weight > 0.
func newWeightedSelector(items []weightedStrategy) *weightedSelector {
	if len(items) == 0 {
		panic("mutator: weightedSelector requires at least one strategy")
	}

	// Compute prefix-sum of weights for O(log n) selection.
	cum := make([]float64, len(items))
	cum[0] = items[0].weight
	for i := 1; i < len(items); i++ {
		cum[i] = cum[i-1] + items[i].weight
	}

	return &weightedSelector{items: items, cumulative: cum}
}

// Pick returns one strategy sampled by weight.
func (ws *weightedSelector) Pick(rng *rand.Rand) Strategy {
	total := ws.cumulative[len(ws.cumulative)-1]
	r := rng.Float64() * total
	idx := sort.SearchFloat64s(ws.cumulative, r)
	if idx >= len(ws.items) {
		idx = len(ws.items) - 1
	}
	return ws.items[idx].strategy
}

// all returns every strategy in the selector (for exhaustive fallback iteration).
func (ws *weightedSelector) all() []Strategy {
	out := make([]Strategy, len(ws.items))
	for i, ws := range ws.items {
		out[i] = ws.strategy
	}
	return out
}
