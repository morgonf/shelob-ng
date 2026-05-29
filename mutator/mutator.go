package mutator

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"shelob-ng/corpus"
	"shelob-ng/mutator/payloads"
)

// Mutator is the top-level mutation engine. Implementations must be safe for
// concurrent use by multiple goroutines.
type Mutator interface {
	// Mutate clones entry, applies one mutation strategy, and returns the clone.
	// Falls back through all strategies when the weighted pick returns
	// StrategyNotApplicable. Returns an error only when all strategies fail.
	Mutate(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error)
}

// Config controls the behaviour of the weighted mutator.
type Config struct {
	// Seed for the random number generator. Zero uses time.Now().UnixNano().
	Seed int64

	// Weights for each strategy. Zero uses the defaults documented below.
	ByteLevelWeight  float64
	StructuralWeight float64
	SecurityWeight   float64

	// Payloads for the security strategy.
	// Nil or empty set causes security strategy to return StrategyNotApplicable.
	Payloads *payloads.Set

	// Schema is the pre-built constraint index derived from the OpenAPI spec.
	// When non-nil, the structural strategy uses schema bounds to generate
	// valid boundary values instead of unconstrained edge cases.
	// Nil disables constraint-aware mutation (original behaviour).
	Schema *SchemaIndex
}

// Default strategy weights.
// Structural is weighted highest: it mutates within schema constraints and
// produces more corpus-worthy entries than byte-level noise.
// Byte-level and security share the remaining weight equally.
const (
	defaultByteLevelWeight  = 1.0
	defaultStructuralWeight = 3.0
	defaultSecurityWeight   = 1.0
)

// weightedMutator orchestrates strategy selection and fallback.
// The same *rand.Rand is shared across all three strategies — all mutations
// from one Mutate call are seeded by the same RNG state, which makes
// replay deterministic when Seed is fixed.
type weightedMutator struct {
	selector *weightedSelector
	rng      *rand.Rand
}

// NewMutator builds a Mutator from cfg.
func NewMutator(cfg Config) Mutator {
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // not crypto, deterministic fuzzing

	byteW := cfg.ByteLevelWeight
	if byteW == 0 {
		byteW = defaultByteLevelWeight
	}
	structW := cfg.StructuralWeight
	if structW == 0 {
		structW = defaultStructuralWeight
	}
	secW := cfg.SecurityWeight
	if secW == 0 {
		secW = defaultSecurityWeight
	}

	items := []weightedStrategy{
		{strategy: &byteLevelMutator{rng: rng}, weight: byteW},
		{strategy: &structuralMutator{rng: rng, schema: cfg.Schema}, weight: structW},
		{strategy: &securityMutator{rng: rng, payloads: cfg.Payloads}, weight: secW},
		// SSRF strategy: built-in, no external payload files needed.
		// Low weight (0.5) so it fires on ~10% of mutations when other strategies apply.
		{strategy: &ssrfMutator{rng: rng}, weight: 0.5},
	}

	return &weightedMutator{
		selector: newWeightedSelector(items),
		rng:      rng,
	}
}

// Mutate picks a strategy by weight, clones entry, and applies the mutation.
// When the chosen strategy returns StrategyNotApplicable, it falls back through
// the remaining strategies in insertion order (byte_level → structural → security).
// Any non-NotApplicable error from a strategy is wrapped and returned immediately.
func (m *weightedMutator) Mutate(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error) {
	chosen := m.selector.Pick(m.rng)

	clone := entry.Clone()
	mutated, err := chosen.Apply(clone)
	if err == nil {
		return mutated, nil
	}
	if !errors.Is(err, StrategyNotApplicable) {
		return nil, fmt.Errorf("mutator %s: %w", chosen.Name(), err)
	}

	// Weighted pick failed — try all remaining strategies.
	for _, s := range m.selector.all() {
		if s.Name() == chosen.Name() {
			continue
		}
		clone = entry.Clone() // re-clone: Apply may have partially modified the previous clone
		mutated, err = s.Apply(clone)
		if err == nil {
			return mutated, nil
		}
		if !errors.Is(err, StrategyNotApplicable) {
			return nil, fmt.Errorf("mutator %s: %w", s.Name(), err)
		}
	}

	return nil, fmt.Errorf("mutator: no strategy applicable to entry %s %s",
		entry.Method, entry.PathPattern)
}
