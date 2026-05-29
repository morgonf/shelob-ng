package corpus

import (
	"sync"
	"time"
)

const (
	// maxCorpusSize is the hard cap on the total number of entries across all
	// per-operation sub-corpora. When reached, the globally weakest non-seed
	// entry is evicted.
	maxCorpusSize = 15_000
)

// CorpusManager is the interface used by run/, mutator/, and coverage/.
// Intentionally minimal: only the operations other packages actually need.
type CorpusManager interface {
	// Add stores entry if it brought new coverage (delta > 0) and is not
	// a duplicate (by content hash). Returns true when the entry was stored.
	// When the corpus is full, the weakest existing entry is evicted first.
	Add(entry *CorpusEntry, delta uint64) bool

	// Select picks one entry by per-operation round-robin + weighted random
	// selection within the chosen operation's sub-corpus.
	// Returns nil only when the corpus is completely empty.
	Select() *CorpusEntry

	// Size returns the current number of stored entries.
	Size() int

	// Save persists the entire corpus to dir as JSON files.
	Save(dir string) error

	// Load reads corpus entries from dir.
	Load(dir string) error
}

// opKey returns the key used to identify a per-operation sub-corpus.
func opKey(e *CorpusEntry) string {
	return e.Method + "\x00" + e.PathPattern
}

// subCorpus holds the entries for one API operation.
type subCorpus struct {
	seeds   []*CorpusEntry // Generation == 0; never evicted
	mutated []*CorpusEntry // Generation > 0; eligible for eviction
}

func (s *subCorpus) all() []*CorpusEntry {
	out := make([]*CorpusEntry, 0, len(s.seeds)+len(s.mutated))
	out = append(out, s.seeds...)
	out = append(out, s.mutated...)
	return out
}

func (s *subCorpus) size() int { return len(s.seeds) + len(s.mutated) }

// weightedCorpus is the concrete CorpusManager implementation.
//
// Per-operation round-robin selection prevents high-delta entries for one
// endpoint from starving other operations. Within each operation's sub-corpus,
// weighted random selection still favours high-delta / low-use-count entries.
type weightedCorpus struct {
	mu      sync.Mutex
	byOp    map[string]*subCorpus // per-operation buckets
	opOrder []string              // stable insertion order for round-robin
	rrIdx   int                   // next round-robin position
	hashes  map[string]struct{}   // global dedup across all operations
	total   int                   // total entry count
}

// NewCorpusManager creates an empty corpus ready for use.
func NewCorpusManager() CorpusManager {
	return &weightedCorpus{
		byOp:   make(map[string]*subCorpus),
		hashes: make(map[string]struct{}),
	}
}

// Add stores the entry when it passes the delta and deduplication filters.
func (c *weightedCorpus) Add(entry *CorpusEntry, delta uint64) bool {
	if delta == 0 {
		return false
	}
	entry.CoverageDelta = delta
	entry.AddedAt = time.Now()
	hash := entry.Hash()

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.hashes[hash]; exists {
		return false
	}

	// Evict globally weakest non-seed before adding when at capacity.
	if c.total >= maxCorpusSize {
		c.evictWeakest()
	}

	k := opKey(entry)
	sc, exists := c.byOp[k]
	if !exists {
		sc = &subCorpus{}
		c.byOp[k] = sc
		c.opOrder = append(c.opOrder, k)
	}

	if entry.Generation == 0 {
		sc.seeds = append(sc.seeds, entry)
	} else {
		sc.mutated = append(sc.mutated, entry)
	}

	c.hashes[hash] = struct{}{}
	c.total++
	return true
}

// evictWeakest removes the globally weakest non-seed entry. Called under lock.
// Falls back to evicting the weakest seed if no non-seed entries exist.
func (c *weightedCorpus) evictWeakest() {
	var target *CorpusEntry
	var targetSC *subCorpus
	targetIdx := -1
	weakestW := float64(1 << 62)

	for _, sc := range c.byOp {
		for i, e := range sc.mutated {
			if w := e.Weight(); w < weakestW {
				weakestW = w
				target = e
				targetSC = sc
				targetIdx = i
			}
		}
	}

	if target != nil {
		delete(c.hashes, target.Hash())
		last := len(targetSC.mutated) - 1
		targetSC.mutated[targetIdx] = targetSC.mutated[last]
		targetSC.mutated[last] = nil
		targetSC.mutated = targetSC.mutated[:last]
		c.total--
		return
	}

	// All entries are seeds (unusual) — evict the weakest seed as last resort.
	weakestW = float64(1 << 62)
	for _, sc := range c.byOp {
		for i, e := range sc.seeds {
			if w := e.Weight(); w < weakestW {
				weakestW = w
				target = e
				targetSC = sc
				targetIdx = i
			}
		}
	}
	if target != nil {
		delete(c.hashes, target.Hash())
		last := len(targetSC.seeds) - 1
		targetSC.seeds[targetIdx] = targetSC.seeds[last]
		targetSC.seeds[last] = nil
		targetSC.seeds = targetSC.seeds[:last]
		c.total--
	}
}

// Select picks an entry using per-operation round-robin then weighted selection.
//
// Round-robin ensures every API operation gets mutation opportunities regardless
// of how many high-delta entries a single operation has accumulated — preventing
// high-traffic endpoints from starving low-traffic ones.
//
// Within each operation, mutated entries are preferred over seeds; weighted
// selection favours high-delta and low-use-count entries.
func (c *weightedCorpus) Select() *CorpusEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.total == 0 {
		return nil
	}

	// Advance round-robin, skipping empty operations.
	n := len(c.opOrder)
	for attempt := 0; attempt < n; attempt++ {
		k := c.opOrder[c.rrIdx%n]
		c.rrIdx++
		sc := c.byOp[k]
		if sc == nil || sc.size() == 0 {
			continue
		}

		// Prefer mutated entries over seeds within this operation.
		candidates := sc.mutated
		if len(candidates) == 0 {
			candidates = sc.seeds
		}

		selected := weightedSelect(candidates)
		selected.UseCount++
		return selected
	}

	// Fallback: should not happen; return any available entry.
	for _, sc := range c.byOp {
		if all := sc.all(); len(all) > 0 {
			all[0].UseCount++
			return all[0]
		}
	}
	return nil
}

// Size returns the current number of stored entries.
func (c *weightedCorpus) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}
