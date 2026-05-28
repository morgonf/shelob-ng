package corpus

import (
	"sync"
	"time"
)

const (
	// maxCorpusSize is the hard cap on the number of entries.
	// When the corpus is full, the entry with the lowest weight is evicted
	// to make room. AFL uses ~10 000; we use 15 000 for broader coverage.
	maxCorpusSize = 15_000
)

// CorpusManager is the interface used by run/, mutator/, and coverage/.
// Intentionally minimal: only the operations other packages actually need.
type CorpusManager interface {
	// Add stores entry if it brought new coverage (delta > 0) and is not
	// a duplicate (by content hash). Returns true when the entry was stored.
	// When the corpus is full, the weakest existing entry is evicted first.
	Add(entry *CorpusEntry, delta uint64) bool

	// Select picks one entry by weighted random selection and increments its
	// UseCount. Prefers mutated entries (Generation > 0) over seeds; falls
	// back to seeds when no mutated entries exist.
	// Returns nil only when the corpus is completely empty.
	Select() *CorpusEntry

	// Size returns the current number of stored entries.
	Size() int

	// Save persists the entire corpus to dir as JSON files.
	// Safe to call concurrently with Add/Select.
	Save(dir string) error

	// Load reads corpus entries from dir. Call before fuzzing starts;
	// not safe to call concurrently with Add/Select.
	Load(dir string) error
}

// weightedCorpus is the concrete implementation of CorpusManager.
// All mutable state is protected by mu.
type weightedCorpus struct {
	mu      sync.RWMutex
	entries []*CorpusEntry
	hashes  map[string]struct{} // O(1) duplicate detection
}

// NewCorpusManager creates an empty corpus ready for use.
func NewCorpusManager() CorpusManager {
	return &weightedCorpus{
		hashes: make(map[string]struct{}),
	}
}

// Add stores the entry when it passes the delta and deduplication filters.
// Thread-safe; acquires a write lock only when actually storing.
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

	// Evict the weakest entry when at capacity to stay within maxCorpusSize.
	if len(c.entries) >= maxCorpusSize {
		c.evictWeakest()
	}

	c.entries = append(c.entries, entry)
	c.hashes[hash] = struct{}{}
	return true
}

// evictWeakest removes the entry with the lowest weight. Called under write lock.
// Seed entries (Generation == 0) are never evicted: they are the only guarantee
// that every seeded API operation remains reachable throughout a long run. Without
// this protection, low-delta seeds for rarely-visited endpoints get displaced by
// high-delta mutated entries after the corpus hits capacity, making those
// endpoints permanently unreachable.
func (c *weightedCorpus) evictWeakest() {
	if len(c.entries) == 0 {
		return
	}

	weakestIdx := -1
	weakestW := float64(1<<62)
	for i, e := range c.entries {
		if e.Generation == 0 {
			continue // never evict seeds
		}
		if w := e.Weight(); w < weakestW {
			weakestW = w
			weakestIdx = i
		}
	}

	// If every entry is a seed (unusual but possible at startup), fall back to
	// evicting the weakest seed so the corpus never deadlocks at capacity.
	if weakestIdx == -1 {
		weakestIdx = 0
		weakestW = c.entries[0].Weight()
		for i, e := range c.entries[1:] {
			if w := e.Weight(); w < weakestW {
				weakestW = w
				weakestIdx = i + 1
			}
		}
	}

	evicted := c.entries[weakestIdx]
	delete(c.hashes, evicted.Hash())
	c.entries[weakestIdx] = c.entries[len(c.entries)-1]
	c.entries[len(c.entries)-1] = nil
	c.entries = c.entries[:len(c.entries)-1]
}

// Select picks an entry by weighted random selection.
// Prefers entries with Generation > 0 (mutated) over seeds (Generation == 0).
// Falls back to seeds when no mutated entries exist.
func (c *weightedCorpus) Select() *CorpusEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) == 0 {
		return nil
	}

	// Separate seeds from mutated entries for preferential selection.
	mutated := make([]*CorpusEntry, 0, len(c.entries))
	seeds := make([]*CorpusEntry, 0)
	for _, e := range c.entries {
		if e.Generation > 0 {
			mutated = append(mutated, e)
		} else {
			seeds = append(seeds, e)
		}
	}

	candidates := mutated
	if len(candidates) == 0 {
		candidates = seeds
	}

	selected := weightedSelect(candidates)
	selected.UseCount++
	return selected
}

// Size returns the current number of stored entries. Thread-safe.
func (c *weightedCorpus) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
