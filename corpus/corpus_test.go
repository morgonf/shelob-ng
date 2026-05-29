package corpus

import (
	"testing"
)

func TestAdd_ZeroDeltaRejected(t *testing.T) {
	c := NewCorpusManager()
	e := makeEntry("GET", "/x", nil, nil)
	if c.Add(e, 0) {
		t.Error("Add with delta=0 should return false")
	}
	if c.Size() != 0 {
		t.Error("corpus should be empty after rejected Add")
	}
}

func TestAdd_PositiveDeltaAccepted(t *testing.T) {
	c := NewCorpusManager()
	e := makeEntry("GET", "/x", nil, nil)
	if !c.Add(e, 1) {
		t.Error("Add with delta=1 should return true")
	}
	if c.Size() != 1 {
		t.Errorf("expected size 1, got %d", c.Size())
	}
}

func TestAdd_DuplicateRejected(t *testing.T) {
	c := NewCorpusManager()
	e1 := makeEntry("GET", "/x", nil, nil)
	e2 := makeEntry("GET", "/x", nil, nil) // same content → same hash

	c.Add(e1, 1)
	if c.Add(e2, 5) {
		t.Error("duplicate entry should be rejected")
	}
	if c.Size() != 1 {
		t.Errorf("expected size 1 after duplicate, got %d", c.Size())
	}
}

func TestAdd_SetsMetrics(t *testing.T) {
	c := NewCorpusManager()
	e := makeEntry("POST", "/users", nil, nil)
	c.Add(e, 42)
	if e.CoverageDelta != 42 {
		t.Errorf("Add should set CoverageDelta=42, got %d", e.CoverageDelta)
	}
	if e.AddedAt.IsZero() {
		t.Error("Add should set AddedAt")
	}
}

func TestSelect_EmptyCorpusReturnsNil(t *testing.T) {
	c := NewCorpusManager()
	if c.Select() != nil {
		t.Error("Select on empty corpus should return nil")
	}
}

func TestSelect_IncrementsUseCount(t *testing.T) {
	c := NewCorpusManager()
	e := makeEntry("GET", "/x", nil, nil)
	c.Add(e, 1)

	sel := c.Select()
	if sel == nil {
		t.Fatal("Select returned nil on non-empty corpus")
	}
	if sel.UseCount != 1 {
		t.Errorf("Select should increment UseCount to 1, got %d", sel.UseCount)
	}
}

func TestSelect_PrefersGenerationAboveZero(t *testing.T) {
	c := NewCorpusManager()

	seed := makeEntry("GET", "/seed", nil, nil)
	seed.Generation = 0
	c.Add(seed, 1)

	for i := 0; i < 20; i++ {
		mut := makeEntry("GET", "/seed", map[string]interface{}{"x": int64(i)}, nil)
		mut.Generation = 1
		c.Add(mut, 2)
	}

	// Run 100 selections — all should prefer Generation>0 entries.
	nonSeed := 0
	for i := 0; i < 100; i++ {
		sel := c.Select()
		if sel.Generation > 0 {
			nonSeed++
		}
	}
	if nonSeed < 95 {
		t.Errorf("expected mostly Generation>0 selections, got %d/100", nonSeed)
	}
}

func TestSelect_FallsBackToSeeds(t *testing.T) {
	c := NewCorpusManager()
	seed := makeEntry("GET", "/x", nil, nil)
	seed.Generation = 0
	c.Add(seed, 1)

	sel := c.Select()
	if sel == nil {
		t.Error("Select should fall back to seeds when no mutated entries exist")
	}
}

// TestSelect_RoundRobinAcrossOperations verifies that Select distributes
// picks evenly across operations even when one has many more entries.
func TestSelect_RoundRobinAcrossOperations(t *testing.T) {
	c := NewCorpusManager()

	// Add 10 entries for GET /users and 1 entry for POST /orders.
	for i := 0; i < 10; i++ {
		e := makeEntry("GET", "/users", map[string]interface{}{"id": int64(i)}, nil)
		e.Generation = 1
		c.Add(e, 1)
	}
	orderEntry := makeEntry("POST", "/orders", nil, []byte(`{"item":"x"}`))
	orderEntry.Generation = 1
	c.Add(orderEntry, 1)

	// Over 100 selections, each operation should be chosen roughly half the time.
	counts := map[string]int{}
	for i := 0; i < 100; i++ {
		e := c.Select()
		counts[e.Method+" "+e.PathPattern]++
	}

	usersCount := counts["GET /users"]
	ordersCount := counts["POST /orders"]

	// With 2 operations round-robin, each should get ~50 picks.
	// Allow ±15 for randomness within each bucket.
	if usersCount < 35 || usersCount > 65 {
		t.Errorf("GET /users: expected ~50 selections, got %d (orders: %d)", usersCount, ordersCount)
	}
	if ordersCount < 35 || ordersCount > 65 {
		t.Errorf("POST /orders: expected ~50 selections, got %d (users: %d)", ordersCount, usersCount)
	}
}

// addDirect inserts entry directly into wc without delta/dedup checks.
// Used by tests that need to inspect internal eviction behaviour.
func addDirect(wc *weightedCorpus, e *CorpusEntry) {
	k := opKey(e)
	if wc.byOp[k] == nil {
		wc.byOp[k] = &subCorpus{}
		wc.opOrder = append(wc.opOrder, k)
	}
	// All test entries have Generation > 0 (or we set it) to make them evictable.
	if e.Generation == 0 {
		e.Generation = 1
	}
	wc.byOp[k].mutated = append(wc.byOp[k].mutated, e)
	wc.hashes[e.Hash()] = struct{}{}
	wc.total++
}

func TestEvictWeakest_RemovesLowestWeight(t *testing.T) {
	wc := &weightedCorpus{
		byOp:   make(map[string]*subCorpus),
		hashes: make(map[string]struct{}),
	}

	weak := makeEntry("GET", "/weak", map[string]interface{}{"id": int64(1)}, nil)
	weak.CoverageDelta = 1
	weak.UseCount = 100 // high useCount → low weight

	medium := makeEntry("GET", "/medium", map[string]interface{}{"id": int64(2)}, nil)
	medium.CoverageDelta = 5
	medium.UseCount = 1

	strong := makeEntry("GET", "/strong", map[string]interface{}{"id": int64(3)}, nil)
	strong.CoverageDelta = 50
	strong.UseCount = 0

	for _, e := range []*CorpusEntry{weak, medium, strong} {
		addDirect(wc, e)
	}

	wc.evictWeakest()

	if wc.total != 2 {
		t.Fatalf("expected 2 entries after eviction, got %d", wc.total)
	}
	for _, sc := range wc.byOp {
		for _, e := range sc.all() {
			if e.PathPattern == "/weak" {
				t.Error("weakest entry (/weak) was not evicted")
			}
		}
	}
}

func TestEvictWeakest_RemovesHashFromIndex(t *testing.T) {
	wc := &weightedCorpus{
		byOp:   make(map[string]*subCorpus),
		hashes: make(map[string]struct{}),
	}
	e := makeEntry("GET", "/x", nil, nil)
	e.CoverageDelta = 1
	h := e.Hash()

	addDirect(wc, e)
	wc.evictWeakest()

	if _, exists := wc.hashes[h]; exists {
		t.Error("evicted entry's hash should be removed from hashes index")
	}
}

func TestSize_Concurrent(t *testing.T) {
	c := NewCorpusManager()
	done := make(chan struct{})

	go func() {
		for i := 0; i < 50; i++ {
			e := makeEntry("GET", "/x", map[string]interface{}{"i": int64(i)}, nil)
			c.Add(e, 1)
		}
		close(done)
	}()

	// Reading Size() concurrently with Add() must not race.
	for i := 0; i < 20; i++ {
		_ = c.Size()
	}
	<-done
}
