package corpus

import (
	"fmt"
	"testing"
)

func TestExtract_EmptyBody(t *testing.T) {
	p := NewDynamicValuePool()
	p.Extract(nil)
	p.Extract([]byte{})
	if p.Size() != 0 {
		t.Errorf("expected empty pool after empty body, got size %d", p.Size())
	}
}

func TestExtract_NonJSON(t *testing.T) {
	p := NewDynamicValuePool()
	p.Extract([]byte("<html>not json</html>"))
	p.Extract([]byte("plain text"))
	if p.Size() != 0 {
		t.Errorf("expected empty pool after non-JSON bodies, got size %d", p.Size())
	}
}

func TestExtract_FlatObject(t *testing.T) {
	p := NewDynamicValuePool()
	p.Extract([]byte(`{"id":42,"name":"alice","active":true}`))

	if p.Size() == 0 {
		t.Fatal("expected non-empty pool after flat object extraction")
	}
	// id, name, active should all be stored.
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(nonNilValues(p.values["id"])) == 0 {
		t.Error("expected 'id' key in pool")
	}
	if len(nonNilValues(p.values["name"])) == 0 {
		t.Error("expected 'name' key in pool")
	}
	if len(nonNilValues(p.values["active"])) == 0 {
		t.Error("expected 'active' key in pool")
	}
}

func TestExtract_NestedObject(t *testing.T) {
	p := NewDynamicValuePool()
	p.Extract([]byte(`{"user":{"id":7,"email":"x@y.com"}}`))

	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(nonNilValues(p.values["id"])) == 0 {
		t.Error("expected nested 'id' to be extracted")
	}
	if len(nonNilValues(p.values["email"])) == 0 {
		t.Error("expected nested 'email' to be extracted")
	}
}

func TestExtract_ArrayValues(t *testing.T) {
	p := NewDynamicValuePool()
	p.Extract([]byte(`{"ids":[1,2,3]}`))

	p.mu.RLock()
	defer p.mu.RUnlock()
	vals := nonNilValues(p.values["ids"])
	if len(vals) != 3 {
		t.Errorf("expected 3 values under 'ids', got %d", len(vals))
	}
}

func TestExtract_JSONArray_TopLevel(t *testing.T) {
	p := NewDynamicValuePool()
	// Top-level JSON array — should not panic; might extract nothing.
	p.Extract([]byte(`[1,2,3]`))
	// No assertion on size — just must not panic.
}

func TestExtract_NullValuesSkipped(t *testing.T) {
	p := NewDynamicValuePool()
	p.Extract([]byte(`{"deleted":null}`))

	p.mu.RLock()
	defer p.mu.RUnlock()
	vals := nonNilValues(p.values["deleted"])
	if len(vals) != 0 {
		t.Error("null values should not be stored in the pool")
	}
}

func TestExtract_RingBufferCap(t *testing.T) {
	p := NewDynamicValuePool()

	// Add maxPerKey+1 values for the same key.
	for i := 0; i < maxPerKey+1; i++ {
		body := []byte(fmt.Sprintf(`{"token":"%d"}`, i))
		p.Extract(body)
	}

	p.mu.RLock()
	count := len(nonNilValues(p.values["token"]))
	p.mu.RUnlock()

	if count != maxPerKey {
		t.Errorf("ring buffer should hold at most %d values, got %d", maxPerKey, count)
	}
}

func TestExtract_RingBufferEvidesOldest(t *testing.T) {
	p := NewDynamicValuePool()

	// Store exactly maxPerKey values: "v0" through "v255".
	for i := 0; i < maxPerKey; i++ {
		body := []byte(fmt.Sprintf(`{"k":"v%d"}`, i))
		p.Extract(body)
	}
	// Add one more — should overwrite position 0 (value "v0").
	p.Extract([]byte(`{"k":"new"}`))

	p.mu.RLock()
	vals := nonNilValues(p.values["k"])
	p.mu.RUnlock()

	// "v0" should be gone; "new" should be present.
	for _, v := range vals {
		if v == "v0" {
			t.Error("oldest value 'v0' should have been evicted by ring buffer")
		}
	}
	found := false
	for _, v := range vals {
		if v == "new" {
			found = true
		}
	}
	if !found {
		t.Error("newly added value 'new' should be in the pool")
	}
}

func TestGetValue_EmptyPool_ReturnsNil(t *testing.T) {
	p := NewDynamicValuePool()
	// Seed RNG so poolProbability check always passes; pool is empty anyway.
	got := p.GetValue("id", nil)
	if got != nil {
		t.Errorf("expected nil from empty pool, got %v", got)
	}
}

func TestPool_Size(t *testing.T) {
	p := NewDynamicValuePool()
	if p.Size() != 0 {
		t.Errorf("expected 0 initial size, got %d", p.Size())
	}
	p.Extract([]byte(`{"a":1,"b":2}`))
	if p.Size() != 2 {
		t.Errorf("expected size 2 after extracting 2 fields, got %d", p.Size())
	}
}

func TestPool_ConcurrentExtract(t *testing.T) {
	p := NewDynamicValuePool()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			body := []byte(fmt.Sprintf(`{"id":%d}`, i))
			p.Extract(body)
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		p.Extract([]byte(`{"name":"test"}`))
	}
	<-done
	// Must not race; size doesn't matter.
}
