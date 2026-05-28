package corpus

import "testing"

func TestDependencyGraph_RegisterAndLookup(t *testing.T) {
	g := NewDependencyGraph()
	b := &ProducerBinding{
		ProducerMethod:      "POST",
		ProducerPathPattern: "/users",
		IDField:             "id",
		ParamName:           "id",
	}
	g.Register("GET", "/users/{id}", b)
	g.Register("DELETE", "/users/{id}", b)

	if g.Size() != 2 {
		t.Fatalf("expected size 2, got %d", g.Size())
	}

	got, ok := g.ProducerFor("GET", "/users/{id}")
	if !ok || got != b {
		t.Error("ProducerFor GET /users/{id} should return the registered binding")
	}
	got, ok = g.ProducerFor("DELETE", "/users/{id}")
	if !ok || got != b {
		t.Error("ProducerFor DELETE /users/{id} should return the registered binding")
	}
	_, ok = g.ProducerFor("GET", "/users")
	if ok {
		t.Error("ProducerFor GET /users should return false (collection, not consumer)")
	}
}

func TestDependencyGraph_Empty(t *testing.T) {
	g := NewDependencyGraph()
	if g.Size() != 0 {
		t.Fatalf("new graph should be empty")
	}
	_, ok := g.ProducerFor("GET", "/anything")
	if ok {
		t.Error("empty graph should return false for any lookup")
	}
}
