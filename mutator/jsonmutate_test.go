package mutator

import (
	"encoding/json"
	"testing"
)

// --- ParseJSONObject ---

func TestParseJSONObject_ValidObject(t *testing.T) {
	obj, err := ParseJSONObject([]byte(`{"name":"alice","age":30}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obj["name"] != "alice" {
		t.Errorf("expected name=alice, got %v", obj["name"])
	}
}

func TestParseJSONObject_EmptyBody(t *testing.T) {
	_, err := ParseJSONObject(nil)
	if err == nil {
		t.Error("expected error for nil body")
	}
	_, err = ParseJSONObject([]byte{})
	if err == nil {
		t.Error("expected error for empty body")
	}
}

func TestParseJSONObject_JSONArray(t *testing.T) {
	_, err := ParseJSONObject([]byte(`[1,2,3]`))
	if err == nil {
		t.Error("expected error for JSON array — only objects are accepted")
	}
}

func TestParseJSONObject_InvalidJSON(t *testing.T) {
	_, err := ParseJSONObject([]byte(`{broken`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseJSONObject_EmptyObject(t *testing.T) {
	obj, err := ParseJSONObject([]byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(obj) != 0 {
		t.Errorf("expected empty map, got %v", obj)
	}
}

// --- MarshalBody ---

func TestMarshalBody_RoundTrip(t *testing.T) {
	obj := map[string]interface{}{"x": "y", "n": float64(1)}
	b, err := MarshalBody(obj)
	if err != nil {
		t.Fatalf("MarshalBody error: %v", err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("marshal result is not valid JSON: %v", err)
	}
	if back["x"] != "y" {
		t.Errorf("expected x=y after round-trip, got %v", back["x"])
	}
}

// --- SetLeafString ---

func TestSetLeafString_TopLevel(t *testing.T) {
	obj := map[string]interface{}{"name": "alice"}
	if err := SetLeafString(obj, "name", "payload"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obj["name"] != "payload" {
		t.Errorf("expected name=payload, got %v", obj["name"])
	}
}

func TestSetLeafString_DottedPath(t *testing.T) {
	obj := map[string]interface{}{
		"user": map[string]interface{}{"name": "alice"},
	}
	if err := SetLeafString(obj, "user.name", "injected"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	inner := obj["user"].(map[string]interface{})
	if inner["name"] != "injected" {
		t.Errorf("expected user.name=injected, got %v", inner["name"])
	}
}

func TestSetLeafString_CreatesIntermediateMap(t *testing.T) {
	obj := map[string]interface{}{}
	if err := SetLeafString(obj, "a.b.c", "deep"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a := obj["a"].(map[string]interface{})
	b := a["b"].(map[string]interface{})
	if b["c"] != "deep" {
		t.Errorf("expected a.b.c=deep, got %v", b["c"])
	}
}

func TestSetLeafString_TypeCollisionError(t *testing.T) {
	// "user" is a string, not a map — can't descend into it.
	obj := map[string]interface{}{"user": "alice"}
	err := SetLeafString(obj, "user.name", "payload")
	if err == nil {
		t.Error("expected error when intermediate key is not a map")
	}
}

// --- CollectStringLeaves ---

func TestCollectStringLeaves_FlatObject(t *testing.T) {
	obj := map[string]interface{}{
		"a": "str",
		"b": float64(42),
		"c": true,
	}
	leaves := CollectStringLeaves(obj)
	if len(leaves) != 1 {
		t.Errorf("expected 1 string leaf, got %d: %v", len(leaves), leaves)
	}
	if leaves[0] != "a" {
		t.Errorf("expected leaf 'a', got %q", leaves[0])
	}
}

func TestCollectStringLeaves_NestedObject(t *testing.T) {
	obj := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "alice",
			"email": "a@b.com",
		},
		"count": float64(1),
	}
	leaves := CollectStringLeaves(obj)
	if len(leaves) != 2 {
		t.Errorf("expected 2 string leaves, got %d: %v", len(leaves), leaves)
	}
	// Verify dotted paths.
	paths := make(map[string]bool)
	for _, l := range leaves {
		paths[l] = true
	}
	if !paths["user.name"] || !paths["user.email"] {
		t.Errorf("missing expected leaf paths, got: %v", leaves)
	}
}

func TestCollectStringLeaves_EmptyObject(t *testing.T) {
	leaves := CollectStringLeaves(map[string]interface{}{})
	if len(leaves) != 0 {
		t.Errorf("expected no leaves for empty object, got %v", leaves)
	}
}

func TestCollectStringLeaves_NoStringValues(t *testing.T) {
	obj := map[string]interface{}{"n": float64(1), "b": true}
	leaves := CollectStringLeaves(obj)
	if len(leaves) != 0 {
		t.Errorf("expected no string leaves, got %v", leaves)
	}
}

// --- AddField / RemoveField ---

func TestAddField_AddsWhenAbsent(t *testing.T) {
	obj := map[string]interface{}{"existing": "val"}
	AddField(obj, "new", "added")
	if obj["new"] != "added" {
		t.Errorf("expected new=added, got %v", obj["new"])
	}
}

func TestAddField_NoopWhenPresent(t *testing.T) {
	obj := map[string]interface{}{"key": "original"}
	AddField(obj, "key", "overwrite-attempt")
	if obj["key"] != "original" {
		t.Errorf("AddField should not overwrite existing key")
	}
}

func TestRemoveField_RemovesExisting(t *testing.T) {
	obj := map[string]interface{}{"key": "val"}
	RemoveField(obj, "key")
	if _, ok := obj["key"]; ok {
		t.Error("RemoveField should have deleted the key")
	}
}

func TestRemoveField_NoopWhenAbsent(t *testing.T) {
	obj := map[string]interface{}{"other": "val"}
	RemoveField(obj, "missing") // must not panic
	if len(obj) != 1 {
		t.Errorf("RemoveField on missing key should not change object, got %v", obj)
	}
}
