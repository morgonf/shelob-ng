package generateInput

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// --- T0.1: circular $ref depth limit ---

// TestDepthLimit_CircularArray verifies that a schema where an object's array
// items reference the same object (e.g. TreeNode.children[].items -> TreeNode)
// does not cause a stack overflow. Before the fix this would recurse infinitely.
func TestDepthLimit_CircularArray(t *testing.T) {
	// Build the circular schema in memory: Inner.myProp = array of Inner.
	// This matches recursive.yaml from swagger-parser test fixtures.
	inner := &openapi3.Schema{
		Properties: make(openapi3.Schemas),
	}
	typeObj := openapi3.Types{"object"}
	inner.Type = &typeObj

	typeArr := openapi3.Types{"array"}
	inner.Properties["myProp"] = &openapi3.SchemaRef{
		Value: &openapi3.Schema{
			Type:  &typeArr,
			Items: &openapi3.SchemaRef{Value: inner}, // circular reference
		},
	}

	// Must return without panicking / stack overflow.
	result := GenerateRandomDataModels(inner)
	if result == nil {
		t.Error("expected non-nil result for object schema")
	}
	obj, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	// myProp should exist; its value may be nil (depth cut) or a slice
	if _, exists := obj["myProp"]; !exists {
		t.Error("expected myProp key in result")
	}
}

// TestDepthLimit_DeepNesting verifies that generation terminates and returns
// a value at any nesting depth.
func TestDepthLimit_DeepNesting(t *testing.T) {
	// Build 10 levels of nested objects: level0 -> level1 -> ... -> level9
	typeStr := openapi3.Types{"string"}
	leaf := &openapi3.Schema{Type: &typeStr}

	current := leaf
	for i := 0; i < 10; i++ {
		typeObj := openapi3.Types{"object"}
		parent := &openapi3.Schema{
			Type:       &typeObj,
			Properties: openapi3.Schemas{"child": {Value: current}},
		}
		current = parent
	}

	// Must not panic.
	result := GenerateRandomDataModels(current)
	if result == nil {
		t.Error("expected non-nil result for deeply nested schema")
	}
}

// --- T0.2: allOf/oneOf/anyOf resolution ---

// TestAllOf_MergesProperties verifies that allOf merges sub-schema properties
// into one object. Matches the composed.yaml fixture pattern.
func TestAllOf_MergesProperties(t *testing.T) {
	typeObj := openapi3.Types{"object"}
	typeStr := openapi3.Types{"string"}

	address := &openapi3.Schema{
		Type:     &typeObj,
		Required: []string{"street"},
		Properties: openapi3.Schemas{
			"street": {Value: &openapi3.Schema{Type: &typeStr}},
			"city":   {Value: &openapi3.Schema{Type: &typeStr}},
		},
	}

	extended := &openapi3.Schema{
		AllOf: openapi3.SchemaRefs{
			{Value: address},
			{Value: &openapi3.Schema{
				Type:     &typeObj,
				Required: []string{"gps"},
				Properties: openapi3.Schemas{
					"gps": {Value: &openapi3.Schema{Type: &typeStr}},
				},
			}},
		},
	}

	result := GenerateRandomDataModels(extended)
	obj, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("allOf: expected map, got %T (%v)", result, result)
	}
	for _, field := range []string{"street", "city", "gps"} {
		if _, exists := obj[field]; !exists {
			t.Errorf("allOf: expected field %q in merged result, got keys: %v", field, keys(obj))
		}
	}
}

// TestOneOf_ProducesOneVariant verifies that oneOf generates a non-empty result
// from one of the sub-schemas. Before the fix the function returned "" because
// schema.Type was nil for composed schemas.
func TestOneOf_ProducesOneVariant(t *testing.T) {
	typeObj := openapi3.Types{"object"}
	typeStr := openapi3.Types{"string"}
	typeInt := openapi3.Types{"integer"}

	book := &openapi3.Schema{
		Type:     &typeObj,
		Required: []string{"title"},
		Properties: openapi3.Schemas{
			"title": {Value: &openapi3.Schema{Type: &typeStr}},
			"isbn":  {Value: &openapi3.Schema{Type: &typeStr}},
		},
	}
	movie := &openapi3.Schema{
		Type:     &typeObj,
		Required: []string{"year"},
		Properties: openapi3.Schemas{
			"title": {Value: &openapi3.Schema{Type: &typeStr}},
			"year":  {Value: &openapi3.Schema{Type: &typeInt}},
		},
	}

	schema := &openapi3.Schema{
		OneOf: openapi3.SchemaRefs{
			{Value: book},
			{Value: movie},
		},
	}

	// Run several times to exercise both branches.
	for i := 0; i < 20; i++ {
		result := GenerateRandomDataModels(schema)
		obj, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("oneOf: expected map, got %T (%v) on iteration %d", result, result, i)
		}
		// Either book (has isbn) or movie (has year) — both have title.
		if _, hasTtitle := obj["title"]; !hasTtitle {
			if _, hasIsbn := obj["isbn"]; !hasIsbn {
				if _, hasYear := obj["year"]; !hasYear {
					t.Errorf("oneOf iteration %d: unexpected keys: %v", i, keys(obj))
				}
			}
		}
	}
}

// TestAnyOf_ProducesOneVariant verifies anyOf behaves like oneOf for generation.
func TestAnyOf_ProducesOneVariant(t *testing.T) {
	typeStr := openapi3.Types{"string"}
	typeInt := openapi3.Types{"integer"}

	schema := &openapi3.Schema{
		AnyOf: openapi3.SchemaRefs{
			{Value: &openapi3.Schema{Type: &typeStr}},
			{Value: &openapi3.Schema{Type: &typeInt}},
		},
	}

	for i := 0; i < 10; i++ {
		result := GenerateRandomDataModels(schema)
		if result == nil {
			t.Errorf("anyOf iteration %d: got nil", i)
		}
		switch result.(type) {
		case string, int32, int64, float32, float64, int:
			// valid
		default:
			t.Errorf("anyOf iteration %d: unexpected type %T", i, result)
		}
	}
}

// TestNilTypeSchemaReturnsEmpty verifies baseline: schema with no type and no
// composition keywords returns "".
func TestNilTypeSchemaReturnsEmpty(t *testing.T) {
	result := GenerateRandomDataModels(&openapi3.Schema{})
	if result != "" {
		t.Errorf("expected empty string for typeless schema, got %v", result)
	}
}

// TestPrimitiveTypesUnchanged verifies that the refactor did not break existing
// primitive type generation.
func TestPrimitiveTypesUnchanged(t *testing.T) {
	typeStr := openapi3.Types{"string"}
	typeInt := openapi3.Types{"integer"}
	typeBool := openapi3.Types{"boolean"}

	if r := GenerateRandomDataModels(&openapi3.Schema{Type: &typeStr}); r == nil {
		t.Error("string schema returned nil")
	}
	if r := GenerateRandomDataModels(&openapi3.Schema{Type: &typeInt}); r == nil {
		t.Error("integer schema returned nil")
	}
	if r := GenerateRandomDataModels(&openapi3.Schema{Type: &typeBool}); r == nil {
		t.Error("boolean schema returned nil")
	}
}

// helpers

func keys(m map[string]interface{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
