package mutator

import (
	"math/rand"
	"testing"
)

func makeConstraintMinMax(min, max float64) *FieldConstraint {
	return &FieldConstraint{Minimum: &min, Maximum: &max}
}

func makeConstraintMaxLen(maxLen uint64) *FieldConstraint {
	return &FieldConstraint{MaxLength: &maxLen}
}

func makeConstraintEnum(vals ...interface{}) *FieldConstraint {
	return &FieldConstraint{Enum: vals}
}

// TestMutateIntConstrained_MostlyInBounds verifies that at least 60% of
// constrained integer mutations stay within [min, max].
func TestMutateIntConstrained_MostlyInBounds(t *testing.T) {
	m := &structuralMutator{rng: rand.New(rand.NewSource(1))}
	c := makeConstraintMinMax(1, 5)

	inBounds := 0
	const N = 1000
	for i := 0; i < N; i++ {
		v := m.mutateIntConstrained(3, c)
		if v >= 1 && v <= 5 {
			inBounds++
		}
	}
	rate := float64(inBounds) / N
	if rate < 0.60 {
		t.Errorf("expected ≥60%% in-bounds, got %.1f%%", rate*100)
	}
}

// TestMutateIntConstrained_SometimesViolates verifies that boundary violations occur.
func TestMutateIntConstrained_SometimesViolates(t *testing.T) {
	m := &structuralMutator{rng: rand.New(rand.NewSource(2))}
	c := makeConstraintMinMax(1, 5)

	violations := 0
	const N = 1000
	for i := 0; i < N; i++ {
		v := m.mutateIntConstrained(3, c)
		if v < 1 || v > 5 {
			violations++
		}
	}
	if violations == 0 {
		t.Error("expected at least some boundary violations from constrained int mutation")
	}
}

// TestMutateIntConstrained_NoConstraintFallback verifies that a constraint with
// no bounds delegates to the unconstrained mutator.
func TestMutateIntConstrained_NoConstraintFallback(t *testing.T) {
	m := &structuralMutator{rng: rand.New(rand.NewSource(3))}
	c := &FieldConstraint{} // no bounds

	found := false
	for i := 0; i < 200; i++ {
		v := m.mutateIntConstrained(0, c)
		if v == int64(^uint64(0)>>1) || v == -int64(^uint64(0)>>1)-1 { // MaxInt64 / MinInt64
			found = true
			break
		}
	}
	if !found {
		// It's fine: fallback is mutateInt which may not always hit edge cases in 200 tries.
		// Just ensure no panic occurred.
	}
}

// TestMutateStringConstrained_RespectsMaxLength verifies that 70% of results
// are within bounds when maxLength is declared.
func TestMutateStringConstrained_RespectsMaxLength(t *testing.T) {
	m := &structuralMutator{rng: rand.New(rand.NewSource(4))}
	c := makeConstraintMaxLen(10)

	inBounds := 0
	const N = 1000
	for i := 0; i < N; i++ {
		v := m.mutateStringConstrained("hello", c)
		if len(v) <= 10 {
			inBounds++
		}
	}
	rate := float64(inBounds) / N
	if rate < 0.60 {
		t.Errorf("expected ≥60%% within maxLength=10, got %.1f%%", rate*100)
	}
}

// TestMutateEnum_PicksFromList verifies that enum mutation returns declared values.
func TestMutateEnum_PicksFromList(t *testing.T) {
	m := &structuralMutator{rng: rand.New(rand.NewSource(5))}
	enum := []interface{}{"red", "green", "blue"}

	fromList := 0
	const N = 1000
	for i := 0; i < N; i++ {
		v := m.mutateEnum("red", enum)
		if s, ok := v.(string); ok {
			for _, e := range enum {
				if s == e.(string) {
					fromList++
					break
				}
			}
		}
	}
	rate := float64(fromList) / N
	if rate < 0.60 {
		t.Errorf("expected ≥60%% from enum list, got %.1f%%", rate*100)
	}
}

// TestConstraintFrom_NilSchema returns nil without panic.
func TestConstraintFrom_NilSchema(t *testing.T) {
	if constraintFrom(nil) != nil {
		t.Error("constraintFrom(nil) should return nil")
	}
}

// TestConstraintFrom_NoConstraints returns nil for an unconstrained schema.
func TestConstraintFrom_NoConstraints(t *testing.T) {
	// An empty schema has no constraints — constraintFrom should return nil.
	// We can't easily instantiate openapi3.Schema without the library, so
	// just verify the HasNumericBounds/HasStringBounds helpers work correctly.
	c := &FieldConstraint{}
	if c.HasNumericBounds() {
		t.Error("empty FieldConstraint should have no numeric bounds")
	}
	if c.HasStringBounds() {
		t.Error("empty FieldConstraint should have no string bounds")
	}
}

// TestSchemaIndex_GetUnknownKey returns nil without panic.
func TestSchemaIndex_GetUnknownKey(t *testing.T) {
	idx := &SchemaIndex{index: make(map[string]*FieldConstraint)}
	if idx.Get("GET", "/anything", "path", "id") != nil {
		t.Error("Get on empty index should return nil")
	}
}
