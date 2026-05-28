package mutator

import (
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	log "github.com/sirupsen/logrus"
)

// FieldConstraint holds the OpenAPI schema bounds for one request field.
// Pointer fields are nil when the spec doesn't declare the constraint.
type FieldConstraint struct {
	Minimum   *float64      // inclusive lower bound for number/integer
	Maximum   *float64      // inclusive upper bound for number/integer
	MinLength *uint64       // minimum string byte length; nil = not declared
	MaxLength *uint64       // maximum string byte length; nil = not declared
	Enum      []interface{} // declared allowed values; nil when absent
	Format    string        // "email", "uri", "date-time", etc.
}

// HasNumericBounds reports whether any numeric bound is declared.
func (c *FieldConstraint) HasNumericBounds() bool {
	return c.Minimum != nil || c.Maximum != nil
}

// HasStringBounds reports whether any string length bound is declared.
func (c *FieldConstraint) HasStringBounds() bool {
	return c.MinLength != nil || c.MaxLength != nil
}

// SchemaIndex is a pre-built lookup table of field constraints extracted from
// the OpenAPI spec. Built once at startup; read-only during the fuzz loop.
// The structural mutator uses it to generate schema-aware boundary values.
type SchemaIndex struct {
	index map[string]*FieldConstraint // key: "METHOD /path location fieldname"
}

// BuildSchemaIndex extracts parameter and request-body field constraints from spec
// and stores them in a flat map for O(1) lookup during mutation.
func BuildSchemaIndex(spec *openapi3.T) *SchemaIndex {
	idx := &SchemaIndex{index: make(map[string]*FieldConstraint)}
	if spec == nil || spec.Paths == nil {
		return idx
	}

	for path, item := range spec.Paths.Map() {
		if item == nil {
			continue
		}
		for method, op := range item.Operations() {
			if op == nil {
				continue
			}
			prefix := strings.ToUpper(method) + " " + path

			// Parameters: path, query, header, cookie.
			for _, pRef := range op.Parameters {
				if pRef == nil || pRef.Value == nil {
					continue
				}
				p := pRef.Value
				if p.Schema == nil || p.Schema.Value == nil {
					continue
				}
				if c := constraintFrom(p.Schema.Value); c != nil {
					idx.index[prefix+" "+p.In+" "+p.Name] = c
				}
			}

			// Request body: top-level JSON object properties only.
			if op.RequestBody == nil || op.RequestBody.Value == nil {
				continue
			}
			mt, ok := op.RequestBody.Value.Content["application/json"]
			if !ok || mt == nil || mt.Schema == nil || mt.Schema.Value == nil {
				continue
			}
			for name, propRef := range mt.Schema.Value.Properties {
				if propRef == nil || propRef.Value == nil {
					continue
				}
				if c := constraintFrom(propRef.Value); c != nil {
					idx.index[prefix+" body "+name] = c
				}
			}
		}
	}

	log.Infof("schema: %d field constraint(s) indexed from spec", len(idx.index))
	return idx
}

// Get returns the FieldConstraint for the given field, or nil when no
// constraint is declared. location is one of: path, query, header, cookie, body.
func (s *SchemaIndex) Get(method, pathPattern, location, name string) *FieldConstraint {
	return s.index[strings.ToUpper(method)+" "+pathPattern+" "+location+" "+name]
}

// Size returns the number of indexed field constraints.
func (s *SchemaIndex) Size() int { return len(s.index) }

// constraintFrom extracts a FieldConstraint from schema.
// Returns nil when the schema declares no fuzzing-relevant constraints.
func constraintFrom(s *openapi3.Schema) *FieldConstraint {
	if s == nil {
		return nil
	}
	c := &FieldConstraint{
		Minimum: s.Min,
		Maximum: s.Max,
		Format:  s.Format,
	}
	if s.MaxLength != nil {
		c.MaxLength = s.MaxLength
	}
	if s.MinLength > 0 {
		ml := s.MinLength
		c.MinLength = &ml
	}
	for _, v := range s.Enum {
		if v != nil {
			c.Enum = append(c.Enum, v)
		}
	}
	if !c.HasNumericBounds() && !c.HasStringBounds() && len(c.Enum) == 0 && c.Format == "" {
		return nil
	}
	return c
}
