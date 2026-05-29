package generateInput

import (
	"encoding/base64"
	"math"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/getkin/kin-openapi/openapi3"
	log "github.com/sirupsen/logrus"
)

// maxGenerateDepth caps recursion for circular or deeply nested schemas
// (e.g. Kubernetes Container → Volume → Container). Five levels covers
// virtually every real-world spec without risking a stack overflow.
const maxGenerateDepth = 5

// GenerateRandomDataModels generates a random value that conforms to schema.
// It handles primitive types, objects, arrays, and allOf/oneOf/anyOf composition.
// Safe against circular $ref chains — recursion is capped at maxGenerateDepth.
func GenerateRandomDataModels(schema *openapi3.Schema) interface{} {
	return generateRandom(schema, 0)
}

func generateRandom(schema *openapi3.Schema, depth int) interface{} {
	if depth > maxGenerateDepth {
		return nil
	}

	// Resolve composition keywords before checking Type.
	// allOf/oneOf/anyOf schemas often have no explicit Type field of their own.
	if len(schema.AllOf) > 0 || len(schema.OneOf) > 0 || len(schema.AnyOf) > 0 {
		if resolved := resolveComposed(schema); resolved != nil {
			return generateRandom(resolved, depth+1)
		}
	}

	if schema.Type == nil || len(*schema.Type) == 0 {
		log.Warn("Schema type is nil or empty")
		return ""
	}

	schemaType := (*schema.Type)[0]

	switch schemaType {
	case "string":
		if schema.Pattern != "" {
			return CheckStringPattern(schema.Pattern)
		}
		if schema.Format != "" {
			return CheckStringFormat(schema.Format)
		}
		if len(schema.Enum) > 0 {
			// Pick a random enum value, not always the first.
			return schema.Enum[gofakeit.IntRange(0, len(schema.Enum)-1)]
		}
		if schema.Default != nil {
			if s, ok := schema.Default.(string); ok {
				return s
			}
		}
		if schema.Example != nil {
			return schema.Example
		}
		// Respect maxLength so seeds don't immediately fail server validation.
		genLen := 50
		if schema.MaxLength != nil && int(*schema.MaxLength) < genLen {
			genLen = int(*schema.MaxLength)
		}
		if schema.MinLength > 0 && int(schema.MinLength) > genLen {
			genLen = int(schema.MinLength)
		}
		if genLen <= 0 {
			genLen = 1
		}
		return gofakeit.LetterN(uint(genLen))
	case "number":
		// Respect declared bounds when available.
		if schema.Min != nil || schema.Max != nil {
			return generateBoundedFloat(schema.Min, schema.Max)
		}
		return CheckNumberFormat(schema.Format)
	case "integer":
		// Respect declared bounds so seeds carry valid data.
		if schema.Min != nil || schema.Max != nil {
			return generateBoundedInt(schema.Min, schema.Max)
		}
		if len(schema.Enum) > 0 {
			return schema.Enum[gofakeit.IntRange(0, len(schema.Enum)-1)]
		}
		return CheckIntegerFormat(schema.Format)
	case "boolean":
		return gofakeit.Bool()
	case "array":
		var array []interface{}
		if schema.Items != nil && schema.Items.Value != nil {
			array = append(array, generateRandom(schema.Items.Value, depth+1))
		}
		return array
	case "object":
		objects := make(map[string]interface{})
		for property, schemaInternal := range schema.Properties {
			if schemaInternal.Value != nil {
				objects[property] = generateRandom(schemaInternal.Value, depth+1)
			}
		}
		return objects
	default:
		log.Warn("Unresolved schema type:", schemaType)
	}
	return ""
}

// resolveComposed flattens allOf/oneOf/anyOf into a concrete schema for generation.
//
// allOf: merges properties from every sub-schema into one object. This is the
// correct approach for inheritance patterns (e.g. ExtendedAddress allOf Address).
//
// oneOf/anyOf: picks one branch at random. Choosing randomly on each call means
// different corpus entries exercise different server code paths.
//
// Returns nil when no composition keywords are present.
func resolveComposed(s *openapi3.Schema) *openapi3.Schema {
	if len(s.AllOf) > 0 {
		t := openapi3.Types{"object"}
		merged := &openapi3.Schema{
			Type:       &t,
			Properties: make(openapi3.Schemas),
		}
		for _, ref := range s.AllOf {
			if ref.Value == nil {
				continue
			}
			for k, v := range ref.Value.Properties {
				merged.Properties[k] = v
			}
			merged.Required = append(merged.Required, ref.Value.Required...)
		}
		// Include any properties declared alongside allOf (valid in OAS 3.1).
		for k, v := range s.Properties {
			merged.Properties[k] = v
		}
		return merged
	}

	if len(s.OneOf) > 0 {
		if picked := s.OneOf[gofakeit.IntRange(0, len(s.OneOf)-1)]; picked.Value != nil {
			return picked.Value
		}
	}

	if len(s.AnyOf) > 0 {
		if picked := s.AnyOf[gofakeit.IntRange(0, len(s.AnyOf)-1)]; picked.Value != nil {
			return picked.Value
		}
	}

	return nil
}

// generateBoundedInt generates a random int64 within [min, max].
// Falls back to a small default range when the span is too large for IntRange.
func generateBoundedInt(min, max *float64) int64 {
	lo := int64(math.MinInt32)
	hi := int64(math.MaxInt32)
	if min != nil {
		lo = int64(math.Round(*min))
	}
	if max != nil {
		hi = int64(math.Round(*max))
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	if lo == hi {
		return lo
	}
	span := hi - lo
	// gofakeit.IntRange takes int; clamp span to avoid overflow on 32-bit platforms.
	if span > math.MaxInt32 {
		span = math.MaxInt32
	}
	return lo + int64(gofakeit.IntRange(0, int(span)))
}

// generateBoundedFloat generates a random float64 within [min, max].
func generateBoundedFloat(min, max *float64) float64 {
	lo := -1e9
	hi := 1e9
	if min != nil {
		lo = *min
	}
	if max != nil {
		hi = *max
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	return gofakeit.Float64Range(lo, hi)
}

func CheckNumberFormat(format string) interface{} {
	switch format {
	case "float":
		return gofakeit.Float32()
	case "double":
		return gofakeit.Float64()
	default:
		return gofakeit.Number(int(math.Inf(-1)), int(math.Inf(1)))
	}
}

func CheckIntegerFormat(format string) interface{} {
	switch format {
	case "int32":
		return gofakeit.Int32()
	case "int64":
		return gofakeit.Int64()
	default:
		return gofakeit.IntRange(int(math.Inf(-1)), int(math.Inf(1)))
	}
}

func CheckStringFormat(format string) interface{} {
	switch format {
	case "date":
		result, _ := gofakeit.Generate("####-##-##")
		return result
	case "date-time":
		date := gofakeit.Date()
		return date.Format("2006-01-02T15:04:05Z")
	case "password":
		randLen := gofakeit.IntRange(0, 255)
		return gofakeit.Password(true, true, true, true, true, randLen)
	case "byte":
		randLen := gofakeit.IntRange(0, 256)
		randStr := gofakeit.LetterN(uint(randLen))
		return base64.StdEncoding.EncodeToString([]byte(randStr))
	case "binary":
		randLen := gofakeit.IntRange(0, 1024)
		return []byte(gofakeit.LetterN(uint(randLen)))
	case "email":
		return gofakeit.Email()
	case "uuid":
		return gofakeit.UUID()
	case "uri":
		return gofakeit.URL()
	case "hostname":
		return gofakeit.DomainName() + gofakeit.DomainSuffix()
	case "ipv4":
		return gofakeit.IPv4Address()
	case "ipv6":
		return gofakeit.IPv6Address()
	default:
		randLen := gofakeit.IntRange(1, 64)
		return gofakeit.LetterN(uint(randLen))
	}
}

func CheckStringPattern(pattern string) interface{} {
	return gofakeit.Regex(pattern)
}
