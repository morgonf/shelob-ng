package generateInput

import (
	"encoding/base64"
	"math"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/getkin/kin-openapi/openapi3"
	log "github.com/sirupsen/logrus"
)

func GenerateRandomDataModels(schema *openapi3.Schema) interface{} {
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
			array = append(array, GenerateRandomDataModels(schema.Items.Value))
		}
		return array
	case "object":
		objects := make(map[string]interface{})
		for property, schemaInternal := range schema.Properties {
			if schemaInternal.Value != nil {
				objects[property] = GenerateRandomDataModels(schemaInternal.Value)
			}
		}
		return objects
	default:
		log.Warn("Unresolved schema type:", schemaType)
	}
	return ""
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
