package corpus

import (
	"context"
	"encoding/json"
	"fmt"

	"shelob-ng/generateInput"

	"github.com/getkin/kin-openapi/openapi3"
	log "github.com/sirupsen/logrus"
)

// SeedOptions controls how the initial corpus is populated from an OpenAPI spec.
type SeedOptions struct {
	// SeedCount is how many CorpusEntries to generate per OpenAPI operation.
	// More entries give broader initial exploration at the cost of startup time.
	// Default: 3.
	SeedCount int

	// IncludeOptionalParams controls whether optional (non-required) parameters
	// are populated in seed entries. Shelob only fuzzed required params;
	// including optional ones increases initial coverage.
	// Default: true.
	IncludeOptionalParams bool
}

// DefaultSeedOptions returns sensible defaults.
func DefaultSeedOptions() SeedOptions {
	return SeedOptions{
		SeedCount:             3,
		IncludeOptionalParams: true,
	}
}

// SeedFromSpec generates initial CorpusEntries from every operation in the
// OpenAPI spec and adds them to the corpus. Each operation gets SeedCount
// entries with independently randomised parameters.
//
// Seed entries are added with delta=1 (minimum non-zero weight) because no
// actual coverage measurement is available yet. The fuzzer will rediscover
// and promote genuinely interesting entries through real coverage feedback.
//
// Returns the total number of entries successfully added.
func SeedFromSpec(
	_ context.Context,
	spec *openapi3.T,
	manager CorpusManager,
	opts SeedOptions,
) (int, error) {
	if spec.Paths == nil {
		return 0, fmt.Errorf("spec has no paths")
	}

	added := 0
	for pathPattern, pathItem := range spec.Paths.Map() {
		if pathItem == nil {
			continue
		}
		for method, operation := range pathItem.Operations() {
			for i := 0; i < opts.SeedCount; i++ {
				entry, err := newEntryFromOperation(method, pathPattern, operation, opts.IncludeOptionalParams)
				if err != nil {
					log.Warnf("seed: skipping %s %s (attempt %d): %v", method, pathPattern, i, err)
					continue
				}
				// delta=1: minimum weight so seeds are selectable but not dominant.
				if manager.Add(entry, 1) {
					added++
				}
			}
		}
	}

	log.Infof("corpus: seeded %d entries from %d spec paths", added, len(spec.Paths.Map()))
	return added, nil
}

// SeedEntry generates one CorpusEntry for the given operation with randomised
// parameters. Used by the sequence builder to create probe entries without
// adding them to the corpus.
func SeedEntry(method, pathPattern string, op *openapi3.Operation) (*CorpusEntry, error) {
	return newEntryFromOperation(method, pathPattern, op, true)
}

// newEntryFromOperation builds one CorpusEntry for the given operation by
// generating random parameter values through generateInput.GenerateRandomDataModels.
func newEntryFromOperation(
	method, pathPattern string,
	operation *openapi3.Operation,
	includeOptional bool,
) (*CorpusEntry, error) {
	entry := &CorpusEntry{
		Method:       method,
		PathPattern:  pathPattern,
		OperationID:  operation.OperationID,
		PathParams:   make(pathParamsMap),
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
		Generation:   0, // mark as seed
	}

	// Populate parameters from the operation definition.
	for _, paramRef := range operation.Parameters {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}
		param := paramRef.Value
		if !param.Required && !includeOptional {
			continue
		}
		if param.Schema == nil || param.Schema.Value == nil {
			continue
		}

		val := generateInput.GenerateRandomDataModels(param.Schema.Value)
		valStr := fmt.Sprintf("%v", val)

		switch param.In {
		case "path":
			entry.PathParams[param.Name] = val
		case "query":
			entry.QueryParams[param.Name] = valStr
		case "header":
			entry.HeaderParams[param.Name] = valStr
		case "cookie":
			entry.CookieParams[param.Name] = valStr
		}
	}

	// Populate request body if the operation has one.
	if operation.RequestBody != nil && operation.RequestBody.Value != nil {
		rb := operation.RequestBody.Value
		// Prefer application/json; fall back to first available content type.
		var chosenType string
		var chosenSchema *openapi3.Schema
		for ct, mt := range rb.Content {
			if mt.Schema != nil && mt.Schema.Value != nil {
				if chosenType == "" || ct == "application/json" {
					chosenType = ct
					chosenSchema = mt.Schema.Value
				}
			}
		}
		if chosenSchema != nil {
			bodyData := generateInput.GenerateRandomDataModels(chosenSchema)
			if chosenType == "application/json" {
				b, err := json.Marshal(bodyData)
				if err != nil {
					return nil, fmt.Errorf("marshal body: %w", err)
				}
				entry.Body = b
			}
			entry.ContentType = chosenType
		}
	}

	return entry, nil
}
