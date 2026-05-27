package sequence

import (
	"strings"

	"shelob-ng/corpus"

	"github.com/getkin/kin-openapi/openapi3"
	log "github.com/sirupsen/logrus"
)

// idFieldNames are the JSON keys we look for when searching a POST response
// schema for the newly created resource's identifier.
var idFieldNames = []string{"id", "ID", "Id", "uuid", "UUID", "key", "token", "slug"}

// BuildSequences inspects the OpenAPI spec and returns CRUD sequences for every
// resource that has a matching POST /X + GET|DELETE /X/{param} pattern.
//
// Example: if the spec has POST /users and DELETE /users/{id}, BuildSequences
// emits a 4-step sequence: create → verify → delete → verify-gone.
func BuildSequences(spec *openapi3.T) []Sequence {
	if spec == nil || spec.Paths == nil {
		return nil
	}

	paths := spec.Paths.Map()
	var seqs []Sequence

	for parentPath, parentItem := range paths {
		if parentItem == nil || parentItem.Post == nil {
			continue
		}

		paramName, childPath, childItem, ok := findChildPath(parentPath, paths)
		if !ok {
			continue
		}

		idField := responseIDField(parentItem.Post, paramName)
		if idField == "" {
			// Can't bind without knowing which field carries the ID.
			continue
		}

		seq := buildCRUDSequence(
			parentPath, parentItem.Post,
			childPath, childItem,
			paramName, idField,
		)
		if seq != nil {
			seqs = append(seqs, *seq)
			log.Debugf("sequence: registered %q (%d steps)", seq.Name, len(seq.Steps))
		}
	}

	log.Infof("sequence: %d CRUD sequence(s) built from spec", len(seqs))
	return seqs
}

// findChildPath searches for a path matching <parent>/{param} that has either
// a GET or DELETE operation, returning the param name, the full child path,
// its PathItem, and true on success.
func findChildPath(parent string, paths map[string]*openapi3.PathItem) (paramName, childPath string, item *openapi3.PathItem, ok bool) {
	prefix := strings.TrimSuffix(parent, "/") + "/"

	for p, pi := range paths {
		if pi == nil {
			continue
		}
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		// The remainder after the prefix must be a single {param} segment.
		rest := p[len(prefix):]
		if strings.Contains(rest, "/") {
			continue // not a direct child
		}
		if !strings.HasPrefix(rest, "{") || !strings.HasSuffix(rest, "}") {
			continue
		}
		pName := rest[1 : len(rest)-1]
		if pi.Get == nil && pi.Delete == nil {
			continue
		}
		return pName, p, pi, true
	}
	return "", "", nil, false
}

// responseIDField inspects the 2xx response schema of op for a top-level
// property whose name is in idFieldNames and whose type is string or integer.
// Returns the first matching field name, or "" when none is found.
func responseIDField(op *openapi3.Operation, hint string) string {
	if op == nil || op.Responses == nil {
		return ""
	}
	for code, respRef := range op.Responses.Map() {
		if !is2xx(code) || respRef == nil || respRef.Value == nil {
			continue
		}
		mt, ok := respRef.Value.Content["application/json"]
		if !ok || mt == nil || mt.Schema == nil || mt.Schema.Value == nil {
			continue
		}
		schema := mt.Schema.Value
		// Check if the hint param name itself is in the schema properties first.
		if _, exists := schema.Properties[hint]; exists {
			return hint
		}
		// Fall back to well-known id field names.
		for _, name := range idFieldNames {
			if prop, exists := schema.Properties[name]; exists && prop != nil && prop.Value != nil {
				t := prop.Value.Type
				if t != nil && (t.Is("string") || t.Is("integer")) {
					return name
				}
			}
		}
	}
	return ""
}

// buildCRUDSequence constructs the 4-step sequence:
//  1. POST /resource            — create, extract id
//  2. GET  /resource/{id}       — read,   expect 2xx
//  3. DELETE /resource/{id}     — delete, expect 2xx  (skipped if no DELETE op)
//  4. GET  /resource/{id}       — probe,  expect 4xx  (UseAfterFree)
//
// Steps 3+4 are only added when childItem has a DELETE operation.
func buildCRUDSequence(
	postPath string, postOp *openapi3.Operation,
	childPath string, childItem *openapi3.PathItem,
	paramName, idField string,
) *Sequence {
	postEntry, err := corpus.SeedEntry("POST", postPath, postOp)
	if err != nil {
		log.Debugf("sequence: seed POST %s: %v", postPath, err)
		return nil
	}

	var getEntry *corpus.CorpusEntry
	if childItem.Get != nil {
		getEntry, err = corpus.SeedEntry("GET", childPath, childItem.Get)
		if err != nil {
			log.Debugf("sequence: seed GET %s: %v", childPath, err)
			return nil
		}
	}

	steps := []Step{
		{
			Entry:      postEntry,
			ExtractKey: idField,
			BindParam:  paramName,
			WantStatus: 2,
			// No mismatch finding for the create step — we'll keep going regardless.
		},
	}

	if getEntry != nil {
		steps = append(steps, Step{
			Entry:           getEntry,
			WantStatus:      2,
			FindingTitle:    "Resource not accessible after creation",
			FindingSeverity: "medium",
		})
	}

	if childItem.Delete != nil {
		delEntry, err := corpus.SeedEntry("DELETE", childPath, childItem.Delete)
		if err != nil {
			log.Debugf("sequence: seed DELETE %s: %v", childPath, err)
			// Continue without the delete step; GET-after-create is still useful.
		} else {
			steps = append(steps, Step{
				Entry:           delEntry,
				WantStatus:      2,
				FindingTitle:    "Deletion failed",
				FindingSeverity: "medium",
			})
			// UseAfterFree probe: GET should now 404.
			if getEntry != nil {
				probeEntry, _ := corpus.SeedEntry("GET", childPath, childItem.Get)
				if probeEntry != nil {
					steps = append(steps, Step{
						Entry:           probeEntry,
						WantStatus:      4,
						FindingTitle:    "Resource accessible after DELETE",
						FindingSeverity: "high",
					})
				}
			}
		}
	}

	name := "CRUD:" + postPath
	return &Sequence{Name: name, Steps: steps}
}

// is2xx returns true when the OpenAPI response status code string represents
// a 2xx class (handles "200", "201", "2XX", "default").
func is2xx(code string) bool {
	return strings.HasPrefix(code, "2") || strings.EqualFold(code, "default")
}
