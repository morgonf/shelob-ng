package sequence

import (
	"bytes"
	"encoding/json"
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
		if pi.Get == nil && pi.Delete == nil && pi.Put == nil && pi.Patch == nil {
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

// BuildDependencyGraph constructs a corpus.DependencyGraph from the OpenAPI spec,
// linking each consumer operation (GET/PUT/PATCH/DELETE /X/{param}) to the producer
// (POST /X) that creates the resource and returns its ID.
//
// The resulting graph is used by the main fuzz loop: before sending a consumer
// request the runner first executes the producer, extracts the created ID, and
// injects it into the consumer's path parameters — ensuring the request targets
// a real, existing resource instead of a random (likely non-existent) ID.
func BuildDependencyGraph(spec *openapi3.T) *corpus.DependencyGraph {
	graph := corpus.NewDependencyGraph()
	if spec == nil || spec.Paths == nil {
		return graph
	}

	paths := spec.Paths.Map()
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
			continue
		}
		postEntry, err := corpus.SeedEntry("POST", parentPath, parentItem.Post)
		if err != nil {
			log.Debugf("dependency: seed POST %s: %v", parentPath, err)
			continue
		}
		binding := &corpus.ProducerBinding{
			ProducerMethod:      "POST",
			ProducerPathPattern: parentPath,
			ProducerEntry:       postEntry,
			IDField:             idField,
			ParamName:           paramName,
		}
		for method, op := range childItem.Operations() {
			if op == nil {
				continue
			}
			graph.Register(method, childPath, binding)
			log.Debugf("dependency: %s %s → POST %s (field: %q)", method, childPath, parentPath, idField)
		}
	}

	log.Infof("dependency: %d consumer binding(s) registered", graph.Size())
	return graph
}

// LearnProducer inspects a successful POST response body and registers producer-consumer
// bindings in graph for any spec-defined child path it discovers. Called at runtime
// so the graph learns even when the spec omits response schemas.
//
// For each matching GET/PUT/PATCH/DELETE /postPath/{param} in the spec, if the
// response body contains an id-like field, a ProducerBinding is registered. Static
// bindings (from BuildDependencyGraph) are never overwritten.
func LearnProducer(graph *corpus.DependencyGraph, postPath string, responseBody []byte, spec *openapi3.T) {
	if spec == nil || spec.Paths == nil {
		return
	}
	paths := spec.Paths.Map()

	paramName, childPath, childItem, ok := findChildPath(postPath, paths)
	if !ok {
		return
	}

	idField := learnIDField(responseBody, paramName)
	if idField == "" {
		return
	}

	parentItem := paths[postPath]
	if parentItem == nil || parentItem.Post == nil {
		return
	}

	postEntry, err := corpus.SeedEntry("POST", postPath, parentItem.Post)
	if err != nil {
		log.Debugf("dependency learn: seed POST %s: %v", postPath, err)
		return
	}

	binding := &corpus.ProducerBinding{
		ProducerMethod:      "POST",
		ProducerPathPattern: postPath,
		ProducerEntry:       postEntry,
		IDField:             idField,
		ParamName:           paramName,
	}

	for method, op := range childItem.Operations() {
		if op == nil {
			continue
		}
		if graph.RegisterIfAbsent(method, childPath, binding) {
			log.Debugf("dependency learn: %s %s → POST %s (field: %q)", method, childPath, postPath, idField)
		}
	}
}

// learnIDField searches body for a recognized id field, checking the top level
// and then under a "data" wrapper (common in Sequelize/Express APIs like Juice Shop).
func learnIDField(body []byte, hint string) string {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return ""
	}
	if f := findIDInMap(m, hint); f != "" {
		return f
	}
	if nested, ok := m["data"].(map[string]interface{}); ok {
		if f := findIDInMap(nested, hint); f != "" {
			return f
		}
	}
	return ""
}

// findIDInMap returns the first id-like field name found in m.
func findIDInMap(m map[string]interface{}, hint string) string {
	if v, ok := m[hint]; ok && v != nil {
		return hint
	}
	for _, name := range idFieldNames {
		if v, ok := m[name]; ok && v != nil {
			return name
		}
	}
	return ""
}

// is2xx returns true when the OpenAPI response status code string represents
// a 2xx class (handles "200", "201", "2XX", "default").
func is2xx(code string) bool {
	return strings.HasPrefix(code, "2") || strings.EqualFold(code, "default")
}
