package corpus

// ProducerBinding holds everything needed to pre-execute a producer request
// before sending a consumer operation.
//
// Example: POST /users (producer) must run before GET /users/{id} (consumer)
// so that a real resource ID is available to bind into the path parameter.
type ProducerBinding struct {
	ProducerMethod      string       // HTTP method of the producer (always "POST")
	ProducerPathPattern string       // path template of the producer, e.g. "/users"
	ProducerEntry       *CorpusEntry // seed entry used to build the producer request
	IDField             string       // JSON field in the 2xx response carrying the created ID
	ParamName           string       // path param name in the consumer, e.g. "id"
}

// DependencyGraph maps consumer operations to their producer bindings.
// Built once at startup from the OpenAPI spec; read-only during the fuzz loop.
// Key format: "METHOD /path/pattern", e.g. "GET /users/{id}".
type DependencyGraph struct {
	consumers map[string]*ProducerBinding
}

// NewDependencyGraph returns an empty DependencyGraph ready to be populated.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{consumers: make(map[string]*ProducerBinding)}
}

// Register links a consumer operation to its producer binding.
// Always overwrites any existing binding; used by the static spec analysis at startup.
func (g *DependencyGraph) Register(consumerMethod, consumerPath string, b *ProducerBinding) {
	g.consumers[consumerMethod+" "+consumerPath] = b
}

// RegisterIfAbsent links a consumer to its producer only when no binding exists
// yet for that operation. Returns true when a new binding was stored.
// Used by runtime learning to avoid overwriting statically-discovered bindings.
func (g *DependencyGraph) RegisterIfAbsent(consumerMethod, consumerPath string, b *ProducerBinding) bool {
	key := consumerMethod + " " + consumerPath
	if _, exists := g.consumers[key]; exists {
		return false
	}
	g.consumers[key] = b
	return true
}

// ProducerFor returns the ProducerBinding for the given consumer operation,
// or (nil, false) when no producer is known for that operation.
func (g *DependencyGraph) ProducerFor(method, pathPattern string) (*ProducerBinding, bool) {
	b, ok := g.consumers[method+" "+pathPattern]
	return b, ok
}

// Size returns the number of registered consumer→producer bindings.
func (g *DependencyGraph) Size() int {
	return len(g.consumers)
}
