package mutator

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseJSONObject parses body as a JSON object into map[string]interface{}.
// Returns an error when body is not a valid JSON object (arrays, scalars,
// and invalid JSON are all rejected — they cannot be field-targeted).
func ParseJSONObject(body []byte) (map[string]interface{}, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	return obj, nil
}

// MarshalBody serialises obj back to compact JSON bytes.
func MarshalBody(obj map[string]interface{}) ([]byte, error) {
	return json.Marshal(obj)
}

// SetLeafString sets the value at a dotted key path to v within obj.
// Intermediate keys are created as maps when absent.
// Example: SetLeafString(obj, "user.name", "payload") → obj["user"]["name"] = "payload"
//
// Returns an error when an intermediate key exists but is not a map
// (type collision makes the path unresolvable).
func SetLeafString(obj map[string]interface{}, path string, v string) error {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) == 1 {
		obj[path] = v
		return nil
	}

	key, rest := parts[0], parts[1]
	switch child := obj[key].(type) {
	case map[string]interface{}:
		return SetLeafString(child, rest, v)
	case nil:
		// Create intermediate map.
		nested := make(map[string]interface{})
		obj[key] = nested
		return SetLeafString(nested, rest, v)
	default:
		return fmt.Errorf("path %q: intermediate key %q is not a map (got %T)", path, key, child)
	}
}

// CollectStringLeaves returns dotted paths to all string-valued leaf nodes
// in a nested JSON object. Used by securityMutator to enumerate injection targets.
// Limited to depth 10 to avoid excessive recursion on deeply nested bodies.
func CollectStringLeaves(obj map[string]interface{}) []string {
	var paths []string
	collectLeaves(obj, "", &paths, 0)
	return paths
}

func collectLeaves(obj map[string]interface{}, prefix string, out *[]string, depth int) {
	const maxDepth = 10
	if depth > maxDepth {
		return
	}
	for k, v := range obj {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch child := v.(type) {
		case string:
			*out = append(*out, path)
		case map[string]interface{}:
			collectLeaves(child, path, out, depth+1)
		}
		// Arrays and non-string primitives are not injection targets at this stage.
	}
}

// AddField adds field with value to obj when field is absent. No-op when present.
func AddField(obj map[string]interface{}, field string, value interface{}) {
	if _, exists := obj[field]; !exists {
		obj[field] = value
	}
}

// RemoveField removes field from obj. No-op when absent.
func RemoveField(obj map[string]interface{}, field string) {
	delete(obj, field)
}
