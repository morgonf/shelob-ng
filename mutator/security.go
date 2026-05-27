package mutator

import (
	"math/rand"

	"shelob-ng/corpus"
	"shelob-ng/mutator/payloads"
)

// securityMutator injects security payloads (SQLi, XSS, SSTI, path traversal, etc.)
// into string-valued fields of a CorpusEntry.
//
// Targets exactly one field per Apply call (Decision 1A: MutationWidth=1).
// For body targets it descends into JSON string leaves via CollectStringLeaves;
// for scalar params it replaces the field value directly.
//
// Returns StrategyNotApplicable when:
//   - the payload set is empty (no payload files were loaded), or
//   - the entry has no string-valued targets (no injectable surface).
type securityMutator struct {
	rng      *rand.Rand
	payloads *payloads.Set
}

func (s *securityMutator) Name() string { return "security" }

func (s *securityMutator) Apply(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error) {
	if s.payloads == nil || s.payloads.Size() == 0 {
		return nil, StrategyNotApplicable
	}

	targets := PickStringFields(entry)
	if len(targets) == 0 {
		return nil, StrategyNotApplicable
	}

	target := targets[s.rng.Intn(len(targets))]
	payload := s.payloads.Random(s.rng)

	switch target.Kind {
	case FieldPath:
		entry.PathParams[target.Key] = payload
	case FieldQuery:
		entry.QueryParams[target.Key] = payload
	case FieldHeader:
		entry.HeaderParams[target.Key] = payload
	case FieldCookie:
		entry.CookieParams[target.Key] = payload
	case FieldBody:
		// Body injection failures (non-JSON, no string leaves) are non-fatal:
		// the entry lacks injectable body surface, not a fuzzer error.
		if err := s.injectIntoBody(entry, payload); err != nil {
			return nil, StrategyNotApplicable
		}
	}

	return entry, nil
}

// injectIntoBody picks a random string leaf in the JSON body and replaces it
// with payload. Returns StrategyNotApplicable when body is not a JSON object
// or has no string-valued leaves.
func (s *securityMutator) injectIntoBody(entry *corpus.CorpusEntry, payload string) error {
	obj, err := ParseJSONObject(entry.Body)
	if err != nil {
		// body is not a JSON object (array, scalar, raw bytes) — skip
		return StrategyNotApplicable
	}

	leaves := CollectStringLeaves(obj)
	if len(leaves) == 0 {
		return StrategyNotApplicable
	}

	leaf := leaves[s.rng.Intn(len(leaves))]
	// SetLeafString only errors when an intermediate key is not a map.
	// CollectStringLeaves only returns paths that already exist, so this
	// error is theoretically impossible but we propagate it for safety.
	if err := SetLeafString(obj, leaf, payload); err != nil {
		return err
	}

	body, err := MarshalBody(obj)
	if err != nil {
		return err
	}
	entry.Body = body
	return nil
}
