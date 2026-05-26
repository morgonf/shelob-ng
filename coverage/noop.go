package coverage

import "context"

// noopClient implements Client as a no-op.
// Used when BaseURL is not configured: the fuzzer runs without coverage
// feedback, delta is always 0, and corpus.Add never stores entries (except
// seeds). This preserves full compatibility with original Shelob behaviour.
type noopClient struct{}

func (noopClient) Reset(_ context.Context) error        { return nil }
func (noopClient) Dump(_ context.Context) (Snapshot, error) { return Snapshot{}, nil }
