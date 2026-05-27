package mutator

import (
	"math/rand"

	"shelob-ng/corpus"
)

// byteLevelMutator applies raw byte mutations to entry.Body.
// It treats Body as an opaque byte slice with no knowledge of content type or schema.
// This finds bugs that structural mutation misses: truncated reads, integer overflows
// in length fields, parser edge cases in binary protocols embedded in JSON strings.
//
// Returns StrategyNotApplicable when entry.Body is nil or empty.
type byteLevelMutator struct {
	rng *rand.Rand
}

func (b *byteLevelMutator) Name() string { return "byte_level" }

// Apply picks one byte-level operation at random and applies it to a copy of Body.
func (b *byteLevelMutator) Apply(entry *corpus.CorpusEntry) (*corpus.CorpusEntry, error) {
	if len(entry.Body) == 0 {
		return nil, StrategyNotApplicable
	}

	// Work on a copy so failed operations don't corrupt entry.Body.
	body := make([]byte, len(entry.Body))
	copy(body, entry.Body)

	ops := []func([]byte) []byte{
		b.bitFlip,
		b.byteFlip,
		b.insertion,
		b.deletion,
		b.duplication,
		b.interesting,
	}
	body = ops[b.rng.Intn(len(ops))](body)

	entry.Body = body
	return entry, nil
}

// bitFlip inverts one random bit. The narrowest possible mutation — changes
// exactly one bit, often producing off-by-one values in numeric fields.
func (b *byteLevelMutator) bitFlip(body []byte) []byte {
	idx := b.rng.Intn(len(body))
	bit := byte(1 << b.rng.Intn(8))
	body[idx] ^= bit
	return body
}

// byteFlip replaces one random byte with a uniformly random value.
func (b *byteLevelMutator) byteFlip(body []byte) []byte {
	body[b.rng.Intn(len(body))] = byte(b.rng.Intn(256))
	return body
}

// insertion inserts 1–8 random bytes at a random position.
// Useful for finding off-by-one errors in length-delimited parsers.
func (b *byteLevelMutator) insertion(body []byte) []byte {
	n := 1 + b.rng.Intn(8)
	pos := b.rng.Intn(len(body) + 1)
	extra := make([]byte, n)
	for i := range extra {
		extra[i] = byte(b.rng.Intn(256))
	}
	result := make([]byte, 0, len(body)+n)
	result = append(result, body[:pos]...)
	result = append(result, extra...)
	result = append(result, body[pos:]...)
	return result
}

// deletion removes 1–8 bytes starting at a random position.
// Useful for finding crashes caused by short reads or missing terminators.
func (b *byteLevelMutator) deletion(body []byte) []byte {
	if len(body) <= 1 {
		return body
	}
	n := 1 + b.rng.Intn(min(8, len(body)-1))
	pos := b.rng.Intn(len(body) - n + 1)
	return append(body[:pos:pos], body[pos+n:]...)
}

// duplication copies a random slice to a random offset.
// Produces repeated structures that stress sequence-of-objects parsers.
func (b *byteLevelMutator) duplication(body []byte) []byte {
	if len(body) < 2 {
		return body
	}
	// Pick source slice.
	srcStart := b.rng.Intn(len(body))
	srcEnd := srcStart + 1 + b.rng.Intn(len(body)-srcStart)
	chunk := body[srcStart:srcEnd]

	// Insert at random destination.
	dst := b.rng.Intn(len(body) + 1)
	result := make([]byte, 0, len(body)+len(chunk))
	result = append(result, body[:dst]...)
	result = append(result, chunk...)
	result = append(result, body[dst:]...)
	return result
}

// interesting replaces one byte with a value known to trigger edge cases:
// bounds of signed/unsigned 8-bit integers and common sentinel values.
func (b *byteLevelMutator) interesting(body []byte) []byte {
	// These values exercise: null terminator, signed overflow, unsigned max,
	// ASCII boundary, and two adjacent boundary pairs.
	interesting := []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff}
	body[b.rng.Intn(len(body))] = interesting[b.rng.Intn(len(interesting))]
	return body
}

// min returns the smaller of two ints (stdlib min is available in Go 1.21+;
// this local version avoids a version constraint on the module).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
