package mutator

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"shelob-ng/corpus"
)

func newByteLevel(seed int64) *byteLevelMutator {
	return &byteLevelMutator{rng: rand.New(rand.NewSource(seed))}
}

func TestByteLevelApply_EmptyBodyNotApplicable(t *testing.T) {
	m := newByteLevel(1)
	e := entryWithBody(nil)
	_, err := m.Apply(e)
	if !errors.Is(err, StrategyNotApplicable) {
		t.Errorf("expected StrategyNotApplicable, got %v", err)
	}
}

func TestByteLevelApply_ChangesBody(t *testing.T) {
	m := newByteLevel(42)
	original := []byte(`{"name":"alice","age":30}`)
	e := entryWithBody(original)

	result, err := m.Apply(e)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Equal(result.Body, original) {
		t.Error("Apply should change the body (at least 1 byte should differ)")
	}
}

func TestByteLevelApply_DoesNotMutateOriginal(t *testing.T) {
	m := newByteLevel(7)
	original := []byte(`{"x":1}`)
	backup := make([]byte, len(original))
	copy(backup, original)

	e := entryWithBody(original)
	m.Apply(e) //nolint:errcheck

	// The entry was passed as-is (caller is expected to pass a clone);
	// bitFlip etc. work on a copy of body before assigning.
	// For Apply itself: it copies body at the start, so original slice unchanged.
	if !bytes.Equal(original, backup) {
		t.Error("byteLevelMutator.Apply should not modify the original body slice")
	}
}

func TestBitFlip_ChangesExactlyOneBit(t *testing.T) {
	m := newByteLevel(0)
	for trial := 0; trial < 50; trial++ {
		body := []byte("abcdefgh")
		orig := make([]byte, len(body))
		copy(orig, body)

		result := m.bitFlip(body)

		diffBytes := 0
		diffBits := 0
		for i := range result {
			xor := result[i] ^ orig[i]
			if xor != 0 {
				diffBytes++
				for xor != 0 {
					diffBits += int(xor & 1)
					xor >>= 1
				}
			}
		}
		if diffBytes != 1 || diffBits != 1 {
			t.Errorf("bitFlip should flip exactly 1 bit; got %d differing bytes, %d differing bits", diffBytes, diffBits)
		}
	}
}

func TestDeletion_DecreasesLength(t *testing.T) {
	m := newByteLevel(3)
	body := []byte("hello world!")
	result := m.deletion(body)
	if len(result) >= len(body) {
		t.Errorf("deletion should shorten body: before=%d after=%d", len(body), len(result))
	}
}

func TestDeletion_SingleByte_Unchanged(t *testing.T) {
	m := newByteLevel(3)
	// deletion on a 1-byte body returns it unchanged (guard: len <= 1).
	body := []byte("X")
	result := m.deletion(body)
	if len(result) != 1 {
		t.Errorf("deletion of 1-byte body should return unchanged, got len=%d", len(result))
	}
}

func TestInsertion_IncreasesLength(t *testing.T) {
	m := newByteLevel(5)
	body := []byte("hello")
	result := m.insertion(body)
	if len(result) <= len(body) {
		t.Errorf("insertion should grow body: before=%d after=%d", len(body), len(result))
	}
}

func TestDuplication_IncreasesLength(t *testing.T) {
	m := newByteLevel(11)
	body := []byte("abcdef")
	result := m.duplication(body)
	if len(result) <= len(body) {
		t.Errorf("duplication should grow body: before=%d after=%d", len(body), len(result))
	}
}

func TestInteresting_ByteInKnownSet(t *testing.T) {
	m := newByteLevel(17)
	interesting := map[byte]bool{0x00: true, 0x01: true, 0x7f: true, 0x80: true, 0xfe: true, 0xff: true}
	for trial := 0; trial < 100; trial++ {
		body := []byte("unchanged")
		result := m.interesting(body)
		// At least one byte must be in the interesting set (the modified byte).
		found := false
		for _, b := range result {
			if interesting[b] {
				found = true
				break
			}
		}
		if !found {
			t.Error("interesting() should replace a byte with a known edge-case value")
		}
	}
}

// --- helpers ---

func entryWithBody(body []byte) *corpus.CorpusEntry {
	return &corpus.CorpusEntry{
		Method:       "POST",
		PathPattern:  "/x",
		PathParams:   make(map[string]interface{}),
		QueryParams:  make(map[string]string),
		HeaderParams: make(map[string]string),
		CookieParams: make(map[string]string),
		Body:         body,
	}
}
