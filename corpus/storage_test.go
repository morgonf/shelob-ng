package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Build a corpus with two entries.
	orig := NewCorpusManager()
	e1 := makeEntry("GET", "/users/{id}", map[string]interface{}{"id": int64(1)}, nil)
	e2 := makeEntry("POST", "/orders", nil, []byte(`{"item":"book"}`))
	e2.QueryParams["filter"] = "new"

	orig.Add(e1, 3)
	orig.Add(e2, 7)

	if err := orig.Save(dir); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	// Verify index.json was written.
	if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
		t.Fatalf("index.json not found: %v", err)
	}

	// Load into a fresh corpus.
	restored := &weightedCorpus{
		byOp:   make(map[string]*subCorpus),
		hashes: make(map[string]struct{}),
	}
	if err := restored.Load(dir); err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if restored.Size() != 2 {
		t.Errorf("expected 2 entries after Load, got %d", restored.Size())
	}

	// Verify content round-trips by iterating all per-op buckets.
	var all []*CorpusEntry
	for _, sc := range restored.byOp {
		all = append(all, sc.all()...)
	}
	for _, e := range all {
		switch e.PathPattern {
		case "/users/{id}":
			if e.PathParams["id"] != int64(1) {
				t.Errorf("expected id=1, got %v (%T)", e.PathParams["id"], e.PathParams["id"])
			}
		case "/orders":
			if e.QueryParams["filter"] != "new" {
				t.Errorf("expected filter=new, got %q", e.QueryParams["filter"])
			}
			if string(e.Body) != `{"item":"book"}` {
				t.Errorf("body mismatch: %s", e.Body)
			}
		default:
			t.Errorf("unexpected path pattern: %s", e.PathPattern)
		}
	}
}

func TestLoad_NonExistentDir(t *testing.T) {
	c := &weightedCorpus{hashes: make(map[string]struct{})}
	err := c.Load("/tmp/shelob-test-nonexistent-dir-xyz")
	if err != nil {
		t.Errorf("Load of non-existent directory should return nil, got: %v", err)
	}
	if c.Size() != 0 {
		t.Error("corpus should be empty after loading non-existent dir")
	}
}

func TestLoad_WrongVersion(t *testing.T) {
	dir := t.TempDir()

	// Write an index with a wrong version number.
	badIndex := `{"version":99,"entry_count":0,"hashes":[],"saved_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(badIndex), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &weightedCorpus{hashes: make(map[string]struct{})}
	err := c.Load(dir)
	if err == nil {
		t.Error("Load with wrong version should return an error")
	}
}

func TestLoad_CorruptEntry(t *testing.T) {
	dir := t.TempDir()
	entDir := filepath.Join(dir, "entries")
	if err := os.MkdirAll(entDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write a valid index pointing to a corrupt entry file.
	hash := "deadbeef"
	index := `{"version":1,"entry_count":1,"hashes":["deadbeef"],"saved_at":"2026-01-01T00:00:00Z"}`
	os.WriteFile(filepath.Join(dir, "index.json"), []byte(index), 0o644)
	os.WriteFile(filepath.Join(entDir, hash+".json"), []byte("NOT JSON{{{"), 0o644)

	c := &weightedCorpus{hashes: make(map[string]struct{})}
	// Should not error — corrupt entries are skipped with a warning.
	if err := c.Load(dir); err != nil {
		t.Errorf("Load should tolerate corrupt entry files, got: %v", err)
	}
	if c.Size() != 0 {
		t.Error("corrupt entry should be skipped, corpus should be empty")
	}
}

func TestSave_AtomicWrite(t *testing.T) {
	// Verify that the temp+rename pattern leaves no .tmp file behind.
	dir := t.TempDir()
	c := NewCorpusManager()
	c.Add(makeEntry("GET", "/x", nil, nil), 1)

	if err := c.Save(dir); err != nil {
		t.Fatal(err)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(matches) > 0 {
		t.Errorf("found leftover .tmp files after Save: %v", matches)
	}
}
