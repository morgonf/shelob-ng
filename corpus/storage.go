package corpus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// storageVersion is bumped when the on-disk format changes incompatibly.
// Load rejects files with a different version to prevent silent corruption.
const storageVersion = 1

// storageIndex is the top-level manifest written to corpus-dir/index.json.
// It lists all entry hashes so Load can find individual entry files without
// scanning the directory.
type storageIndex struct {
	Version    int       `json:"version"`
	EntryCount int       `json:"entry_count"`
	Hashes     []string  `json:"hashes"`
	SavedAt    time.Time `json:"saved_at"`
}

// entriesDir returns the subdirectory path where individual entry files live.
func entriesDir(dir string) string {
	return filepath.Join(dir, "entries")
}

// Save writes the entire corpus to dir. Each entry is stored as
// {dir}/entries/{hash}.json; a manifest at {dir}/index.json lists all hashes.
//
// Save is safe to call concurrently with Add and Select: it acquires a read
// lock for the duration of the index build, then releases it before writing files.
func (c *weightedCorpus) Save(dir string) error {
	if err := os.MkdirAll(entriesDir(dir), 0o755); err != nil {
		return fmt.Errorf("corpus save: create entries dir: %w", err)
	}

	// Hold RLock while reading entries and writing their files. Save is infrequent
	// (called periodically or at shutdown), so briefly blocking Add/Select is
	// acceptable. Snapshotting only pointers and releasing the lock would create
	// a data race: Select() writes UseCount under write lock concurrently with
	// json.Marshal reading it in Save().
	c.mu.RLock()
	hashes := make([]string, 0, len(c.entries))
	for _, e := range c.entries {
		if err := saveEntry(dir, e); err != nil {
			log.Warnf("corpus save: entry %s: %v", e.Hash(), err)
			continue
		}
		hashes = append(hashes, e.Hash())
	}
	c.mu.RUnlock()

	index := storageIndex{
		Version:    storageVersion,
		EntryCount: len(hashes),
		Hashes:     hashes,
		SavedAt:    time.Now(),
	}
	if err := writeJSON(filepath.Join(dir, "index.json"), index); err != nil {
		return fmt.Errorf("corpus save: write index: %w", err)
	}

	log.Infof("corpus: saved %d entries to %s", len(hashes), dir)
	return nil
}

// Load reads corpus entries from dir using the index manifest.
// Entries that fail to parse are skipped with a warning.
// Not safe to call concurrently with Add or Select.
func (c *weightedCorpus) Load(dir string) error {
	indexPath := filepath.Join(dir, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Infof("corpus: no saved corpus at %s, starting fresh", dir)
			return nil
		}
		return fmt.Errorf("corpus load: read index: %w", err)
	}

	var index storageIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("corpus load: parse index: %w", err)
	}
	if index.Version != storageVersion {
		return fmt.Errorf("corpus load: unsupported format version %d (expected %d)", index.Version, storageVersion)
	}

	loaded := 0
	for _, hash := range index.Hashes {
		if len(c.entries) >= maxCorpusSize {
			log.Warnf("corpus load: reached maxCorpusSize=%d, skipping remaining entries", maxCorpusSize)
			break
		}
		entry, err := loadEntry(dir, hash)
		if err != nil {
			log.Warnf("corpus load: entry %s: %v", hash, err)
			continue
		}
		// Bypass Add filters: restored entries already passed delta and dedup
		// checks when first saved. Direct append preserves their metrics.
		c.entries = append(c.entries, entry)
		c.hashes[entry.Hash()] = struct{}{}
		loaded++
	}
	log.Infof("corpus: loaded %d/%d entries from %s", loaded, len(index.Hashes), dir)
	return nil
}

// saveEntry writes one CorpusEntry to {dir}/entries/{hash}.json.
func saveEntry(dir string, entry *CorpusEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	path := filepath.Join(entriesDir(dir), entry.Hash()+".json")
	return os.WriteFile(path, data, 0o644)
}

// loadEntry reads and parses {dir}/entries/{hash}.json, then recomputes the hash.
func loadEntry(dir string, hash string) (*CorpusEntry, error) {
	path := filepath.Join(entriesDir(dir), hash+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var entry CorpusEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	// Recompute hash after loading so the in-memory hash field is populated.
	// The hash field is excluded from JSON (json:"-") and must be rebuilt.
	_ = entry.Hash()
	return &entry, nil
}

// writeJSON is a helper that marshals v and writes it to path atomically
// (write to temp file, then rename).
func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
