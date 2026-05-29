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
const storageVersion = 1

type storageIndex struct {
	Version    int       `json:"version"`
	EntryCount int       `json:"entry_count"`
	Hashes     []string  `json:"hashes"`
	SavedAt    time.Time `json:"saved_at"`
}

func entriesDir(dir string) string {
	return filepath.Join(dir, "entries")
}

// Save writes the entire corpus to dir. Each entry is stored as
// {dir}/entries/{hash}.json; a manifest at {dir}/index.json lists all hashes.
func (c *weightedCorpus) Save(dir string) error {
	if err := os.MkdirAll(entriesDir(dir), 0o755); err != nil {
		return fmt.Errorf("corpus save: create entries dir: %w", err)
	}

	c.mu.Lock()
	var all []*CorpusEntry
	for _, sc := range c.byOp {
		all = append(all, sc.all()...)
	}
	c.mu.Unlock()

	hashes := make([]string, 0, len(all))
	for _, e := range all {
		if err := saveEntry(dir, e); err != nil {
			log.Warnf("corpus save: entry %s: %v", e.Hash(), err)
			continue
		}
		hashes = append(hashes, e.Hash())
	}

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
	c.mu.Lock()
	for _, hash := range index.Hashes {
		if c.total >= maxCorpusSize {
			log.Warnf("corpus load: reached maxCorpusSize=%d, skipping remaining entries", maxCorpusSize)
			break
		}
		entry, err := loadEntry(dir, hash)
		if err != nil {
			log.Warnf("corpus load: entry %s: %v", hash, err)
			continue
		}
		// Bypass Add filters: restored entries already passed checks when saved.
		k := opKey(entry)
		sc, exists := c.byOp[k]
		if !exists {
			sc = &subCorpus{}
			c.byOp[k] = sc
			c.opOrder = append(c.opOrder, k)
		}
		if entry.Generation == 0 {
			sc.seeds = append(sc.seeds, entry)
		} else {
			sc.mutated = append(sc.mutated, entry)
		}
		c.hashes[entry.Hash()] = struct{}{}
		c.total++
		loaded++
	}
	c.mu.Unlock()

	log.Infof("corpus: loaded %d/%d entries from %s", loaded, len(index.Hashes), dir)
	return nil
}

func saveEntry(dir string, entry *CorpusEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	path := filepath.Join(entriesDir(dir), entry.Hash()+".json")
	return os.WriteFile(path, data, 0o644)
}

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
	_ = entry.Hash()
	return &entry, nil
}

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
