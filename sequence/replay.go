package sequence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// SaveReplay writes r as a JSON file under <dir>/replays/ when the replay
// contains at least one finding. Silent no-op when findings list is empty.
func SaveReplay(r Replay, dir string) {
	if len(r.Findings) == 0 {
		return
	}

	replayDir := filepath.Join(dir, "replays")
	if err := os.MkdirAll(replayDir, 0o755); err != nil {
		log.Warnf("sequence: mkdir %s: %v", replayDir, err)
		return
	}

	ts := time.Now().Format("20060102_150405_000")
	safe := sanitizeName(r.SequenceName)
	path := filepath.Join(replayDir, safe+"_"+ts+".json")

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		log.Warnf("sequence: marshal replay: %v", err)
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Warnf("sequence: write %s: %v", path, err)
		return
	}
	log.Debugf("sequence: replay saved to %s", path)
}

// sanitizeName converts an arbitrary sequence name into a filesystem-safe slug.
func sanitizeName(name string) string {
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '_'
	}, name)
	// Truncate very long names (path strings can be verbose).
	if len(safe) > 64 {
		safe = fmt.Sprintf("%s_%x", safe[:54], len(name))
	}
	return safe
}
