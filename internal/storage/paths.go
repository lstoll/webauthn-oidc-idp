package storage

import "strings"

// StateSQLitePath returns the SQLite database path for a configured state path.
// A legacy .bolt path selects a sibling .sqlite database; the BoltDB file is
// left untouched. Paths that already end in .sqlite are unchanged, and other
// paths receive a .sqlite suffix.
func StateSQLitePath(statePath string) string {
	if b, ok := strings.CutSuffix(statePath, ".bolt"); ok {
		return b + ".sqlite"
	}
	if strings.HasSuffix(statePath, ".sqlite") {
		return statePath
	}
	return statePath + ".sqlite"
}
