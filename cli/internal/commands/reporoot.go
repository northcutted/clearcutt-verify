package commands

import (
	"os"
	"path/filepath"
)

// findRepoRoot walks up from the working directory to the repository root,
// marked by go.work. Tests use it to find the docs and workflows.
func findRepoRoot() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}
