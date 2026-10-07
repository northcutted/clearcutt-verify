package commands

import (
	"os"
	"path/filepath"

	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/spf13/cobra"
)

// repoRootMarkers identify the root of a ClearCutt checkout (or fork). The
// fleet config is the operator-facing marker; go.work covers contributor
// checkouts of this repository itself.
// repoRootMarkers accept both config names: a fork that has not migrated must
// still be recognised as a checkout.
var repoRootMarkers = []string{config.DefaultConfigPath, config.LegacyConfigPath, "go.work"}

// findRepoRoot walks upward from the current working directory looking for a
// repo marker, stopping at the filesystem root. It returns ("", false) when no
// marker is found, in which case callers keep today's cwd-relative behavior.
func findRepoRoot() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		for _, marker := range repoRootMarkers {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return dir, true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// resolveRepoRootDefault rebases a path flag's *default* value onto the repo
// root, so commands that write into the canonical roots (core/, docs/,
// examples/, site/) land there even when run from a subdirectory such as cli/
// instead of scattering stray nested trees. Explicitly passed flags and
// absolute defaults keep their exact meaning, and when no repo marker is found
// the cwd-relative default is preserved.
func resolveRepoRootDefault(cmd *cobra.Command, flagName string, target *string) {
	if flag := cmd.Flags().Lookup(flagName); flag == nil || flag.Changed {
		return
	}
	if *target == "" || filepath.IsAbs(*target) {
		return
	}
	if root, ok := findRepoRoot(); ok {
		*target = filepath.Join(root, *target)
	}
}
