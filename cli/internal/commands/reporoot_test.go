package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/spf13/cobra"
)

// reporootSentinel is the runtime line these tests `matrix add` to observe
// which file a write landed in. Every fixture config below filters it out, so
// the tests stay valid regardless of which lines DefaultConfig selects.
const reporootSentinel = "python3.14"

// writeConfigWithoutSentinel writes a fleet config whose matrix is the
// default minus reporootSentinel, so adding the sentinel is always a real
// mutation of that file.
func writeConfigWithoutSentinel(t *testing.T, dir string) string {
	t.Helper()
	cfg := config.DefaultConfig("acme", "platform")
	languages := make([]string, 0, len(cfg.Matrix.Languages))
	for _, lang := range cfg.Matrix.Languages {
		if lang != reporootSentinel {
			languages = append(languages, lang)
		}
	}
	cfg.Matrix.Languages = languages
	path := filepath.Join(dir, config.DefaultConfigPath)
	writeConfigStruct(t, path, cfg)
	return path
}

// fakeRepo builds a temp checkout with a ClearCutt config at its root (the
// repo marker) plus a nested subdirectory mimicking running from cli/internal.
func fakeRepo(t *testing.T) (root, subdir string) {
	t.Helper()
	root = t.TempDir()
	writeConfigWithoutSentinel(t, root)
	subdir = filepath.Join(root, "cli", "internal")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("create subdir: %v", err)
	}
	return root, subdir
}

// samePath compares paths through symlinks (macOS temp dirs live under
// /var -> /private/var, so Getwd-derived paths differ textually).
func samePath(t *testing.T, got, want string) bool {
	t.Helper()
	gotResolved, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("eval symlinks %q: %v", got, err)
	}
	wantResolved, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatalf("eval symlinks %q: %v", want, err)
	}
	return gotResolved == wantResolved
}

func TestFindRepoRootWalksUpToFleetConfigMarker(t *testing.T) {
	root, subdir := fakeRepo(t)
	t.Chdir(subdir)

	got, ok := findRepoRoot()
	if !ok {
		t.Fatalf("expected to find repo root above %s", subdir)
	}
	if !samePath(t, got, root) {
		t.Fatalf("findRepoRoot() = %q, want %q", got, root)
	}
}

func TestResolveRepoRootDefaultGuards(t *testing.T) {
	root, subdir := fakeRepo(t)
	t.Chdir(subdir)

	abs := filepath.Join(root, "pinned.yaml")
	empty := ""
	rel := config.DefaultConfigPath
	cmd := &cobra.Command{Use: "guard"}
	cmd.Flags().StringVar(&abs, "abs", abs, "")
	cmd.Flags().StringVar(&empty, "empty", empty, "")
	cmd.Flags().StringVar(&rel, "rel", rel, "")

	// Absolute defaults keep their exact meaning.
	resolveRepoRootDefault(cmd, "abs", &abs)
	if abs != filepath.Join(root, "pinned.yaml") {
		t.Fatalf("absolute default was rewritten to %q", abs)
	}
	// Empty defaults (computed later by the command) are left alone.
	resolveRepoRootDefault(cmd, "empty", &empty)
	if empty != "" {
		t.Fatalf("empty default was rewritten to %q", empty)
	}
	// Unknown flag names are a no-op rather than a panic.
	missing := "untouched"
	resolveRepoRootDefault(cmd, "missing", &missing)
	if missing != "untouched" {
		t.Fatalf("missing flag lookup mutated target to %q", missing)
	}
	// Relative defaults are rebased onto the marker root.
	resolveRepoRootDefault(cmd, "rel", &rel)
	if !samePath(t, filepath.Dir(rel), root) {
		t.Fatalf("relative default %q did not land at repo root %q", rel, root)
	}
}

// writeConfigStruct writes a config to an exact PATH (not a directory),
// which is what repo-root detection uses as its marker.
func writeConfigStruct(t *testing.T, path string, cfg config.Config) {
	t.Helper()
	raw, err := config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
