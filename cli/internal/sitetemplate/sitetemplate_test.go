package sitetemplate

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/sitetemplate/rules"
)

// liveSiteDir returns the repository's site/ directory, or "" when it is not
// present (e.g. the module is consumed outside its source tree).
func liveSiteDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	siteDir := filepath.Clean(filepath.Join(filepath.Dir(self), "..", "..", "..", "site"))
	if info, err := os.Stat(siteDir); err != nil || !info.IsDir() {
		return ""
	}
	return siteDir
}

// TestEmbeddedTemplateMatchesSite guards against drift: the embedded template
// must be byte-identical to the live site/ directory under the shared exclusion
// rules. If this fails, run `go generate ./...`.
func TestEmbeddedTemplateMatchesSite(t *testing.T) {
	siteDir := liveSiteDir(t)
	if siteDir == "" {
		t.Skip("live site/ directory not present; skipping template drift check")
	}

	sub, err := FS()
	if err != nil {
		t.Fatalf("embedded FS: %v", err)
	}

	embeddedFiles := map[string][]byte{}
	if err := fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		embeddedFiles[filepath.ToSlash(p)] = data
		return nil
	}); err != nil {
		t.Fatalf("walk embedded template: %v", err)
	}

	seen := map[string]bool{}
	if err := filepath.WalkDir(siteDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(siteDir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		slashRel := filepath.ToSlash(rel)
		if rules.IsExcluded(slashRel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		want, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got, ok := embeddedFiles[slashRel]
		if !ok {
			t.Errorf("embedded template is missing %s (run `go generate ./...`)", slashRel)
			return nil
		}
		seen[slashRel] = true
		if !bytes.Equal(got, want) {
			t.Errorf("embedded template is stale for %s (run `go generate ./...`)", slashRel)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk site directory: %v", err)
	}

	for name := range embeddedFiles {
		if !seen[name] {
			t.Errorf("embedded template has a stale extra file %s (run `go generate ./...`)", name)
		}
	}
}

// TestMaterializeWritesPortableTemplate exercises the binary-only path that runs
// when site/ is absent: the embedded template must materialize a buildable
// project and must not carry the excluded data-pipeline inputs.
func TestMaterializeWritesPortableTemplate(t *testing.T) {
	dst := t.TempDir()
	if err := Materialize(dst); err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	for _, want := range []string{
		"package.json",
		"astro.config.mjs",
		filepath.Join("src", "lib", "catalog.ts"),
	} {
		if _, err := os.Stat(filepath.Join(dst, want)); err != nil {
			t.Errorf("expected materialized %s: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "src", "data")); !os.IsNotExist(err) {
		t.Errorf("src/data must be excluded from the embedded template, stat err=%v", err)
	}
}
