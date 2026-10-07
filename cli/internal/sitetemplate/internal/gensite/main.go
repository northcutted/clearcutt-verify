// Command gensite regenerates the embedded Astro catalog template from the live
// site/ directory at the repository root.
//
// Run it with `go generate ./...` from the cli module (or directly with
// `go run ./internal/gensite` from the sitetemplate package) whenever site/
// changes. The TestEmbeddedTemplateMatchesSite drift test fails if the embedded
// copy is stale, so CI catches a forgotten regeneration.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/northcutted/clearcutt-verify/internal/sitetemplate/rules"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gensite:", err)
		os.Exit(1)
	}
}

func run() error {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("cannot resolve generator source path")
	}
	genDir := filepath.Dir(self)                                        // cli/internal/sitetemplate/internal/gensite
	pkgDir := filepath.Clean(filepath.Join(genDir, "..", ".."))         // cli/internal/sitetemplate
	repoRoot := filepath.Clean(filepath.Join(pkgDir, "..", "..", "..")) // repository root
	siteDir := filepath.Join(repoRoot, "site")
	destDir := filepath.Join(pkgDir, "template")
	return runFrom(siteDir, destDir)
}

func runFrom(siteDir, destDir string) error {
	if info, err := os.Stat(siteDir); err != nil || !info.IsDir() {
		return fmt.Errorf("live site directory not found at %s: %w", siteDir, err)
	}
	if err := os.RemoveAll(destDir); err != nil {
		return err
	}

	count := 0
	walkErr := filepath.WalkDir(siteDir, func(p string, d fs.DirEntry, err error) error {
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
		if rules.IsExcluded(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(destDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := copyFile(p, target); err != nil {
			return err
		}
		count++
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	fmt.Printf("gensite: wrote %d files from %s to %s\n", count, siteDir, destDir)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
