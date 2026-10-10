package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGlobalFormatValidation(t *testing.T) {
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte("cgr.dev/chainguard/static:latest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n := 0
	importImages := func(format string) (string, error) {
		n++
		return runCLI(t, "import", "images", "--refs", refs, "--output", filepath.Join(dir, fmt.Sprintf("images-%d.yaml", n)), "--format", format)
	}

	stdout, err := importImages("jsno")
	if err == nil || err.Error() != `unknown --format "jsno" (expected table, json, or yaml)` {
		t.Fatalf("unknown --format: %v\n%s", err, stdout)
	}
	for _, format := range []string{"table", "json", "yaml", "yml", "JSON", "Table", "YAML"} {
		if stdout, err := importImages(format); err != nil {
			t.Fatalf("--format %s should be accepted: %v\n%s", format, err, stdout)
		}
	}
	if stdout, err := runCLI(t, "estate", "verify", "--format", "xml"); err == nil || !strings.Contains(err.Error(), `unknown --format "xml"`) {
		t.Fatalf("format validation on estate verify: %v\n%s", err, stdout)
	}
}
