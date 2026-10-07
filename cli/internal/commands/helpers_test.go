package commands

import (
	"bytes"
	"github.com/northcutted/clearcutt-verify/internal/config"
	"os"
	"path/filepath"
	"testing"
)

// fixtureCatalog is the path to the committed test catalog fixture.
func fixtureCatalog() string {
	return filepath.Join("..", "testdata", "catalog")
}

func mixedFixtureCatalog() string {
	return filepath.Join("..", "testdata", "mixed-catalog")
}

// runCLI executes the full root command with the given args, capturing everything
// written to the package output writers. It exercises real flag parsing, command
// wiring, and the error model, and returns captured stdout plus the Execute error.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var buf bytes.Buffer
	oldOut, oldErr := out, errOut
	out, errOut = &buf, &buf
	defer func() { out, errOut = oldOut, oldErr }()

	cmd := NewRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	return buf.String(), err
}

// writeExecutable writes a file with the executable bit set. Tests use it to stand
// up fake tools on PATH.
func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// writeConfig writes the default config into dir and returns its path.
func writeConfig(t *testing.T, dir string) string {
	t.Helper()
	raw, err := config.Marshal(config.DefaultConfig("acme", "platform"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, config.DefaultConfigPath)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func stringPtr(v string) *string { return &v }
