package commands

import (
	"bytes"
	"os"
	"testing"
)

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
