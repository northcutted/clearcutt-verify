package commands

import (
	"bytes"
	"context"
	"errors"
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

// withCosign stands in for cosign for the rest of the test: it says it is
// version (v3.1.3 when empty), and answers every other run with run, or,
// without one, as cosign does when nothing verifies.
func withCosign(t *testing.T, version string, run func(args []string) ([]byte, error)) {
	t.Helper()
	if version == "" {
		version = "v3.1.3"
	}
	old := cosignRunner
	cosignRunner = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "version" {
			return []byte(`{"gitVersion":"` + version + `"}`), nil
		}
		if run == nil {
			return nil, errors.New("error during command execution: no matching signatures")
		}
		return run(args)
	}
	t.Cleanup(func() { cosignRunner = old })
}
