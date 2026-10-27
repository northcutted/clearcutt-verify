package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEstateProgressKeepsJSONOnStdout(t *testing.T) {
	reg, host := commandTestRegistry(t)
	ref := host + "/acme/app:1"
	if _, err := reg.PushImage(ref, commandTestImage(t, 92)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(ref), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		flags []string
		show  bool
	}{
		{name: "redirected"},
		{name: "verbose", flags: []string{"--verbose"}, show: true},
		{name: "quiet overrides verbose", flags: []string{"--verbose", "--quiet"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cmd := NewRootCmd()
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			args := []string{"estate", "verify", "--refs", refs, "--out", filepath.Join(t.TempDir(), "estate"), "--format", "json"}
			cmd.SetArgs(append(args, tc.flags...))
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if !json.Valid(stdout.Bytes()) || strings.Contains(stdout.String(), "[verify-estate]") {
				t.Fatalf("stdout is not just JSON: %s", &stdout)
			}
			if got := strings.Contains(stderr.String(), "inspected 1/1"); got != tc.show {
				t.Fatalf("show progress=%v, stderr=%s", tc.show, &stderr)
			}
		})
	}
}

func TestProgressDoesNotMistakeFilesOrPipesForTerminals(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "progress")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	for _, f := range []*os.File{file, write, devnull} {
		if isTerminal(f) {
			t.Errorf("%s is not a terminal", f.Name())
		}
	}
}
