package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
)

// writeObservationsAt writes an observations file to an exact path, unlike
// writeObservationsFile which picks its own temp location.
func writeObservationsAt(t *testing.T, path string, obs estategraph.Observations) {
	t.Helper()
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestGraphReadsObservationsFromTheWorkingDirectory pins the ergonomic that
// `graph packages` always had and `graph build`/`graph layers` did not: stood
// in a directory holding an observations.json, the bare command answers. It is
// the difference between a tool you can try and one you have to study first.
func TestGraphReadsObservationsFromTheWorkingDirectory(t *testing.T) {
	for _, sub := range []string{"build", "layers"} {
		t.Run(sub, func(t *testing.T) {
			dir := t.TempDir()
			writeObservationsAt(t, filepath.Join(dir, "observations.json"), estategraph.Observations{
				Images: []estategraph.Observation{
					nixObs("reg/a:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2"),
					nixObs("reg/b:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2"),
				},
			})
			t.Chdir(dir)

			stdout, err := runCLI(t, "graph", sub)
			if err != nil {
				t.Fatalf("bare `graph %s` should read ./observations.json: %v\n%s", sub, err, stdout)
			}
			if !strings.Contains(stdout, "2 image(s)") {
				t.Errorf("both observed images should be reported:\n%s", stdout)
			}
		})
	}
}

// TestGraphWritesNothingUnlessAsked: --output used to be required, so the only
// way to see the report was to leave a JSON file behind. Now the terminal is
// the default surface, and a command that was told to write nothing must
// neither create a file nor claim it wrote one.
func TestGraphWritesNothingUnlessAsked(t *testing.T) {
	for _, sub := range []string{"build", "layers"} {
		t.Run(sub, func(t *testing.T) {
			dir := t.TempDir()
			writeObservationsAt(t, filepath.Join(dir, "observations.json"), estategraph.Observations{
				Images: []estategraph.Observation{nixObs("reg/a:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2")},
			})
			t.Chdir(dir)

			stdout, err := runCLI(t, "graph", sub)
			if err != nil {
				t.Fatalf("graph %s: %v\n%s", sub, err, stdout)
			}
			if strings.Contains(stdout, "wrote") {
				t.Errorf("nothing was requested, so nothing should be announced as written:\n%s", stdout)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != "observations.json" {
					t.Errorf("graph %s left behind %s; --output was not passed", sub, e.Name())
				}
			}

			// The opposite direction: asked for a file, it writes one and says so.
			out := filepath.Join(dir, "graph.json")
			stdout, err = runCLI(t, "graph", sub, "--output", out)
			if err != nil {
				t.Fatalf("graph %s --output: %v\n%s", sub, err, stdout)
			}
			if !strings.Contains(stdout, "wrote "+out) {
				t.Errorf("an explicit --output should still be announced:\n%s", stdout)
			}
			if _, err := os.Stat(out); err != nil {
				t.Errorf("an explicit --output should still produce the file: %v", err)
			}
		})
	}
}
