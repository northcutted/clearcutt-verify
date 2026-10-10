package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
)

func TestImportedFleetCommandWorkflowOffline(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	exampleDir := filepath.Join(root, "examples", "imported-fleet")
	work := t.TempDir()
	images := filepath.Join(work, "images.yaml")
	observations := filepath.Join(work, "observations.json")
	governance := filepath.Join(work, "governance")
	report := filepath.Join(work, "report.md")
	graph := filepath.Join(work, "graph.json")
	stamp := "2026-01-01T00:00:00Z"

	stdout, err := runCLI(t, "--format", "json", "import", "images",
		"--refs", filepath.Join(exampleDir, "refs.txt"),
		"--output", images,
		"--owner", "acme",
		"--repo", "imported-fleet",
		"--registry-base", "registry.acme.dev/platform",
		"--generated-at", stamp,
	)
	if err != nil || !strings.Contains(stdout, `"imageCount": 4`) {
		t.Fatalf("import images failed: %v\n%s", err, stdout)
	}
	if _, err := runCLI(t, "import", "images", "--refs", filepath.Join(exampleDir, "refs.txt"), "--output", images); err == nil {
		t.Fatal("import images should refuse an existing output without --force")
	}

	stdout, err = runCLI(t, "--format", "json", "import", "observe",
		"--images", images,
		"--offline-fixtures", filepath.Join(exampleDir, "observations.fixture.json"),
		"--output", observations,
		"--generated-at", stamp,
	)
	if err != nil || !strings.Contains(stdout, `"kind": "ImportedFleetObservations"`) {
		t.Fatalf("import observe failed: %v\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "--format", "json", "import", "assess",
		"--images", images,
		"--observations", observations,
		"--output", governance,
		"--generated-at", stamp,
	)
	if err != nil || !strings.Contains(stdout, `"importedImages": 4`) {
		t.Fatalf("import assess failed: %v\n%s", err, stdout)
	}
	if stdout, err = runCLI(t, "import", "report", "--assessment", governance, "--output", report); err != nil {
		t.Fatalf("import report failed: %v\n%s", err, stdout)
	}
	reportRaw, err := os.ReadFile(report)
	if err != nil || !strings.Contains(string(reportRaw), "ClearCutt did not build") {
		t.Fatalf("unexpected report: %v\n%s", err, reportRaw)
	}

	if stdout, err = runCLI(t, "graph", "build", "--observations", observations, "--output", graph); err != nil {
		t.Fatalf("graph build failed: %v\n%s", err, stdout)
	}
	var g estategraph.Graph
	raw, err := os.ReadFile(graph)
	if err != nil || json.Unmarshal(raw, &g) != nil || len(g.Edges) == 0 {
		t.Fatalf("graph: %v %+v", err, g.Edges)
	}
}
