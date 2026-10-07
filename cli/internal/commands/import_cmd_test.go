package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/estategraph"
)

func TestImportedFleetCommandWorkflowOffline(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	exampleDir := filepath.Join(root, "examples", "imported-fleet")
	work := t.TempDir()
	images := filepath.Join(work, "images.yaml")
	catalogDir := filepath.Join(work, "catalog")
	observations := filepath.Join(work, "observations.json")
	governance := filepath.Join(work, "governance")
	report := filepath.Join(work, "report.md")
	candidatesPath := filepath.Join(work, "rebase", "candidates.json")
	planPath := filepath.Join(work, "rebase", "plan.json")
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

	if stdout, err = runCLI(t, "catalog", "generate", "--images", images, "--output", catalogDir, "--owner", "acme", "--repo", "imported-fleet", "--registry-base", "registry.acme.dev/platform", "--generated-at", stamp); err != nil {
		t.Fatalf("catalog generate failed: %v\n%s", err, stdout)
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
	if stdout, err = runCLI(t, "import", "apply-evidence", "--catalog", catalogDir, "--observations", observations); err != nil {
		t.Fatalf("apply evidence failed: %v\n%s", err, stdout)
	}
	if stdout, err = runCLI(t, "--catalog", catalogDir, "catalog", "validate", "--schema-version", catalog.EvidenceManifestSchemaVersion); err != nil {
		t.Fatalf("catalog validate failed: %v\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "--format", "json", "import", "assess",
		"--images", images,
		"--catalog", catalogDir,
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

	stdout, err = runCLI(t, "--format", "json", "rebase", "discover",
		"--apps", filepath.Join(exampleDir, "apps.yaml"),
		"--bases", images,
		"--observations", observations,
		"--output", candidatesPath,
		"--generated-at", stamp,
	)
	if err != nil || !strings.Contains(stdout, `"confidence": "verified"`) {
		t.Fatalf("rebase discover failed: %v\n%s", err, stdout)
	}
	candidateRaw, err := os.ReadFile(candidatesPath)
	if err != nil {
		t.Fatal(err)
	}
	var candidates estategraph.RebaseCandidateSet
	if err := json.Unmarshal(candidateRaw, &candidates); err != nil {
		t.Fatal(err)
	}
	if len(candidates.Candidates) != 1 || len(candidates.Candidates[0].NewBaseCandidates) != 1 {
		t.Fatalf("unexpected candidates: %#v", candidates.Candidates)
	}
	stdout, err = runCLI(t, "--format", "json", "rebase", "plan",
		"--candidate", candidates.Candidates[0].ID,
		"--candidates", candidatesPath,
		"--new-base", candidates.Candidates[0].NewBaseCandidates[0],
		"--observations", observations,
		"--output", planPath,
	)
	if err != nil || !strings.Contains(stdout, `"allowedToApplyAutomatically": false`) {
		t.Fatalf("rebase plan failed: %v\n%s", err, stdout)
	}
	if _, err := os.Stat(planPath); err != nil {
		t.Fatalf("missing rebase plan: %v", err)
	}
}
