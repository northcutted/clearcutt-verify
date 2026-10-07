package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/evidence"

	"github.com/northcutted/clearcutt-verify/internal/config"
)

func TestCatalogWorkflowParamsWritesGitHubOutputs(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig("acme", "platform")
	cfg.Catalog.ReleaseLimit = 12
	cfg.Catalog.ScanDepth = "5"
	raw, err := config.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	cfgPath := filepath.Join(root, config.DefaultConfigPath)
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}
	ghOut := filepath.Join(root, "github-output")

	stdout, err := runCLI(t,
		"--format", "json",
		"catalog", "workflow-params",
		"--fleet-config", cfgPath,
		"--release-limit", "3",
		"--github-output", ghOut,
	)
	if err != nil {
		t.Fatalf("catalog workflow-params failed: %v\n%s", err, stdout)
	}
	var params catalogWorkflowParams
	if err := json.Unmarshal([]byte(stdout), &params); err != nil {
		t.Fatalf("stdout should be JSON: %v\n%s", err, stdout)
	}
	if params.ReleaseLimit != 3 || params.ScanDepth != "5" {
		t.Fatalf("unexpected params: %#v", params)
	}
	rawOut, err := os.ReadFile(ghOut)
	if err != nil {
		t.Fatalf("read github output: %v", err)
	}
	gh := string(rawOut)
	for _, want := range []string{"limit=3", "scan_depth=5"} {
		if !strings.Contains(gh, want) {
			t.Fatalf("github output missing %q:\n%s", want, gh)
		}
	}
}

func TestCatalogVexAllWritesPerImageDocuments(t *testing.T) {
	catalogDir := writeCommandSmokeCatalog(t)
	outputDir := filepath.Join(t.TempDir(), "vex")

	stdout, err := runCLI(t,
		"--catalog", catalogDir,
		"--format", "json",
		"catalog", "vex-all",
		"--output-dir", outputDir,
	)
	if err != nil {
		t.Fatalf("catalog vex-all failed: %v\n%s", err, stdout)
	}
	var result catalogVexAllResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout should be JSON: %v\n%s", err, stdout)
	}
	if result.Count != 1 || len(result.Images) != 1 || result.Images[0] != "java21-distroless" {
		t.Fatalf("unexpected vex-all result: %#v", result)
	}
	raw, err := os.ReadFile(filepath.Join(outputDir, "java21-distroless.json"))
	if err != nil {
		t.Fatalf("read generated VEX: %v", err)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse generated VEX: %v\n%s", err, raw)
	}
	if len(doc.Statements) == 0 {
		t.Fatalf("expected VEX statements in generated document: %#v", doc)
	}
}

// TestResolveReleaseSourceSelectsThePlane pins the control-plane switch. The
// catalog builder consumes a two-method ReleaseSource and never knew where
// evidence came from, which is exactly why the plane is swappable — this test
// guards that the swap is reachable and that a misconfiguration says so.
func TestResolveReleaseSourceSelectsThePlane(t *testing.T) {
	restore := catalogGatherOpts.evidenceSource
	t.Cleanup(func() { catalogGatherOpts.evidenceSource = restore })

	t.Run("explicit registry", func(t *testing.T) {
		catalogGatherOpts.evidenceSource = "registry"
		source, err := resolveReleaseSource("acme", "app", "ghcr.io/acme/app")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := source.(*evidence.ReleaseSource); !ok {
			t.Fatalf("expected an OCI release source, got %T", source)
		}
	})

	t.Run("explicit github", func(t *testing.T) {
		catalogGatherOpts.evidenceSource = "github"
		source, err := resolveReleaseSource("acme", "app", "ghcr.io/acme/app")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := source.(*evidence.ReleaseSource); ok {
			t.Fatal("explicit github must not silently use the registry")
		}
	})

	// The default must not move an existing fork onto a plane its evidence has
	// not been written to yet. Switching planes is a migration, not an upgrade
	// side effect — an earlier version defaulted to the registry whenever a
	// registry base was configured, and three offline tests immediately started
	// reaching for ghcr.io.
	t.Run("default is github even with a registry configured", func(t *testing.T) {
		catalogGatherOpts.evidenceSource = ""
		source, err := resolveReleaseSource("acme", "app", "ghcr.io/acme/app")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := source.(*evidence.ReleaseSource); ok {
			t.Fatal("the default must not silently repoint an existing fork at the registry")
		}
	})

	t.Run("registry without a base explains itself", func(t *testing.T) {
		catalogGatherOpts.evidenceSource = "registry"
		if _, err := resolveReleaseSource("acme", "app", ""); err == nil {
			t.Fatal("registry mode with no registry base should fail")
		} else if !strings.Contains(err.Error(), "registry base") {
			t.Fatalf("error should name the missing setting, got: %v", err)
		}
	})

	t.Run("unknown mode is rejected", func(t *testing.T) {
		catalogGatherOpts.evidenceSource = "auto"
		if _, err := resolveReleaseSource("acme", "app", "ghcr.io/acme/app"); err == nil {
			t.Fatal("an unrecognised evidence source should be rejected, not defaulted")
		}
	})
}
