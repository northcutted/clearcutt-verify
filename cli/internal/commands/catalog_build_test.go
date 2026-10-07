package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
	"github.com/northcutted/clearcutt-verify/internal/config"
)

func TestCatalogBuildRunsOfflinePipelineWithFleetConfig(t *testing.T) {
	const (
		runtimeTarget = "python3.13-slim"
		serviceTarget = "postgres16"
		tag           = "v1.0.0"
		publishedAt   = "2026-06-09T12:00:00Z"
	)

	root := t.TempDir()
	outDir := filepath.Join(root, "catalog")
	sbomDir := filepath.Join(root, "sboms")
	enrichmentDir := filepath.Join(root, "enrichment")
	vulnDir := filepath.Join(root, "vulns")

	for _, target := range []string{runtimeTarget, serviceTarget} {
		writeTestFile(t, filepath.Join(enrichmentDir, tag, target+".json"), []byte(`{
  "manifestDigest": "sha256:`+target+`-manifest",
  "architectures": [
    {
      "arch": "amd64",
      "digest": "sha256:`+target+`-amd64",
      "size": 42,
      "layers": [],
      "labels": {}
    }
  ],
  "signature": {
    "cosignBundlePresent": true
  },
  "provenance": {
    "predicateType": "https://slsa.dev/provenance/v1",
    "builder": { "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml" },
    "slsaLevel": 3
  },
  "attestations": [
    {
      "kind": "slsa-provenance",
      "predicateType": "https://slsa.dev/provenance/v1",
      "sources": ["oci", "github"]
    }
  ]
}`))
		writeTestFile(t, filepath.Join(vulnDir, tag, target+"-amd64.json"), []byte(`{"scannedAt":"2026-06-09T12:30:00Z","scanner":"grype-test","dbBuiltAt":null,"countsBySeverity":{"critical":0,"high":0,"medium":0,"low":0,"negligible":0,"unknown":0},"findings":[]}`))
	}

	spdxRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCatalogReleaseSource{
		releases: []catalogbuild.Release{{
			Tag:         tag,
			Name:        "v1.0.0",
			PublishedAt: publishedAt,
			Assets: []catalogbuild.Asset{
				{Name: runtimeTarget + "-amd64.sbom.json", URL: "https://example.invalid/" + runtimeTarget + "-amd64.sbom.json"},
				{Name: runtimeTarget + "-amd64.test-results.json", URL: "https://example.invalid/" + runtimeTarget + "-amd64.test-results.json"},
				{Name: serviceTarget + "-amd64.sbom.json", URL: "https://example.invalid/" + serviceTarget + "-amd64.sbom.json"},
				{Name: serviceTarget + "-amd64.test-results.json", URL: "https://example.invalid/" + serviceTarget + "-amd64.test-results.json"},
			},
		}},
		assets: map[string][]byte{
			runtimeTarget + "-amd64.sbom.json":         spdxRaw,
			runtimeTarget + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-06-09T12:05:00Z","assertions":[{"name":"Syft SBOM Generation","status":"passed"}]}`),
			serviceTarget + "-amd64.sbom.json":         spdxRaw,
			serviceTarget + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-06-09T12:06:00Z","assertions":[{"name":"Service Smoke","status":"passed"}]}`),
		},
	}
	oldNewReleaseSource := newReleaseSource
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		if owner != "acme" || repo != "platform" {
			t.Fatalf("unexpected release source request for %s/%s", owner, repo)
		}
		return source
	}
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })

	cfg := config.DefaultConfig("acme", "platform")
	cfg.Matrix.Languages = []string{"python3.13"}
	cfg.Matrix.Tiers = []string{"slim"}
	cfg.Catalog.ReleaseLimit = 1
	cfg.Catalog.ScanDepth = "1"
	cfg.Services = []config.ServiceImage{{
		ID:       serviceTarget,
		Template: "postgres",
		Version:  "16",
		Smoke:    []string{"postgres --version"},
	}}
	raw, err := config.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	configPath := filepath.Join(root, config.DefaultConfigPath)
	if err := os.WriteFile(configPath, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}

	t.Setenv("ENRICHMENT_DIR", enrichmentDir)
	t.Setenv("SBOM_CACHE_DIR", sbomDir)
	t.Setenv("VULN_DIR", vulnDir)
	t.Setenv("GATHER_TAGS", tag)
	t.Setenv("GRYPE_BIN", filepath.Join(root, "missing-grype"))

	stdout, err := runCLI(t,
		"--catalog", outDir,
		"catalog", "build",
		"--config", configPath,
		"--include-services",
	)
	if err != nil {
		t.Fatalf("catalog build failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[gather] wrote " + runtimeTarget + " (1 releases)",
		"[gather] wrote service " + serviceTarget + " (1 releases)",
		"[enrich] done fetched=0 cached=2",
		"[catalog-verify] ok: 2 latest images",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected catalog build output %q, got:\n%s", want, stdout)
		}
	}

	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("load generated index: %v", err)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersionV2 || len(index.Images) != 2 {
		t.Fatalf("expected v2 mixed catalog index, got %#v", index)
	}
	summaryRaw, err := os.ReadFile(filepath.Join(outDir, "summary.json"))
	if err != nil {
		t.Fatalf("expected generated summary: %v", err)
	}
	var summary catalogSummaryReport
	if err := json.Unmarshal(summaryRaw, &summary); err != nil {
		t.Fatalf("decode summary: %v\n%s", err, summaryRaw)
	}
	if summary.ImageCount != 2 || summary.SignedCount != 2 || summary.ProvenanceCount != 2 || summary.SBOMCount != 2 || summary.ScanCount != 2 {
		t.Fatalf("unexpected generated summary: %#v", summary)
	}
	assertRawEvidenceDirs(t, outDir)
}
