package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
)

// assertCatalogSatisfiesSchemas runs the full catalog validator (structural
// checks plus embedded JSON Schema validation) and fails on any error.
func assertCatalogSatisfiesSchemas(t *testing.T, catalogPath string) {
	t.Helper()
	oldOpts := catalogValidateOpts
	catalogValidateOpts = catalogValidateFlags{}
	defer func() { catalogValidateOpts = oldOpts }()

	report := validateCatalogDirectory(catalogPath)
	if report.ErrorCount != 0 {
		t.Fatalf("catalog %s has %d validation error(s):\n%s", catalogPath, report.ErrorCount, strings.Join(report.Errors, "\n"))
	}
}

// TestTestdataCatalogsSatisfyEmbeddedSchemas keeps every committed catalog
// fixture aligned with the published JSON Schema contract the generator emits.
func TestTestdataCatalogsSatisfyEmbeddedSchemas(t *testing.T) {
	for _, dir := range []string{"catalog", "dev-catalog", "mixed-catalog"} {
		t.Run(dir, func(t *testing.T) {
			assertCatalogSatisfiesSchemas(t, filepath.Join("..", "testdata", dir))
		})
	}
}

// TestFreshlyGeneratedCatalogSatisfiesEmbeddedSchemas generates a catalog
// offline through the real gather pipeline (including the index metadata
// stamp round-trip) and asserts the output honors the published schemas.
func TestFreshlyGeneratedCatalogSatisfiesEmbeddedSchemas(t *testing.T) {
	const target = "java21-distroless"
	const tag = "v1.0.0"

	temp := t.TempDir()
	outDir := filepath.Join(temp, "catalog")
	enrichmentDir := filepath.Join(temp, "enrichment")

	writeTestFile(t, filepath.Join(enrichmentDir, tag, target+".json"), []byte(`{
  "manifestDigest": "sha256:manifest-fresh",
  "architectures": [
    {
      "arch": "amd64",
      "digest": "sha256:image-amd64",
      "size": 11,
      "layers": [],
      "labels": {}
    }
  ],
  "signature": { "cosignBundlePresent": true },
  "provenance": {
    "predicateType": "https://slsa.dev/provenance/v1",
    "builder": { "id": "test-builder" },
    "slsaLevel": 3
  },
  "attestations": []
}`))

	spdxRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCatalogReleaseSource{
		releases: []catalogbuild.Release{{
			Tag:         tag,
			Name:        tag,
			PublishedAt: "2026-06-10T00:00:00Z",
			Assets: []catalogbuild.Asset{
				{Name: target + "-amd64.sbom.json", URL: "https://example.invalid/" + target + "-amd64.sbom.json"},
				{Name: target + "-amd64.test-results.json", URL: "https://example.invalid/" + target + "-amd64.test-results.json"},
			},
		}},
		assets: map[string][]byte{
			target + "-amd64.sbom.json":         spdxRaw,
			target + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-06-10T00:05:00Z","assertions":[{"name":"Syft SBOM Generation","status":"passed"}]}`),
		},
	}
	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		return source
	}

	stdout, err := runCLI(t,
		"catalog", "gather",
		"--owner", "test-owner",
		"--repo", "test-repo",
		"--registry-base", "ghcr.io/test-owner/test-repo",
		"--out-dir", outDir,
		"--enrichment-dir", enrichmentDir,
		"--sbom-cache-dir", filepath.Join(temp, "sboms"),
		"--vuln-dir", filepath.Join(temp, "vulnerabilities"),
		"--targets", target,
		"--limit", "1",
		"--force-refresh-all",
		"--generated-at", "2026-06-10T00:10:00Z",
	)
	if err != nil {
		t.Fatalf("catalog gather failed: %v\n%s", err, stdout)
	}
	if err := writeEvidenceManifestFile(outDir); err != nil {
		t.Fatalf("write evidence manifest: %v", err)
	}

	assertCatalogSatisfiesSchemas(t, outDir)
}

// TestCatalogValidateSchemaHasTeeth corrupts a schema-required key that the
// structural checks never inspect (a package's cpes array) and proves the
// embedded JSON Schema validation catches it with file + JSON-pointer detail.
// Before schema validation was wired in, this corruption sailed through
// `catalog validate` because validateCatalogPackages only checks
// name/version/spdxId.
func TestCatalogValidateSchemaHasTeeth(t *testing.T) {
	outDir := copyFixtureCatalog(t)
	recordPath := filepath.Join(outDir, "images", "java21-distroless.json")
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := strings.Replace(string(raw), "\"cpes\": [],\n", "", 1)
	if corrupted == string(raw) {
		t.Fatal("fixture no longer carries the cpes key this test corrupts")
	}
	if err := os.WriteFile(recordPath, []byte(corrupted), 0o644); err != nil {
		t.Fatal(err)
	}

	oldOpts := catalogValidateOpts
	catalogValidateOpts = catalogValidateFlags{}
	defer func() { catalogValidateOpts = oldOpts }()
	report := validateCatalogDirectory(outDir)
	if report.ErrorCount == 0 {
		t.Fatal("schema validation accepted a package with the required cpes key removed")
	}
	found := false
	for _, msg := range report.Errors {
		if strings.Contains(msg, filepath.Join("images", "java21-distroless.json")) &&
			strings.Contains(msg, "schema image-record.v1.schema.json") &&
			strings.Contains(msg, "/sbom/packages/0") &&
			strings.Contains(msg, "cpes") {
			found = true
		}
		// The corruption must be reported by the schema layer, not the
		// structural layer: every error for this file carries the schema label.
		if strings.Contains(msg, "java21-distroless.json") && !strings.Contains(msg, "schema image-record.v1.schema.json") {
			t.Errorf("unexpected non-schema error for corrupted record: %s", msg)
		}
	}
	if !found {
		t.Fatalf("expected a schema violation naming the file and the /sbom/packages/0 cpes pointer, got:\n%s", strings.Join(report.Errors, "\n"))
	}
}

// TestStampCatalogIndexMetadataPreservesExplicitNulls guards the v1 round-trip:
// stampCatalogIndexMetadata loads and rewrites index.json, and the rewrite must
// keep the schema-required nullable lifecycle/runtimeContract keys the
// catalogbuild writer emits as explicit nulls.
func TestStampCatalogIndexMetadataPreservesExplicitNulls(t *testing.T) {
	outDir := copyFixtureCatalog(t)
	if err := stampCatalogIndexMetadata(outDir); err != nil {
		t.Fatalf("stampCatalogIndexMetadata: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Images []map[string]json.RawMessage `json:"images"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatalf("unmarshal stamped index: %v", err)
	}
	if len(index.Images) == 0 {
		t.Fatal("stamped index has no images")
	}
	for _, section := range []struct {
		key  string
		want []string
	}{
		{"lifecycle", []string{"deprecatedAt", "eolAt", "reason"}},
		{"runtimeContract", []string{"user", "workingDir", "shellPresent", "packageManagerPresent", "caCertificatesPresent", "timezoneDataPresent", "defaultEntrypoint"}},
	} {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(index.Images[0][section.key], &obj); err != nil {
			t.Fatalf("unmarshal images[0].%s: %v", section.key, err)
		}
		for _, key := range section.want {
			if _, ok := obj[key]; !ok {
				t.Errorf("stamped index dropped images[0].%s.%s", section.key, key)
			}
		}
	}

	validator, err := catalog.NewSchemaValidator()
	if err != nil {
		t.Fatalf("NewSchemaValidator: %v", err)
	}
	violations, err := validator.Validate("catalog-index.v1.schema.json", raw)
	if err != nil {
		t.Fatalf("schema validate stamped index: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("stamped index violates catalog-index.v1.schema.json:\n%s", strings.Join(violations, "\n"))
	}
}

// TestImageRecordRoundTripPreservesExplicitNulls covers the image-record side
// of the same round-trip: load through the typed model, rewrite, and the
// schema-required nullable keys must survive with explicit nulls.
func TestImageRecordRoundTripPreservesExplicitNulls(t *testing.T) {
	outDir := copyFixtureCatalog(t)
	record, err := catalog.LoadImageRecord(outDir, "java21-distroless")
	if err != nil {
		t.Fatalf("LoadImageRecord: %v", err)
	}
	recordPath := filepath.Join(outDir, "images", "java21-distroless.json")
	if err := writeJSONFile(recordPath, record); err != nil {
		t.Fatalf("rewrite image record: %v", err)
	}

	raw, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Lifecycle map[string]json.RawMessage `json:"lifecycle"`
		Releases  []struct {
			Lifecycle       map[string]json.RawMessage `json:"lifecycle"`
			RuntimeContract map[string]json.RawMessage `json:"runtimeContract"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal rewritten record: %v", err)
	}
	if len(doc.Releases) == 0 {
		t.Fatal("rewritten record has no releases")
	}
	for _, key := range []string{"deprecatedAt", "eolAt", "reason"} {
		if _, ok := doc.Lifecycle[key]; !ok {
			t.Errorf("rewritten record dropped lifecycle.%s", key)
		}
		if _, ok := doc.Releases[0].Lifecycle[key]; !ok {
			t.Errorf("rewritten record dropped releases[0].lifecycle.%s", key)
		}
	}
	if _, ok := doc.Releases[0].RuntimeContract["defaultEntrypoint"]; !ok {
		t.Error("rewritten record dropped releases[0].runtimeContract.defaultEntrypoint")
	}

	validator, err := catalog.NewSchemaValidator()
	if err != nil {
		t.Fatalf("NewSchemaValidator: %v", err)
	}
	violations, err := validator.Validate("image-record.v1.schema.json", raw)
	if err != nil {
		t.Fatalf("schema validate rewritten record: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("rewritten record violates image-record.v1.schema.json:\n%s", strings.Join(violations, "\n"))
	}
}
