package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func writeCatalogJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeCatalogFixture(t *testing.T, dir string, index any, images map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCatalogJSON(t, filepath.Join(dir, "index.json"), index)
	for id, rec := range images {
		writeCatalogJSON(t, filepath.Join(dir, "images", id+".json"), rec)
	}
}

func completeEvidence(signature bool) map[string]any {
	return map[string]any{
		"signature":              signature,
		"provenance":             true,
		"sbom":                   true,
		"tests":                  true,
		"vulnerabilities":        true,
		"archCount":              1,
		"sbomArchCount":          1,
		"testArchCount":          1,
		"passedTestArchCount":    1,
		"vulnerabilityArchCount": 1,
	}
}

func zeroExceptions() map[string]any {
	return map[string]any{
		"total": 0, "expired": 0, "active": 0, "acceptedRisk": 0,
		"noFixAvailable": 0, "falsePositive": 0, "inheritedFromBase": 0,
	}
}

// A latest image whose index summary advertises a signature the release evidence
// does not actually carry must fail verification (signed=true vs evidence=false).
func TestVerifyCatalogFailsWhenSignatureInferredFromProvenance(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	runtimeContract := map[string]any{"shellPresent": true, "packageManagerPresent": false, "productionTier": true}
	evidence := completeEvidence(false)

	index := map[string]any{
		"latestTag": "v1.0.0",
		"images": []any{map[string]any{
			"id": "java21-slim", "latestTag": "v1.0.0", "signed": true, "provenance": true,
			"lifecycle": lifecycle, "runtimeContract": runtimeContract, "evidence": evidence,
		}},
	}
	release := map[string]any{
		"tag": "v1.0.0", "signature": nil,
		"provenance":      map[string]any{"predicateType": "https://slsa.dev/provenance/v1"},
		"lifecycle":       lifecycle,
		"runtimeContract": runtimeContract,
		"exceptions":      zeroExceptions(),
		"evidence":        evidence,
		"architectures":   []any{},
	}
	record := map[string]any{"id": "java21-slim", "lifecycle": lifecycle, "runtimeContract": runtimeContract, "releases": []any{release}}
	writeCatalogFixture(t, dir, index, map[string]any{"java21-slim": record})

	stdout, err := runCLI(t, "--catalog", dir, "verify", "catalog")
	if err == nil {
		t.Fatalf("expected verification to fail, got success:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Sigstore signature is missing") {
		t.Fatalf("expected missing signature failure, got:\n%s", stdout)
	}
}

func TestVerifyCatalogAcceptsCompleteLatestEvidence(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	runtimeContract := map[string]any{"shellPresent": true, "packageManagerPresent": false, "productionTier": true}
	evidence := completeEvidence(true)

	index := map[string]any{
		"latestTag": "v1.0.0",
		"images": []any{map[string]any{
			"id": "java21-slim", "latestTag": "v1.0.0", "signed": true, "provenance": true,
			"lifecycle": lifecycle, "runtimeContract": runtimeContract, "evidence": evidence,
		}},
	}
	release := map[string]any{
		"tag": "v1.0.0", "signature": map[string]any{"cosignBundlePresent": true},
		"provenance":      map[string]any{"predicateType": "https://slsa.dev/provenance/v1"},
		"lifecycle":       lifecycle,
		"runtimeContract": runtimeContract,
		"exceptions":      zeroExceptions(),
		"evidence":        evidence,
		"architectures":   []any{},
	}
	record := map[string]any{"id": "java21-slim", "lifecycle": lifecycle, "runtimeContract": runtimeContract, "releases": []any{release}}
	writeCatalogFixture(t, dir, index, map[string]any{"java21-slim": record})

	stdout, err := runCLI(t, "--catalog", dir, "verify", "catalog")
	if err != nil {
		t.Fatalf("expected verification to pass, got %v:\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "ok: 1 latest images") {
		t.Fatalf("expected ok summary, got:\n%s", stdout)
	}
}

func TestVerifyCatalogRejectsStaleAndObservedEvidence(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	runtimeContract := map[string]any{"shellPresent": false, "packageManagerPresent": false, "productionTier": true}
	evidence := completeEvidence(true)
	evidence["statuses"] = map[string]any{
		"signature":       map[string]any{"status": "observed"},
		"provenance":      map[string]any{"status": "attested"},
		"sbom":            map[string]any{"status": "stale"},
		"tests":           map[string]any{"status": "stale"},
		"vulnerabilities": map[string]any{"status": "stale"},
	}
	index := map[string]any{
		"latestTag": "v1.0.0",
		"images": []any{map[string]any{
			"id": "java21-slim", "latestTag": "v1.0.0", "signed": true, "provenance": true,
			"lifecycle": lifecycle, "runtimeContract": runtimeContract, "evidence": evidence,
		}},
	}
	release := map[string]any{
		"tag": "v1.0.0", "lifecycle": lifecycle, "runtimeContract": runtimeContract,
		"exceptions": zeroExceptions(), "evidence": evidence,
		"architectures": []any{map[string]any{"arch": "amd64"}},
	}
	record := map[string]any{"id": "java21-slim", "lifecycle": lifecycle, "runtimeContract": runtimeContract, "releases": []any{release}}
	writeCatalogFixture(t, dir, index, map[string]any{"java21-slim": record})

	stdout, err := runCLI(t, "--catalog", dir, "verify", "catalog")
	if err == nil {
		t.Fatalf("stale and observed evidence must fail strict catalog verification:\n%s", stdout)
	}
	for _, want := range []string{"Sigstore signature is missing", "SLSA provenance is missing", "SBOM coverage incomplete", "test evidence incomplete", "vulnerability scan coverage incomplete"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in output:\n%s", want, stdout)
		}
	}
}

func TestReleaseEvidenceSummaryRecomputesWhenMissing(t *testing.T) {
	rel := &catalog.ReleaseEntry{
		Signature:  &catalog.SignatureInfo{CosignBundlePresent: true},
		Provenance: &catalog.ProvenanceInfo{PredicateType: "https://slsa.dev/provenance/v1"},
		Architectures: []catalog.ArchPayload{
			{
				Arch: "amd64",
				SBOM: catalog.SBOMInfo{PackageCount: 1},
				TestResults: &catalog.TestResultsInfo{
					Status: "passed",
				},
				Vulnerabilities: &catalog.VulnerabilitiesInfo{},
			},
			{
				Arch: "arm64",
				SBOM: catalog.SBOMInfo{PackageCount: 0},
				TestResults: &catalog.TestResultsInfo{
					Status: "failed",
				},
			},
		},
	}
	got := releaseEvidenceSummary(rel)
	if !got.Signature || !got.Provenance || got.SBOM || got.Tests || got.Vulnerabilities {
		t.Fatalf("unexpected recomputed evidence: %#v", got)
	}
	if got.ArchCount != 2 || got.SBOMArchCount != 1 || got.PassedTestArchCount != 1 || got.VulnerabilityArchCount != 1 {
		t.Fatalf("unexpected recomputed counts: %#v", got)
	}

	explicit := catalog.EvidenceSummary{Signature: true, ArchCount: 99}
	rel.Evidence = &explicit
	if got := releaseEvidenceSummary(rel); got.ArchCount != 99 {
		t.Fatalf("explicit evidence should win, got %#v", got)
	}
}

func TestWarningTestResultsSatisfyOnlyNonProductionCatalogEvidence(t *testing.T) {
	rel := &catalog.ReleaseEntry{
		Lifecycle:       catalog.Lifecycle{Status: "preview", Support: "preview", ProductionAllowed: false},
		RuntimeContract: catalog.RuntimeContract{ProductionTier: false},
		Architectures: []catalog.ArchPayload{
			{Arch: "amd64", SBOM: catalog.SBOMInfo{PackageCount: 1}, TestResults: &catalog.TestResultsInfo{Status: "warning"}, Vulnerabilities: &catalog.VulnerabilitiesInfo{}},
			{Arch: "arm64", SBOM: catalog.SBOMInfo{PackageCount: 1}, TestResults: &catalog.TestResultsInfo{Status: "warning"}, Vulnerabilities: &catalog.VulnerabilitiesInfo{}},
		},
	}

	evidence := releaseEvidenceSummary(rel)
	if !evidence.Tests || evidence.PassedTestArchCount != 2 {
		t.Fatalf("non-production warning test results should satisfy catalog evidence: %#v", evidence)
	}
	if service := serviceEvidenceSummary(catalog.ReleaseEntry(*rel)); !service.Tests || service.PassedTestArchCount != 2 {
		t.Fatalf("non-production warning service evidence should satisfy catalog evidence: %#v", service)
	}

	rel.RuntimeContract.ProductionTier = true
	evidence = releaseEvidenceSummary(rel)
	if evidence.Tests || evidence.PassedTestArchCount != 0 {
		t.Fatalf("production-tier warning test results should not satisfy catalog evidence: %#v", evidence)
	}

	rel.RuntimeContract.ProductionTier = false
	rel.Lifecycle.ProductionAllowed = true
	evidence = releaseEvidenceSummary(rel)
	if evidence.Tests || evidence.PassedTestArchCount != 0 {
		t.Fatalf("production-allowed warning test results should not satisfy catalog evidence: %#v", evidence)
	}
}

func TestVerifyCatalogRawHelperBranches(t *testing.T) {
	failures := []string{}
	failFor := func(id, msg string) { failures = append(failures, id+": "+msg) }
	validateRawCatalogSummary("java21-distroless", rawCatalogSummary{
		Lifecycle:       json.RawMessage(`{"productionAllowed":"yes"}`),
		RuntimeContract: json.RawMessage(`{"shellPresent":"yes","packageManagerPresent":1,"productionTier":null}`),
	}, failFor)
	validateRawCatalogSummary("missing-runtime", rawCatalogSummary{Lifecycle: json.RawMessage(`null`)}, failFor)
	validateRawImageRecord(rawImageRecord{
		ID:              "java21-distroless",
		Lifecycle:       json.RawMessage(`null`),
		RuntimeContract: json.RawMessage(``),
		Releases: []rawReleaseRecord{{
			Tag:             "v1.0.0",
			Lifecycle:       json.RawMessage(`null`),
			RuntimeContract: json.RawMessage(`null`),
			Exceptions:      json.RawMessage(`{"total":"nope"}`),
		}},
	}, failFor)
	if len(failures) < 8 {
		t.Fatalf("expected several raw validation failures, got %d: %#v", len(failures), failures)
	}
	if obj, ok := rawObject(json.RawMessage(`{"ok":true}`)); !ok || obj["ok"] == nil {
		t.Fatalf("rawObject valid branch failed: %#v ok=%v", obj, ok)
	}
	if _, ok := rawObject(json.RawMessage(`[`)); ok {
		t.Fatal("invalid raw object should fail")
	}
	if rawNumber(json.RawMessage(`"7"`)) {
		t.Fatal("quoted number should not satisfy rawNumber")
	}
}

// When no published image carries the index's latest tag, verification must fail
// rather than vacuously pass on an empty set.
func TestVerifyCatalogFailsWhenNoLatestImages(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	index := map[string]any{
		"latestTag": "v2.0.0",
		"images": []any{map[string]any{
			"id": "java21-slim", "latestTag": "v1.0.0", "lifecycle": lifecycle,
		}},
	}
	writeCatalogFixture(t, dir, index, map[string]any{})

	stdout, err := runCLI(t, "--catalog", dir, "verify", "catalog")
	if err == nil {
		t.Fatalf("expected verification to fail, got success:\n%s", stdout)
	}
	if !strings.Contains(stdout, "no images are published for latest tag v2.0.0") {
		t.Fatalf("expected no-latest-images failure, got:\n%s", stdout)
	}
}

func TestVerifyCatalogFailsWhenRequiredRawFieldsAreMissing(t *testing.T) {
	dir := t.TempDir()
	lifecycle := map[string]any{"status": "active", "support": "lts", "productionAllowed": true}
	runtimeContract := map[string]any{"shellPresent": true, "packageManagerPresent": false, "productionTier": true}
	evidence := completeEvidence(true)

	index := map[string]any{
		"latestTag": "v1.0.0",
		"images": []any{map[string]any{
			"id": "java21-slim", "latestTag": "v1.0.0", "signed": true, "provenance": true,
			"lifecycle": lifecycle, "evidence": evidence,
		}},
	}
	release := map[string]any{
		"tag": "v1.0.0", "signature": map[string]any{"cosignBundlePresent": true},
		"provenance":      map[string]any{"predicateType": "https://slsa.dev/provenance/v1"},
		"lifecycle":       lifecycle,
		"runtimeContract": runtimeContract,
		"evidence":        evidence,
		"architectures":   []any{},
	}
	record := map[string]any{"id": "java21-slim", "lifecycle": lifecycle, "runtimeContract": runtimeContract, "releases": []any{release}}
	writeCatalogFixture(t, dir, index, map[string]any{"java21-slim": record})

	stdout, err := runCLI(t, "--catalog", dir, "verify", "catalog")
	if err == nil {
		t.Fatalf("expected verification to fail, got success:\n%s", stdout)
	}
	for _, want := range []string{
		"index summary is missing runtimeContract",
		"release v1.0.0 is missing exceptions",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in verifier output, got:\n%s", want, stdout)
		}
	}
}
