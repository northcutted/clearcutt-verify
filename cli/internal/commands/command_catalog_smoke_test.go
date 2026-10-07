package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func TestReleaseDiffReportWritesArtifacts(t *testing.T) {
	dir := writeCommandSmokeCatalog(t)
	outDir := filepath.Join(t.TempDir(), "reports")

	stdout, err := runCLI(t,
		"--catalog", dir,
		"release", "diff-report",
		"--image", "java21-distroless",
		"--from", "v1.0.0",
		"--to", "v2.0.0",
		"--output-dir", outDir,
	)
	if err != nil {
		t.Fatalf("release diff-report failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Successfully generated release diff reports") {
		t.Fatalf("expected success output, got:\n%s", stdout)
	}

	jsonPath := filepath.Join(outDir, "java21-distroless.json")
	mdPath := filepath.Join(outDir, "java21-distroless.md")
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("expected JSON report: %v", err)
	}
	var report struct {
		Decision     string   `json:"recommendedAction"`
		BlockReasons []string `json:"reasons"`
		ArchChanges  []any    `json:"architectureChanges"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("failed to decode report: %v\n%s", err, raw)
	}
	if report.Decision != "manual_review" || len(report.BlockReasons) == 0 || len(report.ArchChanges) != 2 {
		t.Fatalf("unexpected release report: %#v", report)
	}
	md, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("expected Markdown report: %v", err)
	}
	if !strings.Contains(string(md), "Newly Introduced CVEs") || !strings.Contains(string(md), "CVE-NEW") {
		t.Fatalf("expected Markdown CVE summary, got:\n%s", md)
	}
}

func writeCommandSmokeCatalog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	imageDir := filepath.Join(dir, "images")
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		t.Fatal(err)
	}

	language := catalog.LanguageInfo{ID: "java", DisplayName: "Java", Version: "21"}
	tier := catalog.TierInfo{ID: "distroless", Name: "Distroless", Blurb: "Minimal runtime"}
	preview := catalog.Lifecycle{Status: "preview", Support: "lts", ProductionAllowed: false, Reason: strPtr("waiting on final smoke evidence")}
	active := catalog.Lifecycle{Status: "active", Support: "lts", ProductionAllowed: true}
	runtimePreview := catalog.RuntimeContract{
		User:                  strPtr("10001"),
		WorkingDir:            strPtr("/app"),
		ShellPresent:          boolPtr(false),
		PackageManagerPresent: boolPtr(false),
		CACertificatesPresent: boolPtr(true),
		TimezoneDataPresent:   boolPtr(true),
		DefaultEntrypoint:     strPtr("/usr/local/bin/java"),
		ProductionTier:        true,
	}
	runtimeActive := runtimePreview
	evidenceOld := catalog.EvidenceSummary{
		Signature: false, Provenance: true, SBOM: true, Tests: false, Vulnerabilities: true,
		ArchCount: 1, SBOMArchCount: 1, TestArchCount: 1, PassedTestArchCount: 0, VulnerabilityArchCount: 1,
	}
	evidenceNew := catalog.EvidenceSummary{
		Signature: true, Provenance: true, SBOM: true, Tests: true, Vulnerabilities: true,
		ArchCount: 2, SBOMArchCount: 2, TestArchCount: 2, PassedTestArchCount: 2, VulnerabilityArchCount: 2,
	}
	oldDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	oldRelease := catalog.ReleaseEntry{
		Tag:            "v1.0.0",
		PublishedAt:    "2026-01-01T00:00:00Z",
		IsLatest:       false,
		ManifestDigest: &oldDigest,
		TotalSize:      int64Ptr(40 * 1024 * 1024),
		Architectures: []catalog.ArchPayload{
			archPayload("amd64", "sha256:old-amd64", 20*1024*1024, 2,
				[]catalog.PackageEntry{
					pkg("zlib", "1.2.13"),
					pkg("openssl", "3.0.0"),
					pkg("curl", "8.0.0"),
				},
				[]catalog.FindingInfo{finding("CVE-OLD", "High", "openssl")},
				"failed",
			),
		},
		Signature: &catalog.SignatureInfo{CosignBundlePresent: false},
		Provenance: &catalog.ProvenanceInfo{
			PredicateType: "https://slsa.dev/provenance/v1",
			Builder:       catalog.BuilderInfo{ID: "builder-old"},
			SlsaLevel:     3,
		},
		Attestations: []catalog.AttestationEntry{},
		AssetURLs: catalog.AssetURLs{
			SBOM:        map[string]string{"amd64": "https://example.invalid/old-amd64.sbom.json"},
			Provenance:  strPtr("https://example.invalid/old.intoto.jsonl"),
			TestResults: map[string]string{"amd64": "https://example.invalid/old-amd64.test-results.json"},
			Digest:      strPtr("https://example.invalid/old.digest.json"),
		},
		Evidence:        &evidenceOld,
		Lifecycle:       preview,
		RuntimeContract: runtimePreview,
		Exceptions:      catalog.ExceptionSummary{Total: 1, Active: 1, AcceptedRisk: 1},
	}
	newRelease := catalog.ReleaseEntry{
		Tag:            "v2.0.0",
		PublishedAt:    "2026-02-01T00:00:00Z",
		IsLatest:       true,
		ManifestDigest: &newDigest,
		TotalSize:      int64Ptr(44 * 1024 * 1024),
		Architectures: []catalog.ArchPayload{
			archPayload("amd64", "sha256:new-amd64", 24*1024*1024, 3,
				[]catalog.PackageEntry{
					pkg("zlib", "1.3.1"),
					pkg("openssl", "3.0.0"),
					pkg("bash", "5.2"),
				},
				[]catalog.FindingInfo{finding("CVE-NEW", "Critical", "zlib")},
				"passed",
			),
			archPayload("arm64", "sha256:new-arm64", 20*1024*1024, 2,
				[]catalog.PackageEntry{
					pkg("zlib", "1.3.1"),
					pkg("openssl", "3.0.0"),
				},
				[]catalog.FindingInfo{},
				"passed",
			),
		},
		Signature: &catalog.SignatureInfo{CosignBundlePresent: true, RekorLogIndex: int64Ptr(1234)},
		Provenance: &catalog.ProvenanceInfo{
			PredicateType: "https://slsa.dev/provenance/v1",
			Builder:       catalog.BuilderInfo{ID: "builder-new"},
			BuildType:     strPtr("https://slsa.dev/container"),
			SourceURI:     strPtr("https://github.com/northcutted/clearcutt"),
			SlsaLevel:     3,
		},
		Attestations: []catalog.AttestationEntry{{
			Kind:          "slsa-provenance",
			PredicateType: "https://slsa.dev/provenance/v1",
			Sources:       []string{"oci", "github"},
		}},
		AssetURLs: catalog.AssetURLs{
			SBOM: map[string]string{
				"amd64": "https://example.invalid/new-amd64.sbom.json",
				"arm64": "https://example.invalid/new-arm64.sbom.json",
			},
			Provenance: strPtr("https://example.invalid/new.intoto.jsonl"),
			TestResults: map[string]string{
				"amd64": "https://example.invalid/new-amd64.test-results.json",
				"arm64": "https://example.invalid/new-arm64.test-results.json",
			},
			Digest: strPtr("https://example.invalid/new.digest.json"),
		},
		Evidence:        &evidenceNew,
		Lifecycle:       active,
		RuntimeContract: runtimeActive,
		Exceptions:      catalog.ExceptionSummary{},
	}

	index := catalog.CatalogIndex{
		GeneratedAt:  "2026-02-01T01:00:00Z",
		Owner:        "northcutted",
		Repo:         "clearcutt",
		RepoURL:      "https://github.com/northcutted/clearcutt",
		RegistryBase: "ghcr.io/northcutted/clearcutt",
		LatestTag:    "v2.0.0",
		Releases: []catalog.ReleaseSummary{
			{Tag: "v2.0.0", PublishedAt: "2026-02-01T00:00:00Z", IsLatest: true},
			{Tag: "v1.0.0", PublishedAt: "2026-01-01T00:00:00Z", IsLatest: false},
		},
		Languages: []catalog.LanguageInfo{language},
		Tiers:     []catalog.TierInfo{tier},
		Images: []catalog.CatalogImageSummary{{
			ID:                   "java21-distroless",
			Language:             "java",
			LanguageDisplay:      "Java",
			LanguageVersion:      "21",
			Tier:                 "distroless",
			LatestTag:            "v2.0.0",
			LatestManifestDigest: &newDigest,
			LatestPackageCount:   3,
			Architectures:        []string{"amd64", "arm64"},
			Signed:               true,
			Provenance:           true,
			Evidence:             &evidenceNew,
			Passed:               true,
			VulnSummary: &catalog.VulnSummary{
				Critical:  1,
				High:      0,
				ScannedAt: strPtr("2026-02-01T00:30:00Z"),
				Remediation: &catalog.RemediationCounts{
					Eligible: 1,
				},
			},
			Lifecycle:       active,
			RuntimeContract: runtimeActive,
		}},
	}
	record := catalog.ImageRecord{
		ID:              "java21-distroless",
		Language:        language,
		Tier:            tier,
		Registry:        "ghcr.io/northcutted/clearcutt",
		ImageName:       "clearcutt-java21",
		FullName:        "ghcr.io/northcutted/clearcutt/clearcutt-java21",
		Lifecycle:       active,
		RuntimeContract: runtimeActive,
		Releases:        []catalog.ReleaseEntry{newRelease, oldRelease},
	}
	writeCatalogJSON(t, filepath.Join(dir, "index.json"), index)
	writeCatalogJSON(t, filepath.Join(imageDir, "java21-distroless.json"), record)
	return dir
}

func archPayload(arch, digest string, size int64, layers int, packages []catalog.PackageEntry, findings []catalog.FindingInfo, testStatus string) catalog.ArchPayload {
	return catalog.ArchPayload{
		Arch:        arch,
		OS:          "linux",
		ImageDigest: strPtr(digest),
		ImageSize:   int64Ptr(size),
		LayerCount:  intPtr(layers),
		Layers:      []catalog.LayerInfo{{Digest: digest + "-layer", Size: size / 2}},
		Labels:      map[string]string{"org.opencontainers.image.source": "https://github.com/northcutted/clearcutt"},
		SBOM: catalog.SBOMInfo{
			Tool:         "syft",
			CreatedAt:    "2026-02-01T00:00:00Z",
			RootDigest:   strPtr("sha256:root-" + arch),
			PackageCount: len(packages),
			Packages:     packages,
		},
		TestResults: &catalog.TestResultsInfo{
			Status:    testStatus,
			Timestamp: strPtr("2026-02-01T00:15:00Z"),
			Assertions: []catalog.AssertionInfo{
				{Name: "Syft SBOM Generation", Status: "passed"},
			},
		},
		Vulnerabilities: &catalog.VulnerabilitiesInfo{
			ScannedAt: "2026-02-01T00:30:00Z",
			Scanner:   "grype-test",
			CountsBySeverity: catalog.SeverityCounts{
				Critical: len(findings),
			},
			Findings: findings,
		},
	}
}

func pkg(name, version string) catalog.PackageEntry {
	return catalog.PackageEntry{
		Name:     name,
		Version:  version,
		Purl:     strPtr("pkg:nix/" + name + "@" + version),
		Cpes:     []string{},
		License:  "MIT",
		Supplier: "nixpkgs",
		SpdxID:   "SPDXRef-" + name,
	}
}

func finding(id, severity, packageName string) catalog.FindingInfo {
	return catalog.FindingInfo{
		ID:             id,
		Severity:       severity,
		PackageName:    packageName,
		PackageVersion: "1.0.0",
		Purl:           strPtr("pkg:nix/" + packageName + "@1.0.0"),
		Layer:          "runtime",
		FixedIn:        strPtr("1.0.1"),
		FixState:       "fixed",
		Remediation: &catalog.RemediationInfo{
			Status:  "eligible",
			Reason:  "fix_available",
			Summary: "runtime fix available",
		},
		Inclusion: &catalog.InclusionInfo{
			Category: "runtime",
			Summary:  "runtime package",
		},
	}
}

func strPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}

func intPtr(value int) *int {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}
