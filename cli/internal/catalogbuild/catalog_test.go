package catalogbuild

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

type gatherMetaFixture struct {
	Lifecycle       Lifecycle                `json:"lifecycle"`
	RuntimeContract RuntimeContract          `json:"runtimeContract"`
	Exceptions      catalog.ExceptionSummary `json:"exceptions"`
}

// Proves the ported runtime-metadata transforms reproduce gather-catalog.mjs
// byte-for-byte across the fleet's 4-line x 3-tier matrix. The golden fixture
// (testdata/catalog/meta-golden.json) was captured from the Node functions
// verbatim, so this guards both the values and the exact JSON shape (explicit
// nulls, key order) that the catalog site and verify catalog depend on.
func TestGatherMetadataMatchesNodeGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "catalog", "meta-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]json.RawMessage
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) != 12 {
		t.Fatalf("expected 12 target fixtures, got %d", len(golden))
	}

	for target, entry := range golden {
		idx := strings.LastIndex(target, "-")
		if idx == -1 {
			t.Fatalf("malformed target id %q", target)
		}
		tier := target[idx+1:]

		got, err := json.Marshal(gatherMetaFixture{
			Lifecycle:       determineLifecycle(target, tier),
			RuntimeContract: determineRuntimeContract(target, tier),
			Exceptions:      defaultGatherExceptions(),
		})
		if err != nil {
			t.Fatal(err)
		}

		var want bytes.Buffer
		if err := json.Compact(&want, entry); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Errorf("%s drift:\n got: %s\nwant: %s", target, got, want.Bytes())
		}
	}
}

type spdxGatherOut struct {
	Packages   []spdxPackageOut `json:"packages"`
	RootDigest *string          `json:"rootDigest"`
	Provenance Provenance       `json:"provenance"`
}

// Proves the SPDX compaction (package fields, cpe/purl split, license
// resolution, nix store path, layer-digest mapping, sort, root digest) and the
// in-toto/SLSA provenance summarization reproduce gather-catalog.mjs. The
// provenance `raw` passthrough is excluded here (arbitrary-key re-serialization);
// it is handled when image-record assembly lands.
func TestSpdxAndProvenanceTransformsMatchNodeGolden(t *testing.T) {
	spdxRaw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spdx spdxDoc
	if err := json.Unmarshal(spdxRaw, &spdx); err != nil {
		t.Fatal(err)
	}
	intotoRaw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "catalog", "intoto-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := json.Marshal(spdxGatherOut{
		Packages:   compactPackages(spdx),
		RootDigest: rootDigest(spdx),
		Provenance: summarizeProvenance(string(intotoRaw)),
	})
	if err != nil {
		t.Fatal(err)
	}

	goldenRaw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "catalog", "spdx-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := json.Compact(&want, goldenRaw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("SPDX/provenance drift:\n got: %s\nwant: %s", got, want.Bytes())
	}
}

func TestCatalogHelperBranches(t *testing.T) {
	if got := parseCatalogTargetName("python3.13-slim.sbom.json"); got == nil || got.Target != "python3.13-slim" || got.Kind != "sbom" || got.Ext != "json" {
		t.Fatalf("unexpected parsed asset name: %#v", got)
	}
	if got := parseCatalogTargetName("not-an-asset.txt"); got != nil {
		t.Fatalf("unexpected asset parse: %#v", got)
	}
	if archForSystem("aarch64-linux") != "arm64" || archForSystem("x86_64-linux") != "amd64" {
		t.Fatal("archForSystem did not normalize expected systems")
	}
	if arch := guessArchFromAsset("target.sbom.json", &spdxDoc{DocumentNamespace: "https://example.invalid/aarch64-linux"}); arch != "arm64" {
		t.Fatalf("expected namespace arch fallback, got %s", arch)
	}
	if arch := guessArchFromAsset("target-amd64.sbom.json", nil); arch != "amd64" {
		t.Fatalf("expected filename arch, got %s", arch)
	}
	if tool := spdxTool(spdxDoc{CreationInfo: spdxCreationInfo{Creators: []string{"Organization: acme"}}}); tool != "syft" {
		t.Fatalf("expected syft fallback, got %s", tool)
	}
	if tool := spdxTool(spdxDoc{CreationInfo: spdxCreationInfo{Creators: []string{"Tool: custom-syft"}}}); tool != "custom-syft" {
		t.Fatalf("expected explicit tool, got %s", tool)
	}

	temp := t.TempDir()
	cachePath := filepath.Join(temp, "sbom.json")
	if got, ok := readCachedSBOM(cachePath, false); ok || got != nil {
		t.Fatalf("missing cache should not read: ok=%v got=%q", ok, got)
	}
	writeTestFile(t, cachePath, []byte(`{"ok":true}`))
	if got, ok := readCachedSBOM(cachePath, false); !ok || string(got) != `{"ok":true}` {
		t.Fatalf("expected cached SBOM, ok=%v got=%q", ok, got)
	}
	if got, ok := readCachedSBOM(cachePath, true); ok || got != nil {
		t.Fatalf("forced refresh should skip cache: ok=%v got=%q", ok, got)
	}
	if !FileExists(cachePath) || FileExists(filepath.Join(temp, "missing")) {
		t.Fatal("FileExists did not report expected paths")
	}

	assets := []Asset{
		{Name: "target.sbom.json"},
		{Name: "target-amd64.sbom.json"},
		{Name: "target-arm64.sbom.json"},
	}
	if got := catalogAssetsNamed(assets, "target.sbom.json"); len(got) != 1 {
		t.Fatalf("expected named asset, got %#v", got)
	}
	if got := catalogArchAssets(assets, "target", ".sbom.json"); len(got) != 2 {
		t.Fatalf("expected arch assets, got %#v", got)
	}
	if got := RefreshTagSet([]Release{{Tag: "v1"}, {Tag: "v2"}}, false, "v2, v3"); !got["v2"] || !got["v3"] || got["v1"] {
		t.Fatalf("unexpected refresh tag set: %#v", got)
	}
	if got := RefreshTagSet([]Release{{Tag: "v1"}, {Tag: "v2"}}, true, ""); !got["v1"] || !got["v2"] {
		t.Fatalf("force refresh should include every release: %#v", got)
	}
	if got := RefreshTagSet([]Release{{Tag: "v1", Prerelease: true}, {Tag: "v2"}}, false, ""); !got["v2"] || got["v1"] {
		t.Fatalf("latest non-prerelease should refresh, got %#v", got)
	}
	if got := RefreshTagSet([]Release{{Tag: "v1", Prerelease: true}}, false, ""); !got["v1"] {
		t.Fatalf("all-prerelease fallback should refresh first release, got %#v", got)
	}
	if got := RefreshTagSet(nil, false, ""); len(got) != 0 {
		t.Fatalf("empty release set should refresh nothing, got %#v", got)
	}
	for reason, want := range map[string]string{
		"fix_available":            "eligible",
		"base_layer":               "baseLayer",
		"no_fixed_version":         "noFixedVersion",
		"below_priority_threshold": "belowPriorityThreshold",
		"unknown-reason":           "otherDeferred",
	} {
		if got := remediationBucket(reason); got != want {
			t.Fatalf("remediationBucket(%q) = %q, want %q", reason, got, want)
		}
	}
	if got := remediationReason(catalog.FindingInfo{Severity: "medium", Layer: "runtime", FixedIn: strPtr("1.0.1")}); got != "below_priority_threshold" {
		t.Fatalf("medium runtime finding reason = %q", got)
	}
	if got := remediationReason(catalog.FindingInfo{Severity: "high", Layer: "runtime"}); got != "no_fixed_version" {
		t.Fatalf("high runtime no-fix reason = %q", got)
	}
	if got := remediationReason(catalog.FindingInfo{Severity: "high", Layer: "runtime", FixedIn: strPtr("1.0.1")}); got != "fix_available" {
		t.Fatalf("high runtime fixed reason = %q", got)
	}
	if remediationBucket("unknown-reason") != "otherDeferred" {
		t.Fatal("unknown remediation reason should use otherDeferred bucket")
	}
}

func TestCatalogProvenanceAndSPDXEdgeBranches(t *testing.T) {
	if extractNixStorePath("") != nil || extractNixStorePath("not a nix path") != nil {
		t.Fatal("non-Nix source info should not produce a store path")
	}
	if got := pickLicense(spdxPkg{LicenseDeclared: "NOASSERTION", LicenseConcluded: "Apache-2.0"}); got != "Apache-2.0" {
		t.Fatalf("pickLicense concluded branch = %q", got)
	}
	if got := pickLicense(spdxPkg{}); got != "NOASSERTION" {
		t.Fatalf("pickLicense fallback = %q", got)
	}
	checksumRoot := rootDigest(spdxDoc{Packages: []spdxPkg{{PrimaryPackagePurpose: "CONTAINER", Checksums: []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: "abc"}}}}})
	if checksumRoot == nil || *checksumRoot != "sha256:abc" {
		t.Fatalf("checksum root digest = %v", checksumRoot)
	}
	versionRoot := rootDigest(spdxDoc{Packages: []spdxPkg{{PrimaryPackagePurpose: "CONTAINER", VersionInfo: "sha256:def"}}})
	if versionRoot == nil || *versionRoot != "sha256:def" {
		t.Fatalf("version root digest = %v", versionRoot)
	}
	if rootDigest(spdxDoc{Packages: []spdxPkg{{PrimaryPackagePurpose: "CONTAINER", VersionInfo: "not-a-digest"}}}) != nil {
		t.Fatal("container package without digest should return nil root digest")
	}

	stmt := IntotoStatement{
		PredicateType: "https://example.invalid/custom",
		Predicate: intotoPredicate{
			RunDetails: &intotoRunDetails{Builder: &intotoBuilder{ID: "runner-builder"}},
			BuildDefinition: &intotoBuildDefinition{
				BuildType: "https://example.invalid/build",
				ExternalParameters: &intotoExternalParams{
					Workflow:  &intotoWorkflow{Repository: "https://github.com/acme/workflow"},
					SourceURI: "https://github.com/acme/source",
				},
				ResolvedDependencies: []intotoDependency{{
					URI:    "https://github.com/acme/repo",
					Digest: &intotoDigest{GitCommit: "abc123"},
				}},
			},
		},
	}
	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	if got := decodeIntotoPayload([]byte(`{"payload":"` + encoded + `"}`)); got == nil || got.PredicateType != "https://example.invalid/custom" {
		t.Fatalf("payload decode branch failed: %#v", got)
	}
	if got := decodeIntotoPayload([]byte(`{"dsseEnvelope":{"payload":"` + encoded + `"}}`)); got == nil || got.PredicateType != "https://example.invalid/custom" {
		t.Fatalf("dsse decode branch failed: %#v", got)
	}
	if decodeIntotoPayload([]byte(`{"payload":"not-base64"}`)) != nil {
		t.Fatal("invalid base64 should not decode")
	}
	if decodeIntotoPayload([]byte(`{"notPredicate":"x"}`)) != nil {
		t.Fatal("non-attestation line should not decode")
	}
	summary := summarizeProvenance(string(raw) + "\n" + `{"predicateType":"https://slsa.dev/provenance/v1","predicate":{"builder":{"id":"slsa-builder"}}}`)
	if summary.PredicateType != "https://slsa.dev/provenance/v1" || summary.Builder.ID != "slsa-builder" {
		t.Fatalf("SLSA provenance should win, got %+v", summary)
	}
	fallback := summarizeProvenance("not-json\n")
	if fallback.PredicateType != "unknown" || fallback.Builder.ID != "unknown" {
		t.Fatalf("provenance fallback = %+v", fallback)
	}
	nonSLSA := summarizeProvenance(string(raw))
	if nonSLSA.Builder.ID != "runner-builder" || nonSLSA.SourceRevision == nil || *nonSLSA.SourceRevision != "abc123" {
		t.Fatalf("expected useful non-SLSA provenance summary, got %+v", nonSLSA)
	}
}

type fakeCatalogReleaseSource struct {
	releases  []Release
	assets    map[string][]byte
	downloads []string
}

func (f *fakeCatalogReleaseSource) ListReleases(limit int) ([]Release, error) {
	if limit > 0 && len(f.releases) > limit {
		return append([]Release(nil), f.releases[:limit]...), nil
	}
	return append([]Release(nil), f.releases...), nil
}

func (f *fakeCatalogReleaseSource) DownloadAsset(asset Asset) ([]byte, error) {
	f.downloads = append(f.downloads, asset.Name)
	data, ok := f.assets[asset.Name]
	if !ok {
		return nil, fmt.Errorf("missing asset fixture %s", asset.Name)
	}
	return data, nil
}

func strPtr(value string) *string {
	return &value
}

type catalogAssemblyFixture struct {
	Image   *ImageRecord `json:"image"`
	Summary ImageSummary `json:"summary"`
}

// Exercises the image-record assembly path that replaces the network-heavy
// gather-catalog.mjs core: per-arch SBOM assets, persisted SBOM cache, release
// test assets plus enrichment fallback, manifest/signature/attestation merge,
// vulnerability fold-in, evidence recomputation, and slim index summary output.
func TestBuildImageRecordMatchesAssemblyGolden(t *testing.T) {
	const target = "python3.13-slim"
	const tag = "v1.0.0"
	const publishedAt = "2026-05-29T13:44:59Z"

	temp := t.TempDir()
	sbomDir := filepath.Join(temp, "sboms")
	enrichmentDir := filepath.Join(temp, "enrichment")
	vulnDir := filepath.Join(temp, "vulnerabilities")
	writeTestFile(t, filepath.Join(enrichmentDir, tag, target+".json"), []byte(`{
  "manifestDigest": "sha256:manifest-enriched",
  "architectures": [
    {
      "arch": "amd64",
      "digest": "sha256:image-amd64",
      "size": 11,
      "layers": [
        { "digest": "sha256:layer-amd64", "size": 7, "diffID": null }
      ],
      "labels": { "org.opencontainers.image.source": "https://github.com/northcutted/clearcutt" }
    },
    {
      "arch": "arm64",
      "digest": "sha256:image-arm64",
      "size": 13,
      "layers": [
        { "digest": "sha256:layer-arm64", "size": 9, "diffID": "sha256:diff-arm64" }
      ],
      "labels": {}
    }
  ],
  "signature": {
    "cosignBundlePresent": true,
    "rekorLogIndex": 12345,
    "certificate": {
      "subject": "https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main",
      "issuer": "https://token.actions.githubusercontent.com",
      "runInvocation": null
    }
  },
  "provenance": {
    "predicateType": "https://slsa.dev/provenance/v1",
    "builder": { "id": "enrichment-builder" },
    "buildType": "enrichment-build",
    "sourceUri": "https://github.com/northcutted/clearcutt",
    "sourceRevision": "enrichment-rev",
    "slsaLevel": 3
  },
  "testResults": {
    "status": "passed",
    "timestamp": "2026-05-29T14:00:00Z",
    "assertions": [
      { "name": "Grype Vulnerability Gating", "status": "passed" }
    ]
  },
  "attestations": [
    {
      "kind": "slsa-provenance",
      "predicateType": "https://slsa.dev/provenance/v1",
      "subjectName": "ghcr.io/northcutted/clearcutt/clearcutt-python3.13",
      "subjectDigest": "sha256:subject",
      "signerIdentity": "https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main",
      "issuer": "https://token.actions.githubusercontent.com",
      "runUrl": "https://github.com/northcutted/clearcutt/actions/runs/1/attempts/1",
      "workflowUrl": "https://github.com/northcutted/clearcutt/actions/workflows/release.yml",
      "githubApiUrl": "https://api.github.com/users/northcutted/attestations/sha256:subject",
      "transparencyLogIndex": 67890,
      "transparencyUrl": "https://search.sigstore.dev/?logIndex=67890",
      "sources": ["oci", "github"]
    }
  ]
}`))
	writeTestFile(t, filepath.Join(vulnDir, tag, target+"-amd64.json"), []byte(`{"scannedAt":"2026-05-29T15:00:00Z","scanner":"grype-test","dbBuiltAt":null,"countsBySeverity":{"critical":1,"high":0,"medium":1,"low":0,"negligible":0,"unknown":0},"findings":[{"id":"CVE-2026-0001","severity":"Critical","packageName":"python3.13","packageVersion":"3.13.1","purl":"pkg:generic/python@3.13.1","layer":"runtime","fixedIn":"3.13.2","fixState":"fixed"},{"id":"CVE-2026-0003","severity":"Medium","packageName":"zlib","packageVersion":"1.3.1","purl":"pkg:nix/zlib@1.3.1","layer":"runtime","fixedIn":null,"fixState":"unknown"}]}`))
	writeTestFile(t, filepath.Join(vulnDir, tag, target+"-arm64.json"), []byte(`{"scannedAt":"2026-05-29T15:05:00Z","scanner":"grype-test","dbBuiltAt":null,"countsBySeverity":{"critical":1,"high":1,"medium":0,"low":0,"negligible":0,"unknown":0},"findings":[{"id":"CVE-2026-0001","severity":"Critical","packageName":"python3.13","packageVersion":"3.13.1","purl":"pkg:generic/python@3.13.1","layer":"runtime","fixedIn":"3.13.2","fixState":"fixed"},{"id":"CVE-2026-0002","severity":"High","packageName":"openssl","packageVersion":"3.5.0","purl":"pkg:nix/openssl@3.5.0","layer":"base","fixedIn":null,"fixState":"unknown"}]}`))

	spdxRaw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	intotoRaw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "catalog", "intoto-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCatalogReleaseSource{assets: map[string][]byte{
		target + "-amd64.sbom.json":         spdxRaw,
		target + "-arm64.sbom.json":         spdxRaw,
		target + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-05-29T13:59:00Z","assertions":[{"name":"Syft SBOM Generation","status":"passed"}]}`),
		target + ".intoto.jsonl":            intotoRaw,
		target + ".digest.json":             []byte(`{"digest":"sha256:manifest-release"}`),
	}}
	releases := []Release{{
		Tag:         tag,
		Name:        "v1.0.0",
		PublishedAt: publishedAt,
		Assets: []Asset{
			{Name: target + "-amd64.sbom.json", URL: "https://example.invalid/" + target + "-amd64.sbom.json"},
			{Name: target + "-arm64.sbom.json", URL: "https://example.invalid/" + target + "-arm64.sbom.json"},
			{Name: target + "-amd64.test-results.json", URL: "https://example.invalid/" + target + "-amd64.test-results.json"},
			{Name: target + ".intoto.jsonl", URL: "https://example.invalid/" + target + ".intoto.jsonl"},
			{Name: target + ".digest.json", URL: "https://example.invalid/" + target + ".digest.json"},
		},
	}}
	img, err := BuildImageRecord(target, releases, map[string]bool{tag: true}, BuildOptions{
		RegistryBase:  "ghcr.io/northcutted/clearcutt",
		SBOMCacheDir:  sbomDir,
		EnrichmentDir: enrichmentDir,
		VulnDir:       vulnDir,
		Source:        source,
	})
	if err != nil {
		t.Fatal(err)
	}
	if img == nil {
		t.Fatal("expected image record")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if _, err := os.Stat(filepath.Join(sbomDir, tag, target+"-"+arch+".sbom.json")); err != nil {
			t.Fatalf("expected persisted %s SBOM: %v", arch, err)
		}
	}
	provenanceRaw, err := json.Marshal(img.Releases[0].Provenance)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(provenanceRaw, []byte(`"raw"`)) {
		t.Fatalf("producer provenance should not re-emit raw passthrough: %s", provenanceRaw)
	}

	gotRaw, err := json.Marshal(catalogAssemblyFixture{
		Image:   img,
		Summary: SummarizeImageForIndex(*img),
	})
	if err != nil {
		t.Fatal(err)
	}
	compareCatalogGolden(t, filepath.Join("..", "commands", "testdata", "catalog", "assembly-golden.json"), gotRaw)
}

func TestBuildServiceImageRecordFoldsReleaseEvidence(t *testing.T) {
	const target = "postgres16"
	const tag = "v1.0.0"
	const publishedAt = "2026-06-05T12:00:00Z"

	temp := t.TempDir()
	sbomDir := filepath.Join(temp, "sboms")
	enrichmentDir := filepath.Join(temp, "enrichment")
	writeTestFile(t, filepath.Join(enrichmentDir, tag, target+".json"), []byte(`{
  "manifestDigest": "sha256:service-manifest",
  "architectures": [
    {
      "arch": "amd64",
      "digest": "sha256:service-amd64",
      "size": 42,
      "layers": [
        { "digest": "sha256:service-layer", "size": 21, "diffID": null }
      ],
      "labels": {
        "dev.clearcutt.image.kind": "service",
        "dev.clearcutt.service.id": "postgres16"
      }
    }
  ],
  "signature": {
    "cosignBundlePresent": true
  },
  "provenance": {
    "predicateType": "https://slsa.dev/provenance/v1",
    "builder": { "id": "service-builder" },
    "slsaLevel": 3
  }
}`))

	spdxRaw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	intotoRaw, err := os.ReadFile(filepath.Join("..", "commands", "testdata", "catalog", "intoto-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCatalogReleaseSource{assets: map[string][]byte{
		target + "-amd64.sbom.json":         spdxRaw,
		target + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-06-05T12:05:00Z","assertions":[{"name":"Syft SBOM Generation","status":"passed"}]}`),
		target + ".intoto.jsonl":            intotoRaw,
		target + ".digest.json":             []byte(`{"digest":"sha256:service-release-manifest"}`),
	}}
	releases := []Release{{
		Tag:         tag,
		Name:        "v1.0.0",
		PublishedAt: publishedAt,
		Assets: []Asset{
			{Name: target + "-amd64.sbom.json", URL: "https://example.invalid/" + target + "-amd64.sbom.json"},
			{Name: target + "-amd64.test-results.json", URL: "https://example.invalid/" + target + "-amd64.test-results.json"},
			{Name: target + ".intoto.jsonl", URL: "https://example.invalid/" + target + ".intoto.jsonl"},
			{Name: target + ".digest.json", URL: "https://example.invalid/" + target + ".digest.json"},
		},
	}}
	service := catalog.ServiceInfo{
		Template:    "postgres",
		Version:     "16",
		Ports:       []catalog.ServicePortInfo{{Name: "postgres", Port: 5432, Protocol: "tcp"}},
		Stateful:    true,
		DataDirs:    []string{"/var/lib/postgresql/data"},
		Smoke:       []string{"postgres --version"},
		SmokeStatus: "configured",
	}
	lifecycle := Lifecycle{Status: "preview", Support: "current", ProductionAllowed: false}
	runtimeContract := RuntimeContract{
		User:                  "10001:10001",
		WorkingDir:            "/app",
		ShellPresent:          true,
		PackageManagerPresent: false,
		CACertificatesPresent: true,
		TimezoneDataPresent:   false,
		DefaultEntrypoint:     Str("/bin/clearcutt-postgres-entrypoint"),
		ProductionTier:        false,
	}

	img, err := BuildServiceImageRecord(target, service, lifecycle, runtimeContract, releases, map[string]bool{tag: true}, BuildOptions{
		RegistryBase:  "ghcr.io/acme/platform",
		ImagePrefix:   "platform",
		SBOMCacheDir:  sbomDir,
		EnrichmentDir: enrichmentDir,
		Source:        source,
	})
	if err != nil {
		t.Fatal(err)
	}
	if img == nil {
		t.Fatal("expected service image record")
	}
	if img.SchemaVersion != catalog.ImageRecordSchemaVersionV2 || img.Kind != "service" || img.ID != target {
		t.Fatalf("unexpected service identity: %#v", img)
	}
	if img.ImageName != "platform-postgres16" || img.FullName != "ghcr.io/acme/platform/platform-postgres16" {
		t.Fatalf("unexpected service image names: %s %s", img.ImageName, img.FullName)
	}
	if img.Service == nil || img.Service.Template != "postgres" || len(img.Service.Ports) != 1 || img.Service.Ports[0].Port != 5432 {
		t.Fatalf("unexpected service metadata: %#v", img.Service)
	}
	latest := img.Releases[0]
	if latest.Evidence.ArchCount != 1 || !latest.Evidence.SBOM || !latest.Evidence.Tests || !latest.Evidence.Signature || !latest.Evidence.Provenance {
		t.Fatalf("unexpected service evidence: %#v", latest.Evidence)
	}
	if latest.Architectures[0].Labels == nil || !bytes.Contains(latest.Architectures[0].Labels, []byte(`"dev.clearcutt.image.kind"`)) {
		t.Fatalf("expected service OCI labels in architecture payload: %s", latest.Architectures[0].Labels)
	}
	summary := SummarizeImageForIndex(*img)
	if summary.Kind != "service" || summary.Service == nil || summary.LatestPackageCount == 0 || !summary.Signed || !summary.Provenance || !summary.Passed {
		t.Fatalf("unexpected service summary: %#v", summary)
	}
	if _, err := os.Stat(filepath.Join(sbomDir, tag, target+"-amd64.sbom.json")); err != nil {
		t.Fatalf("expected persisted service SBOM: %v", err)
	}
}

func TestWarningTestResultsSatisfyOnlyNonProductionEvidence(t *testing.T) {
	release := &gatherReleaseEntry{
		Lifecycle:       Lifecycle{Status: "preview", Support: "preview", ProductionAllowed: false},
		RuntimeContract: RuntimeContract{ProductionTier: false},
		Architectures: []gatherArchPayload{
			{Arch: "amd64", SBOM: gatherSBOMInfo{PackageCount: 1}, TestResults: &TestResults{Status: "warning"}, Vulnerabilities: rawJSONPtr(`{}`)},
			{Arch: "arm64", SBOM: gatherSBOMInfo{PackageCount: 1}, TestResults: &TestResults{Status: "warning"}, Vulnerabilities: rawJSONPtr(`{}`)},
		},
	}
	evidence := releaseEvidenceFromGather(release)
	if !evidence.Tests || evidence.PassedTestArchCount != 2 {
		t.Fatalf("non-production warning test results should satisfy evidence: %#v", evidence)
	}

	release.RuntimeContract.ProductionTier = true
	evidence = releaseEvidenceFromGather(release)
	if evidence.Tests || evidence.PassedTestArchCount != 0 {
		t.Fatalf("production-tier warning test results should not satisfy evidence: %#v", evidence)
	}

	release.RuntimeContract.ProductionTier = false
	release.Lifecycle.ProductionAllowed = true
	evidence = releaseEvidenceFromGather(release)
	if evidence.Tests || evidence.PassedTestArchCount != 0 {
		t.Fatalf("production-allowed warning test results should not satisfy evidence: %#v", evidence)
	}
}

func rawJSONPtr(value string) *json.RawMessage {
	raw := json.RawMessage(value)
	return &raw
}

func TestEnrichmentAttestationShapeOmitsReleaseAssetURL(t *testing.T) {
	raw, err := json.Marshal(Enrichment{
		Attestations: []EnrichmentAttestation{{
			Kind:          "slsa-provenance",
			PredicateType: "https://slsa.dev/provenance/v1",
			Sources:       []string{"oci"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("releaseAssetUrl")) {
		t.Fatalf("enrichment output must not include releaseAssetUrl; gather adds it to release records: %s", raw)
	}
	releaseAttestations := attachReleaseAssetLinks([]EnrichmentAttestation{{
		Kind:          "slsa-provenance",
		PredicateType: "https://slsa.dev/provenance/v1",
		Sources:       []string{"oci"},
	}}, Str("https://example.invalid/provenance.jsonl"))
	if len(releaseAttestations) != 1 || releaseAttestations[0].ReleaseAssetURL == nil {
		t.Fatalf("expected release attestation link to be attached: %#v", releaseAttestations)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func compareCatalogGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	var compactGot bytes.Buffer
	if err := json.Compact(&compactGot, got); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_CATALOG_GOLDEN") == "1" {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, compactGot.Bytes(), "", "  "); err != nil {
			t.Fatal(err)
		}
		pretty.WriteByte('\n')
		if err := os.WriteFile(path, pretty.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	goldenRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var compactWant bytes.Buffer
	if err := json.Compact(&compactWant, goldenRaw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compactGot.Bytes(), compactWant.Bytes()) {
		t.Fatalf("catalog assembly drift:\n got: %s\nwant: %s", compactGot.Bytes(), compactWant.Bytes())
	}
}
