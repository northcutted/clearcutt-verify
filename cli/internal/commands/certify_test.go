package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/certify"
)

func createMockLayerTar(t *testing.T, filenames []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range filenames {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: 0}); err != nil {
			t.Fatalf("failed to write layer header: %v", err)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func createMockTarball(t *testing.T, files map[string][]byte) string {
	t.Helper()
	tmpFile, err := os.CreateTemp(t.TempDir(), "clearcutt-test-*.tar")
	if err != nil {
		t.Fatalf("failed to create temp tarball: %v", err)
	}
	tw := tar.NewWriter(tmpFile)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content))}); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("failed to write content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	tmpFile.Close()
	return tmpFile.Name()
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	gw.Close()
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func mockConfig(t *testing.T, user string) []byte {
	t.Helper()
	var config certify.OCIImageConfig
	config.Config.User = user
	config.Config.Labels = map[string]string{"org.opencontainers.image.source": "https://github.com/org/repo"}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return b
}

// dockerTarball builds a legacy `docker save` style archive.
func dockerTarball(t *testing.T, config, layer []byte) string {
	t.Helper()
	manifest, _ := json.Marshal([]certify.DockerManifest{{Config: "config.json", RepoTags: []string{"test-app:latest"}, Layers: []string{"layer.tar"}}})
	return createMockTarball(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   config,
		"layer.tar":     layer,
	})
}

// ociTarball builds an OCI-layout archive (index.json + blobs/sha256/*).
func ociTarball(t *testing.T, config, layer []byte) string {
	t.Helper()
	cfgDigest := sha256Hex(config)
	layerDigest := sha256Hex(layer)
	man, _ := json.Marshal(certify.Manifest{
		Config: certify.Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: "sha256:" + cfgDigest, Size: int64(len(config))},
		Layers: []certify.Descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + layerDigest, Size: int64(len(layer))}},
	})
	manDigest := sha256Hex(man)
	index, _ := json.Marshal(certify.Index{Manifests: []certify.Descriptor{{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:" + manDigest, Size: int64(len(man))}}})
	return createMockTarball(t, map[string][]byte{
		"oci-layout":                  []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json":                  index,
		"blobs/sha256/" + cfgDigest:   config,
		"blobs/sha256/" + layerDigest: layer,
		"blobs/sha256/" + manDigest:   man,
	})
}

func nestedOCITarball(t *testing.T, config, layer []byte) string {
	t.Helper()
	cfgDigest := sha256Hex(config)
	layerDigest := sha256Hex(layer)
	man, _ := json.Marshal(certify.Manifest{
		Config: certify.Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: "sha256:" + cfgDigest, Size: int64(len(config))},
		Layers: []certify.Descriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + layerDigest, Size: int64(len(layer))}},
	})
	manDigest := sha256Hex(man)
	nested, _ := json.Marshal(certify.Index{Manifests: []certify.Descriptor{{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:" + manDigest, Size: int64(len(man))}}})
	nestedDigest := sha256Hex(nested)
	index, _ := json.Marshal(certify.Index{Manifests: []certify.Descriptor{{
		MediaType:   "application/vnd.oci.image.index.v1+json",
		Digest:      "sha256:" + nestedDigest,
		Size:        int64(len(nested)),
		Annotations: map[string]string{"org.opencontainers.image.ref.name": "ghcr.io/acme/app@sha256:" + nestedDigest},
	}}})
	return createMockTarball(t, map[string][]byte{
		"oci-layout":                   []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json":                   index,
		"blobs/sha256/" + cfgDigest:    config,
		"blobs/sha256/" + layerDigest:  layer,
		"blobs/sha256/" + manDigest:    man,
		"blobs/sha256/" + nestedDigest: nested,
	})
}

func runCertifyJSON(t *testing.T, tarball string, extra ...string) (CertifyResponse, error) {
	t.Helper()
	args := append([]string{"certify", tarball, "--base", "java21-distroless", "--catalog", fixtureCatalog(), "--format", "json"}, extra...)
	stdout, err := runCLI(t, args...)
	var resp CertifyResponse
	if uerr := json.Unmarshal([]byte(stdout), &resp); uerr != nil {
		t.Fatalf("failed to parse certify JSON: %v\n%s", uerr, stdout)
	}
	return resp, err
}

func certifyCheck(resp CertifyResponse, id string) (string, bool) {
	for _, c := range resp.Checks {
		if c.ID == id {
			return c.Status, true
		}
	}
	return "", false
}

func TestCertify_CompliantDocker(t *testing.T) {
	tarball := dockerTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball)
	if err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	if resp.Status != "pass" {
		t.Fatalf("expected pass, got %q", resp.Status)
	}
	if st, _ := certifyCheck(resp, "config.user.nonroot"); st != "pass" {
		t.Errorf("user.nonroot expected pass, got %q", st)
	}
	if st, _ := certifyCheck(resp, "contract.shell.absence"); st != "pass" {
		t.Errorf("shell.absence expected pass, got %q", st)
	}
}

func TestCertify_CompliantOCILayout(t *testing.T) {
	tarball := ociTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball)
	if err != nil {
		t.Fatalf("expected OCI-layout archive to certify, got %v", err)
	}
	if st, _ := certifyCheck(resp, "manifest.parsed"); st != "pass" {
		t.Errorf("manifest.parsed expected pass for OCI layout, got %q", st)
	}
	if st, _ := certifyCheck(resp, "config.user.nonroot"); st != "pass" {
		t.Errorf("user.nonroot expected pass, got %q", st)
	}
}

func TestCertify_RootViolation(t *testing.T) {
	tarball := dockerTarball(t, mockConfig(t, "root"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed for root user, got %v", err)
	}
	if st, _ := certifyCheck(resp, "config.user.nonroot"); st != "fail" {
		t.Errorf("expected user.nonroot fail, got %q", st)
	}
}

// Covers both the gzip-layer decoding and the shell detection in a distroless tier.
func TestCertify_ShellViolationInGzippedLayer(t *testing.T) {
	layer := gzipBytes(t, createMockLayerTar(t, []string{"bin/sh", "usr/bin/apk"}))
	tarball := dockerTarball(t, mockConfig(t, "10001"), layer)
	resp, err := runCertifyJSON(t, tarball)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed for shell/pkg-manager in distroless layer, got %v", err)
	}
	if st, _ := certifyCheck(resp, "contract.shell.absence"); st != "fail" {
		t.Errorf("expected shell.absence fail (gzip layer), got %q", st)
	}
	if st, _ := certifyCheck(resp, "contract.package_manager.absence"); st != "fail" {
		t.Errorf("expected package_manager.absence fail, got %q", st)
	}
}

// Required supply-chain attestations are reported as skipped (not falsely passed)
// because they cannot be verified from an offline tarball.
func TestCertify_EvidenceChecksAreSkippedNotPassed(t *testing.T) {
	tarball := dockerTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball, "--require-signature", "--require-sbom", "--require-provenance")
	if err != nil {
		t.Fatalf("offline evidence gaps should not fail certification, got %v", err)
	}
	for _, id := range []string{"evidence.signature.verified", "evidence.sbom.present", "evidence.provenance.present"} {
		st, ok := certifyCheck(resp, id)
		if !ok {
			t.Errorf("expected %s to be present", id)
		}
		if st == "pass" {
			t.Errorf("%s must not be reported as pass offline; got %q", id, st)
		}
		if st != "skip" {
			t.Errorf("%s expected skip, got %q", id, st)
		}
	}
}

func TestCertifyImageRefSatisfiesDigestPinnedPolicy(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte(`apiVersion: clearcutt.dev/v1
kind: CertificationPolicy
metadata:
  name: digest-policy
spec:
  base:
    allowedImages:
      - java21-distroless
    requireDigestPinned: true
    requireKnownBase: true
  supplyChain:
    requireSignature: false
    requireProvenance: false
    requireSbom: false
  runtime:
    requireNonRoot: true
    forbidShell: true
    forbidPackageManagers: true
    forbidDevTier: true
  vulnerabilities:
    maxCritical: 999
    maxHigh: 999
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	tarball := dockerTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	resp, err := runCertifyJSON(t, tarball, "--policy", policy, "--image-ref", "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("expected image-ref digest pin to satisfy policy, got %v", err)
	}
	if st, _ := certifyCheck(resp, "policy.base.digestPinned"); st != "pass" {
		t.Fatalf("digestPinned expected pass, got %q", st)
	}
}

func TestCertifyPolicyFailuresAndYAMLReporting(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte(`apiVersion: clearcutt.dev/v1
kind: CertificationPolicy
metadata:
  name: strict-production
spec:
  base:
    allowedImages:
      - python3.14-slim
    requireDigestPinned: true
  supplyChain:
    requireSignature: true
    requireProvenance: true
    requireSbom: true
    minimumSlsaLevel: 3
  runtime:
    requireNonRoot: true
    forbidShell: true
    forbidPackageManagers: true
    forbidDevTier: true
  vulnerabilities:
    maxCritical: 0
    maxHigh: 0
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	tarball := dockerTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	stdout, err := runCLI(t,
		"certify", tarball,
		"--base", "java21-distroless",
		"--catalog", fixtureCatalog(),
		"--policy", policy,
		"--format", "json",
	)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected strict policy to fail, got %v\n%s", err, stdout)
	}
	var resp CertifyResponse
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("parse certify output: %v\n%s", err, stdout)
	}
	for id, want := range map[string]string{
		"policy.base.allowed":             "fail",
		"policy.base.digestPinned":        "fail",
		"policy.supplychain.slsaLevel":    "skip",
		"policy.vulnerabilities.critical": "pass",
		"policy.vulnerabilities.high":     "fail",
		"evidence.signature.verified":     "skip",
		"evidence.sbom.present":           "skip",
		"evidence.provenance.present":     "skip",
	} {
		if got, ok := certifyCheck(resp, id); !ok || got != want {
			t.Fatalf("%s status = %q ok=%v, want %q; response=%+v", id, got, ok, want, resp)
		}
	}

	stdout, err = runCLI(t,
		"certify", tarball,
		"--base", "java21-distroless",
		"--catalog", fixtureCatalog(),
		"--format", "yaml",
	)
	if err != nil {
		t.Fatalf("expected YAML certify pass, got %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "status: pass") || !strings.Contains(stdout, "config.user.nonroot") {
		t.Fatalf("expected YAML certify report, got:\n%s", stdout)
	}
}

func TestCertifyTarballParsingAndLayerErrorBranches(t *testing.T) {
	tempDir := t.TempDir()
	if _, err := certify.LoadImageArchive(filepath.Join(tempDir, "missing.tar"), tempDir); err == nil || !strings.Contains(err.Error(), "unable to open") {
		t.Fatalf("expected missing tarball error, got %v", err)
	}

	badGzip := filepath.Join(tempDir, "bad.tgz")
	if err := os.WriteFile(badGzip, []byte("not-gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := certify.LoadImageArchive(badGzip, tempDir); err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("expected gzip init error, got %v", err)
	}

	config := mockConfig(t, "10001")
	layer := createMockLayerTar(t, []string{"app/main.js"})
	tarball := nestedOCITarball(t, config, layer)
	img, err := certify.LoadImageArchive(tarball, t.TempDir())
	if err != nil {
		t.Fatalf("load nested OCI: %v", err)
	}
	if img.Format != "oci" || len(img.RepoTags) != 1 || len(img.ConfigRaw) == 0 || len(img.LayerPaths) != 1 {
		t.Fatalf("unexpected nested OCI resolution: %+v", img)
	}
	if certify.BlobPath(map[string]string{}, "not-a-digest") != "" || certify.ReadBlob(map[string]string{}, "sha256:missing") != nil {
		t.Fatal("blob helpers should ignore malformed or missing digests")
	}

	badLayerTarball := dockerTarball(t, mockConfig(t, "10001"), []byte("not a tar layer"))
	resp, err := runCertifyJSON(t, badLayerTarball)
	if err != nil {
		t.Fatalf("unreadable layer audit should skip, not fail: %v", err)
	}
	if st, _ := certifyCheck(resp, "contract.shell.absence"); st != "skip" {
		t.Fatalf("expected shell audit skip for unreadable layer, got %q", st)
	}
}

func TestCertifyRejectsInvalidPolicyDocuments(t *testing.T) {
	tarball := dockerTarball(t, mockConfig(t, "10001"), createMockLayerTar(t, []string{"app/main.js"}))
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte(`apiVersion: wrong/v1
kind: CertificationPolicy
metadata:
  name: invalid
`), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t, "certify", tarball, "--policy", policy)
	if err == nil || !strings.Contains(err.Error(), "invalid certification policy apiVersion") {
		t.Fatalf("expected invalid policy apiVersion error, got %v\n%s", err, stdout)
	}
	if err := os.WriteFile(policy, []byte(`apiVersion: clearcutt.dev/v1
kind: WrongKind
metadata:
  name: invalid
`), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, err = runCLI(t, "certify", tarball, "--policy", policy)
	if err == nil || !strings.Contains(err.Error(), "invalid certification policy kind") {
		t.Fatalf("expected invalid policy kind error, got %v\n%s", err, stdout)
	}
}

func TestCertifyVulnGateCatalogCountsAndExceptions(t *testing.T) {
	oldCatalog := GlobalOpts.CatalogPath
	GlobalOpts.CatalogPath = writeCommandSmokeCatalog(t)
	t.Cleanup(func() { GlobalOpts.CatalogPath = oldCatalog })

	policy := &CertificationPolicyDoc{}
	policy.Spec.Vulnerabilities.MaxCritical = 0
	policy.Spec.Vulnerabilities.MaxHigh = 0

	statuses := map[string]string{}
	certifyVulnGate(policy, "java21-distroless", func(id, status, message string) {
		statuses[id] = status
	})
	if statuses["policy.vulnerabilities.critical"] != "fail" || statuses["policy.vulnerabilities.high"] != "pass" {
		t.Fatalf("unexpected smoke catalog vuln statuses: %#v", statuses)
	}

	exceptionsFile := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(exceptionsFile, []byte(`apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: test-exceptions
spec:
  exceptions:
    - id: CVE-NEW
      package: zlib
      image: java21-distroless
      release: v2.0.0
      status: accepted_risk
      reason: temporary_business_exception
      owner: security
      createdAt: 2026-01-01
      expiresAt: 2999-01-01
      references:
        - https://example.invalid/risk
`), 0o644); err != nil {
		t.Fatal(err)
	}
	policy.Spec.Vulnerabilities.AllowExceptions = true
	policy.Spec.Vulnerabilities.ExceptionFile = exceptionsFile
	statuses = map[string]string{}
	certifyVulnGate(policy, "java21-distroless", func(id, status, message string) {
		statuses[id] = status
	})
	if statuses["policy.vulnerabilities.critical"] != "pass" {
		t.Fatalf("active exception should suppress critical finding, got %#v", statuses)
	}

	countDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(countDir, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	GlobalOpts.CatalogPath = countDir
	writeCatalogJSON(t, filepath.Join(countDir, "images", "counts-only.json"), catalog.ImageRecord{
		ID:       "counts-only",
		Language: catalog.LanguageInfo{ID: "java", DisplayName: "Java", Version: "21"},
		Tier:     catalog.TierInfo{ID: "distroless", Name: "Distroless", Blurb: "Minimal runtime"},
		Releases: []catalog.ReleaseEntry{{
			Tag:       "v1.0.0",
			IsLatest:  true,
			AssetURLs: catalog.AssetURLs{},
			Architectures: []catalog.ArchPayload{{
				Arch:   "amd64",
				OS:     "linux",
				Layers: []catalog.LayerInfo{},
				Labels: map[string]string{},
				SBOM:   catalog.SBOMInfo{Tool: "syft", Packages: []catalog.PackageEntry{}},
				Vulnerabilities: &catalog.VulnerabilitiesInfo{
					Scanner: "grype",
					CountsBySeverity: catalog.SeverityCounts{
						Critical: 0,
						High:     2,
					},
					Findings: []catalog.FindingInfo{},
				},
			}},
		}},
	})
	countPolicy := &CertificationPolicyDoc{}
	countPolicy.Spec.Vulnerabilities.MaxCritical = 0
	countPolicy.Spec.Vulnerabilities.MaxHigh = 1
	statuses = map[string]string{}
	certifyVulnGate(countPolicy, "counts-only", func(id, status, message string) {
		statuses[id] = status
	})
	if statuses["policy.vulnerabilities.critical"] != "pass" || statuses["policy.vulnerabilities.high"] != "fail" {
		t.Fatalf("count-only vulnerability gate statuses = %#v", statuses)
	}
}

func TestCertify_UnrecognizedArchiveFails(t *testing.T) {
	tarball := createMockTarball(t, map[string][]byte{"random.txt": []byte("not an image")})
	resp, err := runCertifyJSON(t, tarball)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed for unrecognized archive, got %v", err)
	}
	if st, _ := certifyCheck(resp, "manifest.parsed"); st != "fail" {
		t.Errorf("expected manifest.parsed fail, got %q", st)
	}
}
