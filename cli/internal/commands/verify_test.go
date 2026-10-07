package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func decodeVerify(t *testing.T, stdout string) VerifyResponse {
	t.Helper()
	var resp VerifyResponse
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("failed to parse verify JSON: %v\noutput:\n%s", err, stdout)
	}
	return resp
}

func checkStatus(checks []VerifyCheckResult, id string) (string, bool) {
	for _, c := range checks {
		if c.ID == id {
			return c.Status, true
		}
	}
	return "", false
}

// The fixture java21-distroless is fully attested, production-allowed, and has a
// single HIGH finding (CVE-2026-9999) deferred to the base layer.
func TestVerify_AllRequirementsPass(t *testing.T) {
	stdout, err := runCLI(t, "verify", "image", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json",
		"--require-signature", "--require-sbom", "--require-provenance",
		"--require-tests", "--require-vuln-scan", "--require-production")
	if err != nil {
		t.Fatalf("expected verification to pass, got error: %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	if resp.Status != "pass" {
		t.Fatalf("expected overall pass, got %q", resp.Status)
	}
	for _, id := range []string{"signature.present", "sbom.present", "provenance.present", "tests.passed", "lifecycle.productionAllowed"} {
		if st, ok := checkStatus(resp.Checks, id); !ok || st != "pass" {
			t.Errorf("expected %s to pass, got %q (present=%v)", id, st, ok)
		}
	}
}

func TestVerify_StaleAndObservedEvidenceDoNotSatisfyRequirements(t *testing.T) {
	dir := writeCommandSmokeCatalog(t)
	record, err := catalog.LoadImageRecord(dir, "java21-distroless")
	if err != nil {
		t.Fatal(err)
	}
	release := &record.Releases[0]
	release.ManifestDigest = stringPtr("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	release.Evidence = &catalog.EvidenceSummary{
		Signature:              true,
		Provenance:             true,
		SBOM:                   true,
		Tests:                  true,
		Vulnerabilities:        true,
		ArchCount:              1,
		SBOMArchCount:          1,
		TestArchCount:          1,
		PassedTestArchCount:    1,
		VulnerabilityArchCount: 1,
		Statuses: &catalog.EvidenceStatuses{
			Signature:       catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusObserved},
			Provenance:      catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusAttested},
			SBOM:            catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusStale},
			Tests:           catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusStale},
			Vulnerabilities: catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusStale},
		},
	}
	writeCatalogJSON(t, filepath.Join(dir, "images", "java21-distroless.json"), record)

	stdout, err := runCLI(t, "--catalog", dir, "--format", "json", "verify", "image", "java21-distroless",
		"--allow-preview", "--require-signature", "--require-sbom", "--require-provenance", "--require-tests", "--require-vuln-scan")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("non-verified and stale evidence must fail: %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	for _, id := range []string{"signature.present", "sbom.present", "provenance.present", "tests.passed", "vulnerabilities.scanned"} {
		if status, ok := checkStatus(resp.Checks, id); !ok || status != "fail" {
			t.Fatalf("%s should fail, got %q (present=%v): %+v", id, status, ok, resp.Checks)
		}
	}
}

func TestVerify_ThresholdFailsAndReturnsSentinel(t *testing.T) {
	stdout, err := runCLI(t, "verify", "image", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json", "--max-high", "0")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed, got %v", err)
	}
	resp := decodeVerify(t, stdout)
	if resp.Status != "fail" {
		t.Fatalf("expected overall fail, got %q", resp.Status)
	}
	if st, _ := checkStatus(resp.Checks, "vulnerabilities.threshold.high"); st != "fail" {
		t.Errorf("expected high threshold check to fail, got %q", st)
	}
}

func TestVerify_ActiveExceptionExemptsFinding(t *testing.T) {
	excPath := writeExceptions(t, "2999-01-01") // far-future expiry => active
	stdout, err := runCLI(t, "verify", "image", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json", "--max-high", "0",
		"--allow-exceptions", "--exceptions", excPath)
	if err != nil {
		t.Fatalf("active exception should exempt the finding and pass, got: %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	if resp.Status != "pass" {
		t.Fatalf("expected pass with active exception, got %q", resp.Status)
	}
}

// Providing --exceptions is sufficient to honour active exceptions; the legacy
// --allow-exceptions toggle is no longer required (it used to make the file a
// silent no-op when omitted).
func TestVerify_ExceptionsFileAloneHonorsExceptions(t *testing.T) {
	excPath := writeExceptions(t, "2999-01-01") // far-future expiry => active
	stdout, err := runCLI(t, "verify", "image", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json", "--max-high", "0",
		"--exceptions", excPath)
	if err != nil {
		t.Fatalf("expected --exceptions alone to honour the active exception and pass, got: %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	if resp.Status != "pass" {
		t.Fatalf("expected pass with active exception and no --allow-exceptions, got %q", resp.Status)
	}
}

func TestVerify_LegacyImageFormStillAcceptsImageFlags(t *testing.T) {
	excPath := writeExceptions(t, "2999-01-01") // far-future expiry => active
	stdout, err := runCLI(t, "verify", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json", "--max-high", "0",
		"--exceptions", excPath)
	if err != nil {
		t.Fatalf("legacy verify form should still accept image flags, got: %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	if resp.Status != "pass" {
		t.Fatalf("expected pass with legacy verify form, got %q", resp.Status)
	}
}

func TestVerify_ExpiredExceptionIsNotHonored(t *testing.T) {
	excPath := writeExceptions(t, "2000-01-01") // past expiry => expired
	stdout, err := runCLI(t, "verify", "image", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json", "--max-high", "0",
		"--allow-exceptions", "--exceptions", excPath)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expired exception must not exempt; expected ErrCheckFailed, got %v", err)
	}
	resp := decodeVerify(t, stdout)
	if st, ok := checkStatus(resp.Checks, "exceptions.expired"); !ok || st != "fail" {
		t.Errorf("expected a dedicated exceptions.expired failure, got %q (present=%v)", st, ok)
	}
}

// writeExceptions creates an exceptions file exempting the fixture's CVE-2026-9999
// with the given expiry date, and returns its path.
func writeExceptions(t *testing.T, expiry string) string {
	t.Helper()
	content := `apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: test-exceptions
spec:
  exceptions:
    - id: CVE-2026-9999
      package: openssl
      image: java21-distroless
      release: v1.0.0
      status: not_affected
      reason: inherited_from_base
      owner: security
      createdAt: "2026-01-01"
      expiresAt: "` + expiry + `"
      references:
        - https://example.invalid/advisory
`
	dir := t.TempDir()
	path := filepath.Join(dir, "exceptions.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write exceptions file: %v", err)
	}
	return path
}

func TestVerify_HumanOutputAndMissingImage(t *testing.T) {
	// Human (table) output should render a result banner.
	stdout, err := runCLI(t, "verify", "image", "java21-distroless", "--catalog", fixtureCatalog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "Verification Result: PASS") {
		t.Errorf("expected human-readable PASS banner, got:\n%s", stdout)
	}

	// A missing image is a real error (not a gate failure) and must not be ErrCheckFailed.
	if _, err := runCLI(t, "verify", "image", "does-not-exist", "--catalog", fixtureCatalog()); err == nil || errors.Is(err, ErrCheckFailed) {
		t.Errorf("expected a load error for missing image, got %v", err)
	}
}

func TestVerifyYAMLAndLifecycleBranches(t *testing.T) {
	dir := writeCommandSmokeCatalog(t)
	stdout, err := runCLI(t,
		"--catalog", dir,
		"--format", "yaml",
		"verify", "image", "java21-distroless",
		"--tag", "v1.0.0",
		"--require-signature",
		"--require-tests",
		"--require-production",
	)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected preview/missing evidence to fail, got %v\n%s", err, stdout)
	}
	for _, want := range []string{"status: fail", "signature.present", "tests.passed", "lifecycle.productionAllowed", "lifecycle.status"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %q in YAML verification report:\n%s", want, stdout)
		}
	}

	stdout, err = runCLI(t,
		"--catalog", dir,
		"--format", "json",
		"verify", "image", "java21-distroless",
		"--tag", "v1.0.0",
		"--allow-preview",
		"--max-critical", "0",
	)
	if err != nil {
		t.Fatalf("allow-preview verification should pass without production/test requirements: %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	if st, _ := checkStatus(resp.Checks, "vulnerabilities.threshold.critical"); st != "pass" {
		t.Fatalf("expected critical threshold pass, got %+v", resp.Checks)
	}
}

func TestVerifyLifecycleStatusFailures(t *testing.T) {
	dir := writeCommandSmokeCatalog(t)
	rec, err := catalog.LoadImageRecord(dir, "java21-distroless")
	if err != nil {
		t.Fatal(err)
	}
	base := rec.Releases[0]
	base.Evidence = &catalog.EvidenceSummary{Signature: true, Provenance: true, SBOM: true, Tests: true, Vulnerabilities: true, ArchCount: 1, SBOMArchCount: 1, TestArchCount: 1, PassedTestArchCount: 1, VulnerabilityArchCount: 1}
	base.Lifecycle.ProductionAllowed = true
	rec.Releases = nil
	for _, status := range []string{"deprecated", "eol", "blocked"} {
		rel := base
		rel.Tag = "v-" + status
		rel.Lifecycle.Status = status
		rec.Releases = append(rec.Releases, rel)
	}
	writeCatalogJSON(t, filepath.Join(dir, "images", "java21-distroless.json"), rec)

	for _, tag := range []string{"v-deprecated", "v-eol", "v-blocked"} {
		stdout, err := runCLI(t, "--catalog", dir, "--format", "json", "verify", "image", "java21-distroless", "--tag", tag)
		if !errors.Is(err, ErrCheckFailed) {
			t.Fatalf("%s should fail lifecycle verification, got %v\n%s", tag, err, stdout)
		}
		resp := decodeVerify(t, stdout)
		if st, _ := checkStatus(resp.Checks, "lifecycle.status"); st != "fail" {
			t.Fatalf("%s expected lifecycle.status fail, got %+v", tag, resp.Checks)
		}
	}

	stdout, err := runCLI(t, "--catalog", dir, "--format", "json", "verify", "image", "java21-distroless", "--tag", "v-deprecated", "--allow-deprecated")
	if err != nil {
		t.Fatalf("allow-deprecated should pass deprecated lifecycle: %v\n%s", err, stdout)
	}
}
