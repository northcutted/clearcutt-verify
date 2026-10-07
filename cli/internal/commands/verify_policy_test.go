package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/config"
)

func TestFindingMateriality(t *testing.T) {
	pol := config.DefaultRemediationPolicy() // runtime, sev>=high, epss>=0.90, kev=always

	cases := []struct {
		name    string
		finding catalog.FindingInfo
		prod    bool
		want    config.RiskDisposition
	}{
		{
			name:    "runtime high fixable -> must_fix",
			finding: catalog.FindingInfo{ID: "CVE-1", Severity: "High", Layer: "runtime", FixedIn: strPtr("1.2.3")},
			prod:    true,
			want:    config.DispositionMustFix,
		},
		{
			name:    "runtime high unfixable -> must_acknowledge",
			finding: catalog.FindingInfo{ID: "CVE-2", Severity: "High", Layer: "runtime", FixedIn: nil},
			prod:    true,
			want:    config.DispositionMustAcknowledge,
		},
		{
			name:    "base layer -> auto_accept (not reachable)",
			finding: catalog.FindingInfo{ID: "CVE-3", Severity: "Critical", Layer: "base", FixedIn: strPtr("2.0")},
			prod:    true,
			want:    config.DispositionAutoAccept,
		},
		{
			name:    "non-production tier -> auto_accept",
			finding: catalog.FindingInfo{ID: "CVE-4", Severity: "Critical", Layer: "runtime", FixedIn: strPtr("2.0")},
			prod:    false,
			want:    config.DispositionAutoAccept,
		},
		{
			name:    "runtime medium low-epss -> auto_accept (below bar)",
			finding: catalog.FindingInfo{ID: "CVE-5", Severity: "Medium", Layer: "runtime", FixedIn: strPtr("1.1")},
			prod:    true,
			want:    config.DispositionAutoAccept,
		},
		{
			name:    "empty FixedIn string counts as unfixable",
			finding: catalog.FindingInfo{ID: "CVE-6", Severity: "High", Layer: "runtime", FixedIn: strPtr("  ")},
			prod:    true,
			want:    config.DispositionMustAcknowledge,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := findingMateriality(c.finding, c.prod, pol)
			if got.Disposition != c.want {
				t.Errorf("findingMateriality = %s, want %s (reason %q)", got.Disposition, c.want, got.Reason)
			}
		})
	}
}

func TestWritePolicyVEXExpiringRecords(t *testing.T) {
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	accepted := map[string]policyAcceptance{
		"a": {Finding: catalog.FindingInfo{ID: "CVE-2026-1", PackageName: "glibc"}, Reason: "not_reachable_base_layer"},
		"b": {Finding: catalog.FindingInfo{ID: "CVE-2026-2", PackageName: "curl"}, Reason: "below_risk_threshold"},
	}
	out := filepath.Join(t.TempDir(), "nested", "vex.json")
	if err := writePolicyVEX(out, "python3.13-slim", "v1.0.0", accepted, 90, now); err != nil {
		t.Fatalf("writePolicyVEX: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read vex: %v", err)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vex: %v\n%s", err, raw)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(doc.Statements))
	}
	for _, s := range doc.Statements {
		if s.Status != vexAffected {
			t.Errorf("%s: policy acceptance should be 'affected', got %q", s.Vulnerability.Name, s.Status)
		}
		if s.ClearCutt == nil || s.ClearCutt.Acceptance != "policy_auto_accept" {
			t.Errorf("%s: missing clearcutt policy_auto_accept extension: %+v", s.Vulnerability.Name, s.ClearCutt)
		}
		if s.ClearCutt.ExpiresAt != "2026-09-13" { // 2026-06-15 + 90 days
			t.Errorf("%s: expected expiry 2026-09-13, got %q", s.Vulnerability.Name, s.ClearCutt.ExpiresAt)
		}
	}
	// Deterministic ordering: sorted by CVE.
	if doc.Statements[0].Vulnerability.Name != "CVE-2026-1" {
		t.Errorf("statements not sorted: %s first", doc.Statements[0].Vulnerability.Name)
	}
}

func TestSummarizeFindingKeysCaps(t *testing.T) {
	findings := map[string]catalog.FindingInfo{}
	for i := 0; i < 12; i++ {
		id := "CVE-" + string(rune('a'+i))
		findings[id] = catalog.FindingInfo{ID: id, PackageName: "pkg"}
	}
	summary := summarizeFindingKeys(findings)
	if !strings.Contains(summary, "+4 more") {
		t.Errorf("expected the cap marker '+4 more', got %q", summary)
	}
}

// End-to-end: the opt-in policy gate passes for the fixture (its only finding is
// base-layer, so it auto-accepts under runtime reachability) and the accept set
// is emitted as an expiring VEX record.
func TestVerifyPolicyGateIntegrationAndVEXOutput(t *testing.T) {
	vexOut := filepath.Join(t.TempDir(), "vex.json")
	stdout, err := runCLI(t, "verify", "image", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json",
		"--require-vuln-policy", "--vex-output", vexOut)
	if err != nil {
		t.Fatalf("base-layer finding should auto-accept and pass the policy gate, got: %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	if st, ok := checkStatus(resp.Checks, "vulnerabilities.policy.fixable"); !ok || st != "pass" {
		t.Errorf("expected vulnerabilities.policy.fixable pass, got %q (present=%v)", st, ok)
	}
	if st, ok := checkStatus(resp.Checks, "vulnerabilities.policy.acknowledge"); !ok || st != "pass" {
		t.Errorf("expected vulnerabilities.policy.acknowledge pass, got %q (present=%v)", st, ok)
	}

	raw, err := os.ReadFile(vexOut)
	if err != nil {
		t.Fatalf("expected a VEX output file: %v", err)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vex: %v", err)
	}
	if len(doc.Statements) != 1 || doc.Statements[0].Vulnerability.Name != "CVE-2026-9999" {
		t.Fatalf("expected one policy-accepted VEX record for CVE-2026-9999, got %+v", doc.Statements)
	}
	ext := doc.Statements[0].ClearCutt
	if ext == nil || ext.Reason != "not_reachable_base_layer" || ext.ExpiresAt == "" {
		t.Fatalf("expected an expiring base-layer acceptance, got %+v", ext)
	}
}

// An expired exception must be surfaced (and block) on the policy path too — the
// 'never silent' contract, consistent with the legacy --max-* path.
func TestVerifyPolicyGateSurfacesExpiredException(t *testing.T) {
	excPath := writeExceptions(t, "2000-01-01") // past => expired
	stdout, err := runCLI(t, "verify", "image", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json",
		"--require-vuln-policy", "--exceptions", excPath)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expired exception must block on the policy path; got %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	if st, ok := checkStatus(resp.Checks, "vulnerabilities.policy.expiredExceptions"); !ok || st != "fail" {
		t.Errorf("expected vulnerabilities.policy.expiredExceptions fail, got %q (present=%v)", st, ok)
	}
}

// Legacy verify (no policy flags) must be byte-for-byte unaffected: the policy
// section never runs and emits no extra checks.
func TestVerifyPolicyGateOptInOnly(t *testing.T) {
	stdout, err := runCLI(t, "verify", "image", "java21-distroless",
		"--catalog", fixtureCatalog(), "--format", "json")
	if err != nil && !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("unexpected error: %v\n%s", err, stdout)
	}
	resp := decodeVerify(t, stdout)
	for _, id := range []string{"vulnerabilities.policy.fixable", "vulnerabilities.policy.acknowledge"} {
		if _, ok := checkStatus(resp.Checks, id); ok {
			t.Errorf("policy check %s must not appear without --require-vuln-policy", id)
		}
	}
}
