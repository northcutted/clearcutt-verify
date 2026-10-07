package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

var validVexStatuses = map[string]bool{
	"not_affected": true, "affected": true, "fixed": true, "under_investigation": true,
}

var validVexJustifications = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

func TestVex_GeneratesCompliantDocument(t *testing.T) {
	stdout, err := runCLI(t, "vex", "java21-distroless", "--catalog", fixtureCatalog())
	if err != nil {
		t.Fatalf("vex failed: %v\n%s", err, stdout)
	}

	var doc OpenVEXDocument
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("failed to parse OpenVEX JSON: %v\n%s", err, stdout)
	}
	if len(doc.Statements) == 0 {
		t.Fatal("expected at least one VEX statement for the fixture's finding")
	}

	for i, stmt := range doc.Statements {
		if !validVexStatuses[stmt.Status] {
			t.Errorf("statement[%d] %s: invalid OpenVEX status %q", i, stmt.Vulnerability.Name, stmt.Status)
		}
		// A justification is only valid when status is not_affected.
		if stmt.Justification != "" {
			if stmt.Status != "not_affected" {
				t.Errorf("statement[%d] %s: justification present on status %q (only valid for not_affected)", i, stmt.Vulnerability.Name, stmt.Status)
			}
			if !validVexJustifications[stmt.Justification] {
				t.Errorf("statement[%d] %s: invalid OpenVEX justification %q", i, stmt.Vulnerability.Name, stmt.Justification)
			}
		}
	}

	// The fixture's CVE-2026-9999 is deferred to the base layer. That is a
	// remediation-scope fact, not proof that the product is unaffected.
	if doc.Statements[0].Vulnerability.Name != "CVE-2026-9999" || doc.Statements[0].Status != vexUnderInvestigation {
		t.Errorf("expected CVE-2026-9999 to stay under investigation, got %q -> %q",
			doc.Statements[0].Vulnerability.Name, doc.Statements[0].Status)
	}
}

// An exception status with no direct OpenVEX equivalent must not leak through.
func TestVexStatusMapping(t *testing.T) {
	cases := map[string]string{
		"accepted_risk":       "affected",
		"false_positive":      "not_affected",
		"affected":            "affected",
		"fixed":               "fixed",
		"under_investigation": "under_investigation",
		"nonsense":            "under_investigation",
	}
	for in, want := range cases {
		if got := vexStatusFromException(in); got != want {
			t.Errorf("vexStatusFromException(%q) = %q, want %q", in, got, want)
		}
		if !validVexStatuses[vexStatusFromException(in)] {
			t.Errorf("vexStatusFromException(%q) produced an invalid OpenVEX status", in)
		}
	}
}

func TestVexExceptionsOutputAndYAMLBranches(t *testing.T) {
	dir := writeCommandSmokeCatalog(t)
	exceptionsPath := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(exceptionsPath, []byte(`apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: app-team-triage
spec:
  exceptions:
    - id: CVE-NEW
      package: zlib
      image: java21-distroless
      release: v2.0.0
      status: false_positive
      reason: scanner_false_positive
      owner: platform-security
      createdAt: "2026-02-01"
      expiresAt: "2099-01-01"
      notes: scanner signature does not match reachable package metadata
`), 0o644); err != nil {
		t.Fatalf("write exceptions: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "openvex.json")
	stdout, err := runCLI(t,
		"--catalog", dir,
		"vex", "java21-distroless",
		"--tag", "v2.0.0",
		"--exceptions", exceptionsPath,
		"--output", outputPath,
	)
	if err != nil {
		t.Fatalf("vex with exceptions failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Successfully generated OpenVEX compliance document") {
		t.Fatalf("expected output-file success message, got:\n%s", stdout)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read vex output: %v", err)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vex output: %v\n%s", err, raw)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected one statement, got %d: %+v", len(doc.Statements), doc.Statements)
	}
	stmt := doc.Statements[0]
	if stmt.Status != vexNotAffected || stmt.Justification != "vulnerable_code_not_present" {
		t.Fatalf("exception did not map to not_affected false-positive VEX statement: %+v", stmt)
	}
	if !strings.Contains(stmt.ImpactStatement, "scanner signature") {
		t.Fatalf("expected exception notes to become impact statement, got: %+v", stmt)
	}

	stdout, err = runCLI(t,
		"--catalog", dir,
		"--format", "yaml",
		"vex", "java21-distroless",
		"--tag", "v2.0.0",
	)
	if err != nil {
		t.Fatalf("vex yaml failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "status: affected") || !strings.Contains(stdout, "CVE-NEW") {
		t.Fatalf("expected YAML VEX output for eligible finding, got:\n%s", stdout)
	}
}

func TestVexRemediationStatusBranches(t *testing.T) {
	dir := writeVexBranchCatalog(t)
	stdout, err := runCLI(t, "--catalog", dir, "vex", "vex-runtime", "--tag", "v3.0.0")
	if err != nil {
		t.Fatalf("vex failed: %v\n%s", err, stdout)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parse vex output: %v\n%s", err, stdout)
	}
	byCVE := map[string]OpenVEXStatement{}
	for _, stmt := range doc.Statements {
		byCVE[stmt.Vulnerability.Name] = stmt
	}

	cases := map[string]struct {
		status        string
		justification string
		impact        string
	}{
		"CVE-2026-1000": {status: vexAffected, impact: "accepted risk"},
		"CVE-2026-1001": {status: vexUnderInvestigation, impact: "no fixed version"},
		"CVE-2026-1002": {status: vexNotAffected, justification: "vulnerable_code_not_present", impact: "scanner-only package"},
		"CVE-2026-1003": {status: vexUnderInvestigation, impact: "Finding is active and under platform triage."},
		"CVE-2026-1004": {status: vexUnderInvestigation, impact: "deferred because the finding is inherited from the base layer"},
		"CVE-2026-1005": {status: vexUnderInvestigation, impact: "below the release-blocking severity threshold"},
	}
	for id, want := range cases {
		stmt, ok := byCVE[id]
		if !ok {
			t.Fatalf("missing VEX statement for %s in %+v", id, byCVE)
		}
		if stmt.Status != want.status || stmt.Justification != want.justification {
			t.Fatalf("%s mapped incorrectly: got status=%q justification=%q, want status=%q justification=%q",
				id, stmt.Status, stmt.Justification, want.status, want.justification)
		}
		if want.impact != "" && !strings.Contains(stmt.ImpactStatement, want.impact) {
			t.Fatalf("%s impact statement = %q, want it to contain %q", id, stmt.ImpactStatement, want.impact)
		}
	}
}

func TestVexAcceptedRiskNeverMapsToNotAffected(t *testing.T) {
	exceptionStatus := vexStatusFromException("accepted_risk")
	if exceptionStatus == vexNotAffected {
		t.Fatal("accepted_risk exception status must not emit an OpenVEX not_affected claim")
	}

	dir := writeVexBranchCatalog(t)
	stdout, err := runCLI(t, "--catalog", dir, "vex", "vex-runtime", "--tag", "v3.0.0")
	if err != nil {
		t.Fatalf("vex failed: %v\n%s", err, stdout)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parse vex output: %v\n%s", err, stdout)
	}
	for _, stmt := range doc.Statements {
		if stmt.Vulnerability.Name == "CVE-2026-1000" && stmt.Status == vexNotAffected {
			t.Fatalf("accepted-risk remediation produced not_affected VEX statement: %+v", stmt)
		}
	}
}

func TestVexNotAffectedRequiresProofBackedReason(t *testing.T) {
	dir := writeCommandSmokeCatalog(t)
	exceptionsPath := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(exceptionsPath, []byte(`apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: app-team-triage
spec:
  exceptions:
    - id: CVE-NEW
      package: zlib
      image: java21-distroless
      release: v2.0.0
      status: not_affected
      reason: temporary_business_exception
      owner: platform-security
      createdAt: "2026-02-01"
      expiresAt: "2099-01-01"
      notes: waiver without reachability proof
`), 0o644); err != nil {
		t.Fatalf("write exceptions: %v", err)
	}

	stdout, err := runCLI(t,
		"--catalog", dir,
		"vex", "java21-distroless",
		"--tag", "v2.0.0",
		"--exceptions", exceptionsPath,
	)
	if err != nil {
		t.Fatalf("vex with exceptions failed: %v\n%s", err, stdout)
	}
	var doc OpenVEXDocument
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parse vex output: %v\n%s", err, stdout)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected one statement, got %d: %+v", len(doc.Statements), doc.Statements)
	}
	if doc.Statements[0].Status != vexUnderInvestigation {
		t.Fatalf("not_affected exception without proof-backed reason must remain under investigation: %+v", doc.Statements[0])
	}
}

func TestVexJustificationFromReason(t *testing.T) {
	cases := map[string]string{
		"scanner_false_positive":       "vulnerable_code_not_present",
		"vulnerable_code_not_present":  "vulnerable_code_not_present",
		"inherited_from_base":          "vulnerable_code_not_in_execute_path",
		"vulnerable_code_not_executed": "vulnerable_code_not_in_execute_path",
		"temporary_business_exception": "vulnerable_code_cannot_be_controlled_by_adversary",
	}
	for reason, want := range cases {
		if got := vexJustificationFromReason(reason); got != want {
			t.Fatalf("vexJustificationFromReason(%q) = %q, want %q", reason, got, want)
		}
	}
}

func writeVexBranchCatalog(t *testing.T) string {
	t.Helper()
	dir := writeCommandSmokeCatalog(t)
	rec, err := catalog.LoadImageRecord(dir, "java21-distroless")
	if err != nil {
		t.Fatalf("load smoke record: %v", err)
	}
	rec.ID = "vex-runtime"
	rec.Releases = []catalog.ReleaseEntry{{
		Tag:      "v3.0.0",
		IsLatest: true,
		Architectures: []catalog.ArchPayload{
			archPayload("amd64", "sha256:vex-amd64", 16*1024*1024, 1, []catalog.PackageEntry{
				pkg("openssl", "3.0.0"),
				pkg("curl", "8.0.0"),
			}, []catalog.FindingInfo{
				vexFinding("CVE-2026-1000", "openssl", &catalog.RemediationInfo{
					Status:  "deferred",
					Reason:  "accepted_risk",
					Summary: "accepted risk while upstream advisory is disputed",
				}),
				vexFinding("CVE-2026-1001", "curl", &catalog.RemediationInfo{
					Status:  "deferred",
					Reason:  "no_fixed_version",
					Summary: "no fixed version has been published",
				}),
				vexFinding("CVE-2026-1002", "openssl", &catalog.RemediationInfo{
					Status:  "ignored",
					Reason:  "scanner_false_positive",
					Summary: "scanner-only package marker is not present",
				}),
				vexFinding("CVE-2026-1003", "curl", nil),
				vexFinding("CVE-2026-1004", "curl", &catalog.RemediationInfo{
					Status:  "deferred",
					Reason:  "base_layer",
					Summary: "deferred because the finding is inherited from the base layer",
				}),
				vexFinding("CVE-2026-1005", "curl", &catalog.RemediationInfo{
					Status:  "deferred",
					Reason:  "below_priority_threshold",
					Summary: "below the release-blocking severity threshold",
				}),
			}, "passed"),
		},
		Lifecycle:       rec.Lifecycle,
		RuntimeContract: rec.RuntimeContract,
	}}
	writeCatalogJSON(t, filepath.Join(dir, "images", "vex-runtime.json"), rec)
	return dir
}

func vexFinding(id, packageName string, remediation *catalog.RemediationInfo) catalog.FindingInfo {
	f := finding(id, "High", packageName)
	f.Remediation = remediation
	return f
}
