package estateverify

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// requirable are the evidence kinds a policy can require.
var requirable = []string{KindSignature, KindSBOM, KindVulnerabilityScan, KindProvenance, KindRecipe, KindTests}

// setEvidence sets one kind's status.
func setEvidence(e *report.Evidence, kind, status string) {
	item := report.EvidenceItem{Status: status}
	switch kind {
	case KindSignature:
		e.Signature = item
	case KindSBOM:
		e.SBOM = item
	case KindVulnerabilityScan:
		e.VulnerabilityScan = item
	case KindProvenance:
		e.Provenance = item
	case KindRecipe:
		e.Recipe = item
	case KindRebase:
		e.Rebase = item
	case KindTests:
		e.Tests = item
	}
}

// allVerified is an image whose every kind of evidence verified, built
// (its rebase record doesn't apply).
func allVerified() report.Image {
	var e report.Evidence
	for _, k := range Kinds {
		setEvidence(&e, k, "verified")
	}
	e.Rebase = report.EvidenceItem{Status: "not-applicable"}
	return report.Image{Evidence: e, Root: "a root", Vulnerabilities: &report.Vulnerabilities{Findings: []report.Finding{}}}
}

// TestOnlyVerifiedEvidenceMeetsARequirement holds the verdict to its one
// invariant across every requirable kind: a requirement is met by verified
// evidence, and by nothing else a trusted signer didn't vouch for.
func TestOnlyVerifiedEvidenceMeetsARequirement(t *testing.T) {
	p := report.Policy{Required: requirable, TrustedSigners: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}}
	if v := verdict(allVerified(), p); v.Status != "verified" {
		t.Fatalf("control: every kind verified: %+v", v)
	}
	for _, kind := range requirable {
		for _, status := range []string{"failed", "present", "unknown", "missing", "not-applicable", "", "trusted-by-someone"} {
			img := allVerified()
			setEvidence(&img.Evidence, kind, status)
			v := verdict(img, p)
			if v.Status == "verified" {
				t.Errorf("required %s %q passed: %+v", kind, status, v)
			}
			if len(v.Reasons) == 0 || !strings.Contains(strings.Join(v.Reasons, ";"), kind) {
				t.Errorf("required %s %q: the reasons don't name it: %+v", kind, status, v)
			}
		}
	}
}

// TestRecipeNotApplicableNeedsAVerifiedRebaseRecord: a rebased image needs
// no recipe of its own, but only a rebase record a trusted signer verified
// shows it was rebased.
func TestRecipeNotApplicableNeedsAVerifiedRebaseRecord(t *testing.T) {
	p := report.Policy{Required: []string{KindSignature, KindRecipe}, TrustedSigners: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}}
	for _, tc := range []struct {
		rebase, recipe, want string
	}{
		{"verified", "not-applicable", "verified"},
		{"failed", "not-applicable", "unverified"},
		{"present", "not-applicable", "unverified"},
		{"unknown", "not-applicable", "unverified"},
		{"missing", "not-applicable", "unverified"},
		{"not-applicable", "not-applicable", "unverified"},
		// A recipe missing beside a record nobody vouched for: undecided
		// when nobody could check the record, failed when it failed.
		{"present", "missing", "unverified"},
		{"unknown", "missing", "unverified"},
		{"failed", "missing", "failed"},
		{"verified", "missing", "failed"},
		{"not-applicable", "missing", "failed"},
	} {
		img := allVerified()
		setEvidence(&img.Evidence, KindRebase, tc.rebase)
		setEvidence(&img.Evidence, KindRecipe, tc.recipe)
		if v := verdict(img, p); v.Status != tc.want {
			t.Errorf("rebase %s, recipe %s: verdict %+v, want %s", tc.rebase, tc.recipe, v, tc.want)
		}
	}
}

// TestUntrustedRebaseRecordDoesNotExcuseTheRecipe runs the whole pipeline: an
// image with no recipe and a rebase record that a trusted signer verified,
// that someone else signed, or that a trusted reusable workflow signed for a
// caller nobody constrained. Only the first is rebased as far as the report
// can tell.
func TestUntrustedRebaseRecordDoesNotExcuseTheRecipe(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	original := pushIndex(t, host+"/original:1", nil, built, nil)
	originalRef := host + "/original@" + descriptorOf(t, original).Digest.String()

	for _, tc := range []struct {
		name, cert             string
		rebase, recipe, wanted string
	}{
		{"trusted", ours, "verified", "not-applicable", "verified"},
		{"someone-else", fulcioCert(t, evilSigner, ghIssuer), "failed", "missing", "failed"},
		{"unconstrained-caller", fulcioCertFrom(t, ourSigner, ghIssuer, "https://github.com/mallory/app"), "present", "missing", "unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := pushIndex(t, host+"/"+tc.name+":1", nil, built, nil)
			desc := descriptorOf(t, img)
			d := desc.Digest.String()
			attach(t, host+"/"+tc.name, desc, bundleJSON(t, PredicateCosignSign, d, map[string]any{}, ours))
			attach(t, host+"/"+tc.name, desc, bundleJSON(t, PredicateRebase, d,
				map[string]any{"factory": map[string]string{"version": "v0.3.0"}, "image": originalRef}, tc.cert))

			verifier := acmeVerifier()
			r, err := Build(context.Background(), observe(t, host, tc.name+":1"), Options{
				Name: "adversarial", Version: "test", GeneratedAt: "2026-10-18T00:00:00Z", Verifier: verifier,
				Policy: report.Policy{Required: []string{KindSignature, KindRecipe}, TrustedSigners: verifier.Signers},
			})
			if err != nil {
				t.Fatal(err)
			}
			got := r.Images[0]
			if got.Evidence.Rebase.Status != tc.rebase || got.Evidence.Recipe.Status != tc.recipe {
				t.Fatalf("rebase %+v recipe %+v, want %s and %s", got.Evidence.Rebase, got.Evidence.Recipe, tc.rebase, tc.recipe)
			}
			if got.Verdict.Status != tc.wanted {
				t.Errorf("verdict %+v, want %s", got.Verdict, tc.wanted)
			}
			if tc.recipe == "missing" && !strings.Contains(got.Evidence.Recipe.Detail, "doesn't stand in") {
				t.Errorf("recipe detail doesn't say why the record doesn't count: %q", got.Evidence.Recipe.Detail)
			}
			validateReport(t, r)
		})
	}
}

// trivyPredicate is Trivy's cosign-vuln output (trivy image --format
// cosign-vuln): the cosign vuln/v1 predicate around Trivy's own report,
// which has no grype matches list. Its one finding is critical.
func trivyPredicate(uri string) map[string]any {
	return map[string]any{
		"invocation": map[string]any{"parameters": nil, "uri": "", "event_id": "", "builder.id": ""},
		"scanner": map[string]any{
			"uri": uri, "version": "0.67.2", "db": map[string]string{"uri": "", "version": ""},
			"result": map[string]any{
				"SchemaVersion": 2, "ArtifactName": "ghcr.io/acme/app:1", "ArtifactType": "container_image",
				"Results": []any{map[string]any{
					"Target": "ghcr.io/acme/app:1 (wolfi 20230201)", "Class": "os-pkgs", "Type": "wolfi",
					"Vulnerabilities": []any{map[string]any{"VulnerabilityID": "CVE-2026-1234", "PkgName": "openssl",
						"InstalledVersion": "3.0.1", "FixedVersion": "3.0.2", "Severity": "CRITICAL"}},
				}},
			},
		},
		"metadata": map[string]string{"scanStartedOn": "2026-10-17T00:00:00Z", "scanFinishedOn": "2026-10-17T00:00:10Z"},
	}
}

// TestOnlyGrypeOutputIsRead: a scan is read only when it says it is grype's
// and has grype's matches list; anything else is unreadable, never clean.
func TestOnlyGrypeOutputIsRead(t *testing.T) {
	grype := vulnPredicate(nil, nil)
	noURI := vulnPredicate(nil, nil)
	noURI["scanner"].(map[string]any)["uri"] = ""
	byURIOnly := vulnPredicate(nil, nil)
	delete(byURIOnly["scanner"].(map[string]any)["result"].(map[string]any), "descriptor")
	disguised := vulnPredicate(nil, nil)
	disguised["scanner"].(map[string]any)["uri"] = "pkg:github/aquasecurity/trivy@0.67.2"
	noMatches := vulnPredicate(nil, nil)
	delete(noMatches["scanner"].(map[string]any)["result"].(map[string]any), "matches")
	nullMatches := vulnPredicate(nil, nil)
	nullMatches["scanner"].(map[string]any)["result"].(map[string]any)["matches"] = nil
	anonymous := trivyPredicate("")
	for _, tc := range []struct {
		name string
		pred any
		want string // "" reads it
	}{
		{"grype", grype, ""},
		{"grype, descriptor only", noURI, ""},
		{"grype, URI only", byURIOnly, ""},
		{"trivy", trivyPredicate("pkg:github/aquasecurity/trivy@0.67.2"), "aquasecurity/trivy"},
		{"trivy, unnamed", anonymous, "doesn't name its scanner"},
		{"grype's shape, trivy's URI", disguised, "trivy"},
		{"no matches list", noMatches, "no list of matches"},
		{"null matches", nullMatches, "no list of matches"},
		{"no result", map[string]any{"scanner": map[string]any{"uri": "pkg:github/anchore/grype@0.1.0"}}, "no scanner result"},
		{"result not an object", map[string]any{"scanner": map[string]any{"uri": "pkg:github/anchore/grype@0.1.0", "result": "[]"}}, "isn't grype's"},
		{"not a predicate", []any{1}, "isn't a cosign vulnerability predicate"},
	} {
		raw, _ := json.Marshal(tc.pred)
		s, err := readVulnPredicate(raw)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unread: %v", tc.name, err)
		case tc.want == "" && !strings.HasPrefix(s.Scanner, "grype"):
			t.Errorf("%s: scanner %q", tc.name, s.Scanner)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %+v, %v; want an error naming %q", tc.name, s, err, tc.want)
		}
	}
}

// TestTrivyScanIsNotACleanScan runs a verified Trivy vulnerability
// attestation through the whole pipeline: its critical finding must not
// vanish into a clean scan that passes failOn.
func TestTrivyScanIsNotACleanScan(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	img := pushIndex(t, host+"/app:1", nil, built, nil)
	desc := descriptorOf(t, img)
	attach(t, host+"/app", desc, bundleJSON(t, PredicateCosignSign, desc.Digest.String(), map[string]any{}, ours))
	im, _ := img.IndexManifest()
	for _, d := range im.Manifests {
		attach(t, host+"/app", d, bundleJSON(t, PredicateVuln, d.Digest.String(), trivyPredicate("pkg:github/aquasecurity/trivy@0.67.2"), ours))
	}
	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "app:1"), Options{
		Name: "trivy", Version: "test", GeneratedAt: "2026-10-18T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{Required: []string{KindSignature, KindVulnerabilityScan}, TrustedSigners: verifier.Signers, FailOn: "critical", MaxScanAgeDays: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := r.Images[0]
	if a.Evidence.VulnerabilityScan.Status != "verified" || !strings.Contains(a.Evidence.VulnerabilityScan.Detail, "only grype's is read") {
		t.Errorf("scan evidence: %+v", a.Evidence.VulnerabilityScan)
	}
	if a.Vulnerabilities != nil {
		t.Errorf("a Trivy report read as grype's: %+v", a.Vulnerabilities)
	}
	if a.Verdict.Status != "unverified" || !strings.Contains(strings.Join(a.Verdict.Reasons, ";"), "vulnerabilities are unknown") {
		t.Errorf("verdict %+v", a.Verdict)
	}
	if !strings.Contains(strings.Join(a.Warnings, ";"), "couldn't be read") {
		t.Errorf("warnings %v", a.Warnings)
	}
	if r.Summary.Vulnerabilities.NotScanned != 1 || r.Summary.Vulnerabilities.Scanned != 0 {
		t.Errorf("summary %+v", r.Summary.Vulnerabilities)
	}
	validateReport(t, r)
}
