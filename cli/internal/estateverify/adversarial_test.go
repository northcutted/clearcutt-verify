package estateverify

import (
	"context"
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
