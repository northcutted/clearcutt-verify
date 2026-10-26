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

	"github.com/northcutted/clearcutt-verify/internal/estategraph"

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

// trivyResult is the Trivy report inside trivyPredicate, to change.
func trivyResult(p map[string]any) map[string]any {
	return p["scanner"].(map[string]any)["result"].(map[string]any)
}

// TestOnlyGrypeAndTrivyOutputIsRead: a scan is read only when it says it is
// grype's and has grype's matches list, or says it is Trivy's and is Trivy's
// report (schema version 2, with its results); anything else is unreadable,
// never clean.
func TestOnlyGrypeAndTrivyOutputIsRead(t *testing.T) {
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
	const trivyURI = "pkg:github/aquasecurity/trivy@v0.67.2"
	trivyClean := trivyPredicate(trivyURI)
	trivyResult(trivyClean)["Results"] = []any{map[string]any{"Target": "app (wolfi 20230201)", "Class": "os-pkgs", "Type": "wolfi"}}
	trivyNothingScanned := trivyPredicate(trivyURI)
	delete(trivyResult(trivyNothingScanned), "Results")
	trivyNullResults := trivyPredicate(trivyURI)
	trivyResult(trivyNullResults)["Results"] = nil
	trivyOldSchema := trivyPredicate(trivyURI)
	trivyResult(trivyOldSchema)["SchemaVersion"] = 1
	trivyNoSchema := trivyPredicate(trivyURI)
	delete(trivyResult(trivyNoSchema), "SchemaVersion")
	trivyNoID := trivyPredicate(trivyURI)
	trivyResult(trivyNoID)["Results"].([]any)[0].(map[string]any)["Vulnerabilities"].([]any)[0].(map[string]any)["VulnerabilityID"] = ""
	trivyNotAnObject := trivyPredicate(trivyURI)
	trivyNotAnObject["scanner"].(map[string]any)["result"] = []any{}
	for _, tc := range []struct {
		name string
		pred any
		want string // "" reads it
		// scanner and matches are what a read scan says.
		scanner string
		matches int
	}{
		{"grype", grype, "", "grype 0.118.0", 0},
		{"grype, descriptor only", noURI, "", "grype 0.118.0", 0},
		{"grype, URI only", byURIOnly, "", "grype 0.118.0", 0},
		{"trivy", trivyPredicate(trivyURI), "", "trivy 0.67.2", 1},
		{"trivy, nothing found", trivyClean, "", "trivy 0.67.2", 0},
		{"trivy, nothing scanned", trivyNothingScanned, "lists no results", "", 0},
		{"trivy, null results", trivyNullResults, "lists no results", "", 0},
		{"trivy, schema 1", trivyOldSchema, "schema version 2 (SchemaVersion 1)", "", 0},
		{"trivy, no schema", trivyNoSchema, "SchemaVersion absent", "", 0},
		{"trivy, finding without an ID", trivyNoID, "without a vulnerability ID", "", 0},
		{"trivy, result not an object", trivyNotAnObject, "isn't Trivy's JSON report", "", 0},
		{"trivy, unnamed", anonymous, "doesn't name its scanner", "", 0},
		{"grype's shape, trivy's URI", disguised, "isn't Trivy's report of schema version 2", "", 0},
		{"another scanner", map[string]any{"scanner": map[string]any{"uri": "pkg:github/acme/scanner@1.0", "result": map[string]any{"matches": []any{}}}}, "acme/scanner", "", 0},
		{"no matches list", noMatches, "no list of matches", "", 0},
		{"null matches", nullMatches, "no list of matches", "", 0},
		{"no result", map[string]any{"scanner": map[string]any{"uri": "pkg:github/anchore/grype@0.1.0"}}, "no scanner result", "", 0},
		{"result not an object", map[string]any{"scanner": map[string]any{"uri": "pkg:github/anchore/grype@0.1.0", "result": "[]"}}, "isn't grype's", "", 0},
		{"not a predicate", []any{1}, "isn't a cosign vulnerability predicate", "", 0},
	} {
		raw, _ := json.Marshal(tc.pred)
		s, err := readVulnPredicate(raw)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unread: %v", tc.name, err)
		case tc.want == "" && (s.Scanner != tc.scanner || len(s.Result.Matches) != tc.matches):
			t.Errorf("%s: scanner %q with %d matches, want %q with %d", tc.name, s.Scanner, len(s.Result.Matches), tc.scanner, tc.matches)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %+v, %v; want an error naming %q", tc.name, s, err, tc.want)
		}
	}
}

// TestVerifiedTrivyScanIsRead runs a verified Trivy vulnerability
// attestation through the whole pipeline: its critical finding is counted
// and fails failOn, like a grype scan's. A Trivy scan no trusted signer
// signed is never read, so its clean findings never pass an image.
func TestVerifiedTrivyScanIsRead(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours, evil := fulcioCert(t, ourSigner, ghIssuer), fulcioCert(t, evilSigner, ghIssuer)
	clean := trivyPredicate("pkg:github/aquasecurity/trivy@v0.67.2")
	trivyResult(clean)["Results"] = []any{map[string]any{"Target": "app", "Class": "os-pkgs", "Type": "wolfi"}}
	for name, signer := range map[string]string{"app": ours, "other": evil} {
		img := pushIndex(t, host+"/"+name+":1", nil, built, nil)
		desc := descriptorOf(t, img)
		attach(t, host+"/"+name, desc, bundleJSON(t, PredicateCosignSign, desc.Digest.String(), map[string]any{}, ours))
		im, _ := img.IndexManifest()
		for _, d := range im.Manifests {
			pred := trivyPredicate("pkg:github/aquasecurity/trivy@v0.67.2")
			if name == "other" {
				pred = clean
			}
			attach(t, host+"/"+name, d, bundleJSON(t, PredicateVuln, d.Digest.String(), pred, signer))
		}
	}
	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "app:1", "other:1"), Options{
		Name: "trivy", Version: "test", GeneratedAt: "2026-10-18T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{Required: []string{KindSignature, KindVulnerabilityScan}, TrustedSigners: verifier.Signers, FailOn: "critical", MaxScanAgeDays: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}
	a := img["app"]
	if a.Evidence.VulnerabilityScan.Status != "verified" || strings.Contains(a.Evidence.VulnerabilityScan.Detail, "weren't read") {
		t.Errorf("scan evidence: %+v", a.Evidence.VulnerabilityScan)
	}
	v := a.Vulnerabilities
	if v == nil || v.Scanner != "trivy 0.67.2" || v.Counts.Critical != 1 || v.Fixable.Critical != 1 || v.ScannedAt != "2026-10-17T00:00:10Z" ||
		len(v.Findings) != 1 || v.Findings[0].ID != "CVE-2026-1234" || strings.Join(v.Findings[0].FixedIn, ",") != "3.0.2" || len(v.Findings[0].Platforms) != 2 {
		t.Fatalf("the verified Trivy scan's findings: %+v", v)
	}
	if a.Verdict.Status != "failed" || !strings.Contains(strings.Join(a.Verdict.Reasons, ";"), "1 vulnerabilities at critical") {
		t.Errorf("verdict %+v", a.Verdict)
	}
	o := img["other"]
	if o.Evidence.VulnerabilityScan.Status == "verified" || o.Vulnerabilities != nil || o.Verdict.Status == "verified" {
		t.Errorf("a clean Trivy scan no trusted signer signed was read: %+v %+v %+v", o.Evidence.VulnerabilityScan, o.Vulnerabilities, o.Verdict)
	}
	if r.Summary.Vulnerabilities.Scanned != 1 || r.Summary.Vulnerabilities.NotScanned != 1 || r.Summary.Vulnerabilities.Counts.Critical != 1 {
		t.Errorf("summary %+v", r.Summary.Vulnerabilities)
	}
}

// maxDaysBehind fails an image only on drift from a base proven by layer
// digests: drift from a claimed base leaves it unverified at worst, never
// failed.
func TestStalenessFromClaimsNeverFails(t *testing.T) {
	p := report.Policy{TrustedSigners: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}, MaxDaysBehind: 30}
	for _, tc := range []struct {
		strength, method, drift string
		days                    int
		want                    string
	}{
		{"proof", "layer-prefix", "stale", 45, "failed"},
		{"proof", "layer-prefix", "stale", 10, "verified"},
		{"declared", "oci-base-digest", "stale", 45, "unverified"},
		{"declared", "buildpacks-metadata", "stale", 45, "unverified"},
		{"assisted", "oci-base-name", "unknown", 0, "unverified"},
		{"weak", "history", "unknown", 0, "unverified"},
		{"declared", "oci-base-digest", "stale", 10, "verified"},
	} {
		img := allVerified()
		img.Base = &report.BaseLink{Repository: "r", Strength: tc.strength, Method: tc.method, Drift: tc.drift, DaysBehind: tc.days}
		if got := verdictAt(img, p, built); got.Status != tc.want {
			t.Errorf("%s base %d days behind (%s): %+v, want %s", tc.strength, tc.days, tc.drift, got, tc.want)
		}
	}
}

// A base named only by repository (base.name, a history line) identifies no
// version, so the edge has no digest. Linking it must not resolve the empty
// digest to an image that couldn't be read (which has no digest either).
func TestNamedBaseIsNotLinkedToAnUnreadableImage(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	pushIndex(t, host+"/base:latest", nil, built, nil)
	pushIndex(t, host+"/app:1", nil, built, nil)
	observations := observe(t, host, "base:latest", "app:1")
	for i := range observations.Images {
		if observations.Images[i].ID == "app" {
			observations.Images[i].Labels["org.opencontainers.image.base.name"] = host + "/base:latest"
		}
	}
	// Unreadable images in either position: the bug kept the last one.
	broken := func(id string) estategraph.Observation {
		return estategraph.Observation{ID: id, SourceRef: host + "/" + id + ":1", Platforms: []string{}, Entrypoint: []string{}, Cmd: []string{},
			Labels: map[string]string{}, Annotations: map[string]string{}, Layers: []estategraph.LayerObservation{},
			History: []estategraph.HistoryObservation{}, Warnings: []string{"the image couldn't be read"}}
	}
	observations.Images = append([]estategraph.Observation{broken("broken-a")}, append(observations.Images, broken("broken-z"))...)

	verifier := acmeVerifier()
	r, err := Build(context.Background(), observations, Options{
		Name: "named-base", Version: "test", GeneratedAt: "2026-10-26T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{TrustedSigners: verifier.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range r.Images {
		if img.ID != "app" {
			continue
		}
		if img.Base == nil || img.Base.Method != estategraph.MethodOCIBaseName || img.Base.Digest != "" {
			t.Fatalf("app base: %+v", img.Base)
		}
		if img.Base.ImageID != "" {
			t.Errorf("a base named by repository was linked to image %q", img.Base.ImageID)
		}
	}
	validateReport(t, r)
}

// --reproduce never skips an image because its recipe or rebase record
// couldn't be read: whether it reproduces is unknown, so it is unverified.
func TestReproduceDoesNotSkipAnUnknownRecipe(t *testing.T) {
	p := report.Policy{TrustedSigners: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}, Reproduce: true}
	img := allVerified()
	img.Evidence.Recipe = report.EvidenceItem{Status: "unknown"}
	img.Reproducibility = reproduce(context.Background(), &img, imageData{}, Options{Policy: p})
	if img.Reproducibility.Status != "not-checked" {
		t.Fatalf("reproducibility: %+v", img.Reproducibility)
	}
	if got := verdictAt(img, report.Policy{TrustedSigners: p.TrustedSigners, Reproduce: true}, built); got.Status != "unverified" ||
		!strings.Contains(strings.Join(got.Reasons, ";"), "reproducibility couldn't be checked") {
		t.Errorf("verdict: %+v", got)
	}
	// No recipe at all is nothing to rebuild.
	img = allVerified()
	img.Evidence.Recipe, img.Evidence.Rebase = report.EvidenceItem{Status: "missing"}, report.EvidenceItem{Status: "not-applicable"}
	img.Reproducibility = reproduce(context.Background(), &img, imageData{}, Options{Policy: p})
	if got := verdictAt(img, report.Policy{TrustedSigners: p.TrustedSigners, Reproduce: true}, built); img.Reproducibility.Status != "no-recipe" || got.Status != "verified" {
		t.Errorf("no recipe: %+v %+v", img.Reproducibility, got)
	}
}
