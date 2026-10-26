package estateverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// Later than bundleJSON's transparency log time: what an attacker attaching
// a copy afterwards would claim.
const later = 1791300000

func vulnPredicateAt(finished string, matches ...map[string]any) map[string]any {
	if matches == nil {
		matches = []map[string]any{} // grype lists no matches as []
	}
	return map[string]any{
		"scanner":  map[string]any{"uri": "pkg:github/anchore/grype@0.118.0", "version": "0.118.0", "result": map[string]any{"matches": matches, "descriptor": map[string]string{"name": "grype", "version": "0.118.0"}}},
		"metadata": map[string]string{"scanFinishedOn": finished},
	}
}

func provenancePredicate(repo, commit string) map[string]any {
	return map[string]any{"buildDefinition": map[string]any{
		"externalParameters":   map[string]any{"workflow": map[string]string{"repository": repo}},
		"resolvedDependencies": []any{map[string]any{"uri": "git+" + repo + "@refs/heads/main", "digest": map[string]string{"gitCommit": commit}}},
	}}
}

func sbomPredicate(pkgs ...string) map[string]any {
	var components []any
	for _, p := range pkgs {
		components = append(components, map[string]string{"type": "library", "name": p, "version": "1", "purl": "pkg:apk/wolfi/" + p + "@1"})
	}
	return map[string]any{"bomFormat": "CycloneDX", "components": components}
}

// TestOnlyVerifiedEvidenceIsRead: anyone who can push to a repository can
// attach more evidence to its images. A copy cosign didn't verify (forged,
// signed by someone else, or simply newer) must never replace what a trusted
// signer attested, in what the report shows or what the policy decides.
func TestOnlyVerifiedEvidenceIsRead(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours, evil := fulcioCert(t, ourSigner, ghIssuer), fulcioCert(t, evilSigner, ghIssuer)
	// A certificate claiming another of acme's workflows that no certificate
	// authority issued; and one claiming ours.
	otherAcme := "https://github.com/acme/other/.github/workflows/x.yml@refs/heads/main"
	forgedOther, forgedOurs := fulcioCert(t, otherAcme, ghIssuer), fulcioCert(t, ourSigner, ghIssuer)
	critical := grypeMatchJSON("CVE-2026-1", "Critical", "openssl", "3.0", "3.1")

	var forged []string
	push := func(name string, scans bool) v1.ImageIndex {
		idx := pushIndex(t, host+"/"+name+":1", nil, built, nil)
		d := descriptorOf(t, idx)
		attach(t, host+"/"+name, d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
		attach(t, host+"/"+name, d, bundleJSON(t, "https://slsa.dev/provenance/v1", d.Digest.String(), provenancePredicate("https://github.com/acme/images", "abc123"), ours))
		im, _ := idx.IndexManifest()
		for _, p := range im.Manifests {
			attach(t, host+"/"+name, p, bundleJSON(t, "https://cyclonedx.org/bom", p.Digest.String(), sbomPredicate("openssl"), ours))
			if scans {
				attach(t, host+"/"+name, p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-01T00:00:00Z", critical), ours))
			}
		}
		return idx
	}

	// app carries a trusted scan with a critical finding, and newer copies
	// that say it is clean and fresh.
	app := push("app", true)
	appDesc := descriptorOf(t, app)
	forged = append(forged,
		attach(t, host+"/app", appDesc, bundleAt(t, PredicateCosignSign, appDesc.Digest.String(), map[string]any{}, forgedOther, later)),
		attach(t, host+"/app", appDesc, bundleAt(t, "https://slsa.dev/provenance/v1", appDesc.Digest.String(), provenancePredicate("https://github.com/mallory/evil", "bad"), forgedOurs, later)))
	im, _ := app.IndexManifest()
	for _, p := range im.Manifests {
		forged = append(forged,
			attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), forgedOurs, later)),
			attach(t, host+"/app", p, bundleAt(t, "https://cyclonedx.org/bom", p.Digest.String(), sbomPredicate("nothing-to-see"), forgedOurs, later)))
		attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), evil, later+1))
	}

	// clean's only scans say it is clean, but no trusted signer signed them.
	clean := push("clean", false)
	im, _ = clean.IndexManifest()
	for _, p := range im.Manifests {
		attach(t, host+"/clean", p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), evil))
		forged = append(forged, attach(t, host+"/clean", p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), forgedOurs)))
	}

	verifier := acmeVerifier(forged...)
	// The policy shape docs/verify-estate.md shows: the scan isn't required,
	// failOn is set.
	r, err := Build(context.Background(), observe(t, host, "app:1", "clean:1"), Options{
		Name: "attached", Version: "test", GeneratedAt: "2026-10-10T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{Required: []string{"signature", "sbom", "provenance"}, TrustedSigners: verifier.Signers, FailOn: "critical", MaxScanAgeDays: 7},
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
	if s := a.Evidence.Signature; s.Status != "verified" || s.Signer == nil || s.Signer.Identity != ourSigner || s.Signer.SourceRepository != "https://github.com/acme/images" {
		t.Errorf("app signature names who cosign verified: %+v %+v", s, s.Signer)
	}
	if s := a.Evidence.VulnerabilityScan; s.Status != "verified" || !strings.Contains(s.Detail, "2 other attached copies") {
		t.Errorf("app scan: %+v", s)
	}
	if v := a.Vulnerabilities; v == nil || v.Counts.Critical != 1 || v.ScannedAt != "2026-10-01T00:00:00Z" {
		t.Errorf("app vulnerabilities come from the trusted scan: %+v", v)
	}
	if a.Source == nil || a.Source.URL != "https://github.com/acme/images" || a.Source.Revision != "abc123" {
		t.Errorf("app source from the trusted provenance: %+v", a.Source)
	}
	if a.Packages == nil || *a.Packages != 1 || a.PackagesSource == nil || a.PackagesSource.Status != "verified" {
		t.Errorf("app packages from the trusted SBOM: %v %+v", a.Packages, a.PackagesSource)
	}
	reasons := strings.Join(a.Verdict.Reasons, "; ")
	if a.Verdict.Status != "failed" || !strings.Contains(reasons, "1 vulnerabilities at critical") || !strings.Contains(reasons, "9 days old") {
		t.Errorf("app verdict: %+v", a.Verdict)
	}
	for _, p := range r.Packages {
		if p.Name == "nothing-to-see" {
			t.Errorf("a forged SBOM's package is in the index: %+v", p)
		}
	}

	c := img["clean"]
	if s := c.Evidence.VulnerabilityScan; s.Status == "verified" || c.Vulnerabilities != nil {
		t.Errorf("clean's unverified scans were read: %+v %+v", s, c.Vulnerabilities)
	}
	if c.Verdict.Status != "unverified" || !strings.Contains(strings.Join(c.Verdict.Reasons, "; "), "vulnerabilities are unknown") {
		t.Errorf("clean verdict: an unverified clean scan passed failOn: %+v", c.Verdict)
	}
}

// TestForgedCertificateDoesNotVerifyAReusableWorkflow: a reusable workflow
// signs with its own identity wherever it is called from, so evidence it
// signed in another repository's run is only present. A newer copy with a
// forged certificate saying the run was in the workflow's own repository (or
// saying nothing) must not make it verified.
func TestForgedCertificateDoesNotVerifyAReusableWorkflow(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	idx := pushIndex(t, host+"/checkout:1", nil, built, nil)
	d := descriptorOf(t, idx)
	attach(t, host+"/checkout", d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, fulcioCertFrom(t, reusable, ghIssuer, "https://github.com/mallory/evil")))
	forged := []string{
		attach(t, host+"/checkout", d, bundleAt(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, fulcioCertFrom(t, reusable, ghIssuer, "https://github.com/acme/factory"), later)),
		attach(t, host+"/checkout", d, bundleAt(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, fulcioCertFrom(t, reusable, ghIssuer, ""), later+1)),
	}
	v := acmeVerifier(forged...)
	v.Signers = []report.Signer{{IdentityRegexp: `^https://github\.com/acme/factory/\.github/workflows/images\.yml@`, Issuer: ghIssuer}}
	r, err := Build(context.Background(), observe(t, host, "checkout:1"), Options{
		Name: "reusable", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v,
		Policy: report.Policy{Required: []string{"signature"}, TrustedSigners: v.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := r.Images[0].Evidence.Signature; s.Status == "verified" || r.Images[0].Verdict.Status == "verified" {
		t.Errorf("a forged certificate verified a reusable workflow's signature: %+v, verdict %+v", s, r.Images[0].Verdict)
	}
}

// TestPolicyWithoutTrust: with no trusted signer nothing can be verified,
// so nothing evidence says is read and no image is verified. And a verdict
// rests on evidence a trusted signer vouched for: checks that read none
// (scan age, base drift, reproduction) never verify an image on their own.
func TestPolicyWithoutTrust(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	d := descriptorOf(t, idx)
	attach(t, host+"/app", d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
	attach(t, host+"/app", d, bundleJSON(t, "https://slsa.dev/provenance/v1", d.Digest.String(), provenancePredicate("https://github.com/acme/images", "abc123"), ours))
	im, _ := idx.IndexManifest()
	for _, p := range im.Manifests {
		attach(t, host+"/app", p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-05T00:00:00Z"), ours))
	}
	// bare is unsigned and unscanned, and a root: child is built on it.
	bare := pushIndex(t, host+"/bare:1", nil, built, nil)
	pushIndex(t, host+"/child:1", bare, built, nil)

	build := func(p report.Policy) map[string]report.Image {
		t.Helper()
		v := acmeVerifier()
		v.Signers = p.TrustedSigners
		r, err := Build(context.Background(), observe(t, host, "app:1", "bare:1", "child:1"), Options{Name: "trust", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v, Policy: p})
		if err != nil {
			t.Fatal(err)
		}
		validateReport(t, r)
		out := map[string]report.Image{}
		for _, i := range r.Images {
			out[i.ID] = i
		}
		return out
	}
	a := build(report.Policy{})["app"]
	if a.Evidence.Signature.Status != "present" || a.Evidence.Provenance.Status != "present" || a.Vulnerabilities != nil || (a.Source != nil && a.Source.Basis == "provenance") {
		t.Errorf("evidence nothing verified was read: %+v, vulnerabilities %+v, source %+v", a.Evidence, a.Vulnerabilities, a.Source)
	}
	if a.Verdict.Status != "unverified" || !strings.Contains(a.Verdict.Reasons[0], "no trusted signer") {
		t.Errorf("empty policy verdict: %+v", a.Verdict)
	}

	acme := acmeVerifier().Signers
	for _, p := range []report.Policy{
		{TrustedSigners: acme},
		{TrustedSigners: acme, MaxScanAgeDays: 7},
		{TrustedSigners: acme, MaxDaysBehind: 30},
		{TrustedSigners: acme, Reproduce: true},
	} {
		img := build(p)
		if b := img["bare"]; b.Root == "" || b.Verdict.Status != "unverified" || !strings.Contains(b.Verdict.Reasons[0], "none of its evidence is verified") {
			t.Errorf("%+v: unsigned, unscanned root: root %q, verdict %+v", p, b.Root, b.Verdict)
		}
		// (app's own base is unknown, so maxDaysBehind can't pass it.)
		if a := img["app"]; a.Verdict.Status != "verified" && p.MaxDaysBehind == 0 {
			t.Errorf("%+v: signed, freshly scanned app: %+v", p, a.Verdict)
		}
	}
}

// TestScanAgeIsTheOldestPlatforms: every platform's scan has to be fresh.
func TestScanAgeIsTheOldestPlatforms(t *testing.T) {
	scan := func(at string) vulnScan { return vulnScan{Scanner: "grype", ScannedAt: at} }
	v := mergeVulnerabilities(map[string]vulnScan{"linux/amd64": scan("2026-10-09T00:00:00Z"), "linux/arm64": scan("2026-10-01T00:00:00Z")})
	if v.ScannedAt != "2026-10-01T00:00:00Z" {
		t.Errorf("scannedAt %q, want the older platform's", v.ScannedAt)
	}
	p := report.Policy{MaxScanAgeDays: 7, TrustedSigners: acmeVerifier().Signers}
	if got := verdictAt(report.Image{Vulnerabilities: v, Evidence: report.Evidence{VulnerabilityScan: report.EvidenceItem{Status: "verified"}}}, p, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)); got.Status != "unverified" || !strings.Contains(got.Reasons[0], "9 days old") {
		t.Errorf("verdict: %+v", got)
	}
	// One platform's scan time is unknown, so the image's is.
	if v := mergeVulnerabilities(map[string]vulnScan{"linux/amd64": scan("2026-10-09T00:00:00Z"), "linux/arm64": scan("")}); v.ScannedAt != "" {
		t.Errorf("scannedAt %q with an undated platform scan", v.ScannedAt)
	}
	// Times compare as times, not strings: 01:00+02:00 is 23:00Z the day before.
	if v := mergeVulnerabilities(map[string]vulnScan{"a": scan("2026-10-09T01:00:00+02:00"), "b": scan("2026-10-08T23:30:00Z")}); v.ScannedAt != "2026-10-09T01:00:00+02:00" {
		t.Errorf("scannedAt %q", v.ScannedAt)
	}
}

func TestVerdictFailOnNeedsAVerifiedScan(t *testing.T) {
	p := report.Policy{TrustedSigners: acmeVerifier().Signers, FailOn: "critical"}
	clean := &report.Vulnerabilities{ScannedAt: "2026-10-09T00:00:00Z"}
	for status, want := range map[string]string{"verified": "verified", "present": "unverified", "failed": "unverified", "unknown": "unverified", "missing": "unverified"} {
		img := report.Image{Evidence: report.Evidence{VulnerabilityScan: report.EvidenceItem{Status: status}}, Vulnerabilities: clean}
		if status == "missing" {
			img.Vulnerabilities = nil
		}
		if got := verdict(img, p); got.Status != want {
			t.Errorf("scan %s: %+v, want %s", status, got, want)
		}
	}
	// Findings from the platforms that verified still fail it.
	img := report.Image{Evidence: report.Evidence{VulnerabilityScan: report.EvidenceItem{Status: "failed"}},
		Vulnerabilities: &report.Vulnerabilities{Findings: []report.Finding{{ID: "CVE-1", Severity: "critical"}}}}
	if got := verdict(img, p); got.Status != "failed" {
		t.Errorf("partial findings: %+v", got)
	}
	// A verified scan that couldn't be read is unknown.
	img = report.Image{Evidence: report.Evidence{VulnerabilityScan: report.EvidenceItem{Status: "verified"}}}
	if got := verdict(img, p); got.Status != "unverified" || !strings.Contains(got.Reasons[0], "couldn't be read") {
		t.Errorf("unreadable scan: %+v", got)
	}
}

func TestVerdictStaleBaseOfUnknownAge(t *testing.T) {
	p := report.Policy{TrustedSigners: acmeVerifier().Signers, MaxDaysBehind: 30}
	signed := report.Evidence{Signature: report.EvidenceItem{Status: "verified"}}
	img := report.Image{Evidence: signed, Base: &report.BaseLink{Drift: "stale", DaysBehindUnknown: true}}
	if got := verdict(img, p); got.Status != "unverified" || !strings.Contains(got.Reasons[0], "couldn't be measured") {
		t.Errorf("stale base of unknown age: %+v", got)
	}
	img.Base = &report.BaseLink{Drift: "stale", DaysBehind: 3}
	if got := verdict(img, p); got.Status != "verified" {
		t.Errorf("stale base within the limit: %+v", got)
	}
}

// TestBaseAgeAndRoots builds an estate of reproducible images (creation
// times zeroed), and an image whose annotations name a base it isn't built
// on, which another image is built on.
func TestBaseAgeAndRoots(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	epoch := time.Unix(1, 0)
	annotate := func(base v1.ImageIndex, name string) func(string) map[string]string {
		im, _ := base.IndexManifest()
		return func(arch string) map[string]string {
			for _, d := range im.Manifests {
				if d.Platform.Architecture == arch {
					return map[string]string{"org.opencontainers.image.base.name": name, "org.opencontainers.image.base.digest": d.Digest.String()}
				}
			}
			return nil
		}
	}

	// app is on nix:1; the graph sees nix:2 is newer, but not by how much.
	nix1 := pushIndex(t, host+"/nix:1", nil, epoch, nil)
	nix2 := pushIndex(t, host+"/nix:2", nil, epoch, nil)
	pushIndex(t, host+"/app:1", nix1, epoch, nil)
	// tools names dist:2 as its base at the version it was built on, dist:1,
	// which isn't observed: its claim is checked, and found behind.
	dist1 := pushIndex(t, host+"/dist:1", nil, epoch, nil)
	pushIndex(t, host+"/dist:2", nil, epoch, nil)
	pushIndex(t, host+"/tools:1", dist1, epoch, annotate(dist1, host+"/dist:2"))
	// liar names nix:2 as its base but isn't built on it; svc is built on
	// liar.
	liar := pushIndex(t, host+"/liar:1", nil, built, annotate(nix2, host+"/nix:2"))
	pushIndex(t, host+"/svc:1", liar, built, nil)

	v := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "nix:1", "nix:2", "app:1", "tools:1", "liar:1", "svc:1"), Options{
		Name: "nix", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v, Platforms: []string{"linux/amd64"},
		Policy: report.Policy{TrustedSigners: v.Signers, MaxDaysBehind: 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}
	for _, id := range []string{"app", "tools"} {
		b := img[id].Base
		if b == nil || b.Drift != "stale" || !b.DaysBehindUnknown || b.DaysBehind != 0 {
			t.Errorf("%s base: %+v (unresolved %v)", id, b, img[id].Unresolved)
		}
		if v := img[id].Verdict; v.Status != "unverified" || !strings.Contains(strings.Join(v.Reasons, ";"), "couldn't be measured") {
			t.Errorf("%s verdict: %+v", id, v)
		}
	}
	l := img["liar"]
	if l.Root != "" || l.Base != nil || !strings.Contains(strings.Join(l.Unresolved, ";"), "doesn't start with that image's layers") {
		t.Errorf("liar: root %q base %+v unresolved %v", l.Root, l.Base, l.Unresolved)
	}
	if l.Verdict.Status != "unverified" {
		t.Errorf("liar verdict: %+v", l.Verdict)
	}
	if s := img["svc"]; s.Base == nil || s.Base.ImageID != "liar" {
		t.Errorf("svc base: %+v", s.Base)
	}
	if n := img["nix-2"]; n.Root == "" {
		t.Errorf("nix is a root: %+v", n)
	}
}

// TestNewestVerifiedScanBySignedTime: among scans a trusted signer verified,
// the newest is the one whose signed scan time is latest, not the one the
// registry says was attached last: an old, clean scan of the same image,
// attached again, doesn't replace a newer one that found something.
func TestNewestVerifiedScanBySignedTime(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	im, _ := idx.IndexManifest()
	for _, p := range im.Manifests {
		attach(t, host+"/app", p, bundleJSON(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-08T00:00:00Z", grypeMatchJSON("CVE-2026-2", "High", "zlib", "1.3", "1.3.1")), ours))
		attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-01T00:00:00Z"), ours, later))
	}
	v := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "app:1"), Options{Name: "replay", Version: "test", GeneratedAt: "2026-10-10T00:00:00Z", Verifier: v,
		Policy: report.Policy{Required: []string{"vulnerabilityScan"}, TrustedSigners: v.Signers, FailOn: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	a := r.Images[0]
	if a.Evidence.VulnerabilityScan.Status != "verified" || a.Vulnerabilities == nil || a.Vulnerabilities.Counts.High != 1 || a.Vulnerabilities.ScannedAt != "2026-10-08T00:00:00Z" {
		t.Errorf("scan: %+v, vulnerabilities %+v", a.Evidence.VulnerabilityScan, a.Vulnerabilities)
	}
	if a.Verdict.Status != "failed" {
		t.Errorf("verdict: %+v", a.Verdict)
	}
}

// TestAttachedCopiesCantCrowdOutATrustedOne: copies anyone can attach under
// made-up certificates, newer than the trusted scan and more of them than
// any budget, neither keep the trusted scan from being read nor cost a
// cosign run each unless they hold content a trusted identity signed.
func TestAttachedCopiesCantCrowdOutATrustedOne(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	critical := vulnPredicateAt("2026-10-05T00:00:00Z", grypeMatchJSON("CVE-2026-1", "Critical", "openssl", "3.0", "3.1"))
	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	im, _ := idx.IndexManifest()
	var forged []string
	for _, p := range im.Manifests {
		attach(t, host+"/app", p, bundleJSON(t, PredicateVuln, p.Digest.String(), critical, ours))
		for i := range 10 {
			// Signers no trusted signer accepts, and ones it would (any
			// workflow of acme's) on certificates no authority issued, each
			// saying the image is clean; then copies of the trusted scan
			// itself under forged acceptable certificates.
			stranger := fmt.Sprintf("https://github.com/mallory%d/x/.github/workflows/x.yml@refs/heads/main", i)
			lookalike := fmt.Sprintf("https://github.com/acme/fake%d/.github/workflows/x.yml@refs/heads/main", i)
			replay := fmt.Sprintf("https://github.com/acme/replay%d/.github/workflows/x.yml@refs/heads/main", i)
			at := int64(later + i)
			attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), fulcioCert(t, stranger, ghIssuer), at))
			forged = append(forged,
				attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), vulnPredicateAt("2026-10-09T00:00:00Z"), fulcioCert(t, lookalike, ghIssuer), at)),
				attach(t, host+"/app", p, bundleAt(t, PredicateVuln, p.Digest.String(), critical, fulcioCert(t, replay, ghIssuer), at)))
		}
	}
	v := acmeVerifier(forged...)
	run, calls := v.Run, 0
	v.Run = func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		calls++
		return run(ctx, bin, args...)
	}
	// The docs' policy shape: the scan isn't required, failOn is set.
	r, err := Build(context.Background(), observe(t, host, "app:1"), Options{Name: "crowd", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v,
		Policy: report.Policy{TrustedSigners: v.Signers, FailOn: "critical"}})
	if err != nil {
		t.Fatal(err)
	}
	a := r.Images[0]
	if a.Evidence.VulnerabilityScan.Status != "verified" || a.Vulnerabilities == nil || a.Vulnerabilities.Counts.Critical != 1 {
		t.Errorf("the trusted scan was crowded out: %+v, vulnerabilities %+v", a.Evidence.VulnerabilityScan, a.Vulnerabilities)
	}
	if a.Verdict.Status != "failed" {
		t.Errorf("verdict %+v, want failed (exit 2 under --fail-on failed)", a.Verdict)
	}
	// Per platform: which statements trusted identities signed (1), the
	// trusted scan's signer (1), and the forged signers of its copies (10).
	if calls > 2*12 {
		t.Errorf("%d cosign runs for 2 platforms", calls)
	}
}

// pushKeySignedAttestation attaches an attestation the way cosign v2 did
// with a key: an .att tag holding a DSSE envelope, and no certificate.
func pushKeySignedAttestation(t *testing.T, repo, digest, predicateType string, predicate any) {
	t.Helper()
	st, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": predicateType, "predicate": predicate,
		"subject": []any{map[string]any{"name": repo, "digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}}})
	env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(st), "signatures": []any{}})
	img, err := mutate.Append(mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		mutate.Addendum{Layer: static.NewLayer(env, "application/vnd.dsse.envelope.v1+json"), Annotations: map[string]string{"predicateType": predicateType}})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := name.ParseReference(repo + ":" + strings.Replace(digest, ":", "-", 1) + ".att")
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
}

// TestKeySignedRecipeReproduces: a trust policy's key file is relative to
// the trust policy, and --reproduce rebuilds a key-signed image bound to that
// key, wherever cosign and clearcutt-factory run.
func TestKeySignedRecipeReproduces(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	idx := pushIndex(t, host+"/tools:1", nil, built, nil)
	d := descriptorOf(t, idx)
	pushKeySignedAttestation(t, host+"/tools", d.Digest.String(), PredicateRecipe, imageRecipePredicate(host+"/base:latest", "sha256:"+strings.Repeat("e", 64)))

	dir := t.TempDir()
	for name, body := range map[string]string{
		"keys/acme.pub":      "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
		"policy/trust.yaml":  "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - name: acme-key\n    key: ../keys/acme.pub\n",
		"policy/verify.yaml": "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [recipe]\ntrustPolicy: trust.yaml\n",
	} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Read from elsewhere: the key resolves against the trust policy.
	var p report.Policy
	t.Run("read", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var err error
		if p, err = ReadPolicy(filepath.Join(dir, "policy", "verify.yaml")); err != nil {
			t.Fatal(err)
		}
	})
	key := filepath.Join(dir, "keys", "acme.pub")
	if len(p.TrustedSigners) != 1 || p.TrustedSigners[0].Key != key {
		t.Fatalf("trusted signers %+v, want key %s", p.TrustedSigners, key)
	}
	p.Reproduce = true

	var args []string
	reproducer := FactoryReproducer{Dir: t.TempDir(), Run: func(_ context.Context, _, _ string, a ...string) ([]byte, []byte, error) {
		args = a
		return []byte("reproducible: rebuilt " + d.Digest.String() + " matches\n"), nil, nil
	}}
	v := acmeVerifier()
	v.Signers = p.TrustedSigners
	r, err := Build(context.Background(), observe(t, host, "tools:1"), Options{Name: "keys", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v, Policy: p, Reproducer: reproducer})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	tl := r.Images[0]
	if e := tl.Evidence.Recipe; e.Status != "verified" || e.Signer == nil || e.Signer.Key != key {
		t.Errorf("recipe: %+v %+v", e, e.Signer)
	}
	if tl.Reproducibility.Status != "reproduced" || tl.Verdict.Status != "verified" {
		t.Errorf("reproducibility %+v, verdict %+v", tl.Reproducibility, tl.Verdict)
	}
	if got := strings.Join(args, " "); !strings.Contains(got, "--key "+key) || strings.Contains(got, "certificate") {
		t.Errorf("clearcutt-factory args %q", got)
	}
}

// TestKeyPaths: key files are relative to the file that names them; KMS and
// other cosign URIs, and absolute paths, are left alone.
func TestKeyPaths(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	body := "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [signature]\ntrustedSigners:\n" +
		"  - key: keys/images.pub\n  - key: awskms:///alias/acme\n  - key: pkcs11:token=acme\n  - key: /etc/acme/images.pub\nstackSigners:\n  - key: stacks.pub\n"
	if err := os.WriteFile(policy, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := ReadPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range append(p.TrustedSigners, p.StackSigners...) {
		got = append(got, s.Key)
	}
	want := []string{filepath.Join(dir, "keys/images.pub"), "awskms:///alias/acme", "pkcs11:token=acme", "/etc/acme/images.pub", filepath.Join(dir, "stacks.pub")}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("keys %q, want %q", got, want)
	}
}

// TestReproduceWithKeySigner: a recipe a trusted key verified is rebuilt
// against that key (it was never reproduced: no policy regexp matches a key).
func TestReproduceWithKeySigner(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	img := &report.Image{Repository: "r", Digest: digest, Evidence: report.Evidence{Recipe: report.EvidenceItem{Status: "verified"}, Rebase: report.EvidenceItem{Status: "not-applicable"}}}
	var got report.Signer
	opts := Options{Policy: report.Policy{Reproduce: true, TrustedSigners: []report.Signer{{Key: "/etc/acme/acme.pub"}}},
		Reproducer: reproducerFunc(func(_ context.Context, _ string, s report.Signer) (string, error) {
			got = s
			return digest, nil
		})}
	r := reproduce(context.Background(), img, imageData{recipeVerified: true, recipeSigner: &report.Signer{Key: "/etc/acme/acme.pub"}}, opts)
	if r.Status != "reproduced" || got != (report.Signer{Key: "/etc/acme/acme.pub"}) {
		t.Errorf("reproduced %+v with signer %+v", r, got)
	}
}

// TestKeySignerWithoutTransparencyLog (V8): evidence a key signed without a
// transparency log fails on the log, and says so, unless its trusted signer
// says tlog: false; then it verifies (cosign --insecure-ignore-tlog for that
// key only), the report says the log wasn't checked, and the rebuild is bound
// the same way.
func TestKeySignerWithoutTransparencyLog(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	idx := pushIndex(t, host+"/tools:1", nil, built, nil)
	d := descriptorOf(t, idx)
	pushKeySignedAttestation(t, host+"/tools", d.Digest.String(), PredicateRecipe, imageRecipePredicate(host+"/base:latest", "sha256:"+strings.Repeat("e", 64)))

	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("acme.pub", "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n")
	key := filepath.Join(dir, "acme.pub")
	// cosign, for evidence signed with no transparency log entry.
	var ran [][]string
	verifier := func(signers []report.Signer) *Verifier {
		v := acmeVerifier()
		v.Signers = signers
		v.Run = func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			ran = append(ran, args)
			if contains(args, "--key") && !contains(args, "--insecure-ignore-tlog=true") {
				return nil, errors.New("cosign " + args[0] + ": exit status 1: failed to verify log inclusion: not enough verified log entries from transparency log: 0 < 1")
			}
			return fakeCosign(ctx, nil, args)
		}
		return v
	}
	build := func(p report.Policy, rep Reproducer) report.Image {
		t.Helper()
		r, err := Build(context.Background(), observe(t, host, "tools:1"), Options{Name: "keys", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z",
			Verifier: verifier(p.TrustedSigners), Policy: p, Reproducer: rep})
		if err != nil {
			t.Fatal(err)
		}
		validateReport(t, r)
		return r.Images[0]
	}

	// The key's trusted signer expects a log entry: the log is what failed.
	p, err := ReadPolicy(write("policy.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [recipe]\ntrustedSigners:\n  - key: acme.pub\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := build(p, nil).Evidence.Recipe
	if e.Status != "failed" || !strings.Contains(e.Detail, "transparency log inclusion couldn't be verified") || !strings.Contains(e.Detail, "tlog: false") ||
		strings.Contains(e.Detail, "not signed by a trusted signer") {
		t.Errorf("recipe without a log entry: %+v", e)
	}

	// tlog: false, in a trust policy shared with clearcutt-factory.
	write("trust.yaml", "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - name: offline-key\n    key: acme.pub\n    tlog: false\n")
	p, err = ReadPolicy(write("policy.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [recipe]\ntrustPolicy: trust.yaml\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.TrustedSigners) != 1 || p.TrustedSigners[0].Tlog == nil || *p.TrustedSigners[0].Tlog {
		t.Fatalf("trusted signers %+v", p.TrustedSigners)
	}
	p.Reproduce = true
	var factoryArgs []string
	rep := FactoryReproducer{Dir: t.TempDir(), Run: func(_ context.Context, _, _ string, a ...string) ([]byte, []byte, error) {
		factoryArgs = a
		return []byte("reproducible: rebuilt " + d.Digest.String() + " matches\n"), nil, nil
	}}
	ran = nil
	tl := build(p, rep)
	if e := tl.Evidence.Recipe; e.Status != "verified" || e.Signer == nil || e.Signer.Key != key || e.Signer.Tlog == nil || *e.Signer.Tlog {
		t.Errorf("recipe with tlog: false: %+v %+v", e, e.Signer)
	}
	for _, args := range ran {
		if !contains(args, "--insecure-ignore-tlog=true") {
			t.Errorf("cosign ran without --insecure-ignore-tlog: %q", args)
		}
	}
	if got := strings.Join(factoryArgs, " "); !strings.Contains(got, "--key "+key+" --insecure-ignore-tlog=true") || tl.Reproducibility.Status != "reproduced" {
		t.Errorf("clearcutt-factory args %q, reproducibility %+v", got, tl.Reproducibility)
	}

	// Only key signers can skip the log.
	write("trust.yaml", "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - identity: "+ourSigner+"\n    issuer: "+ghIssuer+"\n    tlog: false\n")
	if _, err := ReadPolicy(write("policy.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\ntrustPolicy: trust.yaml\n")); err == nil || !strings.Contains(err.Error(), "applies to key signers") {
		t.Errorf("keyless tlog: false: %v", err)
	}
	if _, err := ReadPolicy(write("policy.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\ntrustedSigners:\n  - identity: "+ourSigner+"\n    issuer: "+ghIssuer+"\n    tlog: false\n")); err == nil || !strings.Contains(err.Error(), "applies to key signers") {
		t.Errorf("keyless tlog: false in a verification policy: %v", err)
	}
}

// A keyless signature whose log entry doesn't verify fails on the log, not
// on its signer.
func TestKeylessTransparencyLogFailure(t *testing.T) {
	v := &Verifier{Signers: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}},
		Run: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("cosign verify: exit status 1: verifying tlog entry: inclusion proof failed")
		}}
	cert := &report.Signer{Identity: ourSigner, Issuer: ghIssuer, SourceRepository: "https://github.com/acme/images"}
	_, err := v.Verify(context.Background(), Subject{Ref: "r@sha256:x", Kind: KindSignature, Signer: cert})
	if err == nil || !strings.HasPrefix(err.Error(), "its transparency log inclusion couldn't be verified") {
		t.Errorf("keyless log failure: %v", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	item, verified := verifyEvidence(context.Background(), v, "r", digest, KindSignature, "", []Found{{Kind: KindSignature, PredicateType: PredicateCosignSign, Format: FormatBundle, Signer: cert}})
	if len(verified) != 0 || item.Status != "failed" || !strings.HasPrefix(item.Detail, "its transparency log inclusion couldn't be verified") {
		t.Errorf("keyless log failure as evidence: %+v", item)
	}
}

// githubProvenance is SLSA provenance as actions/attest-build-provenance
// writes it.
func githubProvenance(repo, workflow string) map[string]any {
	return map[string]any{
		"buildDefinition": map[string]any{
			"buildType":            githubBuildType,
			"externalParameters":   map[string]any{"workflow": map[string]string{"ref": "refs/heads/main", "repository": repo, "path": workflow}},
			"resolvedDependencies": []any{map[string]any{"uri": "git+" + repo + "@refs/heads/main", "digest": map[string]string{"gitCommit": "abc123"}}},
		},
		"runDetails": map[string]any{"builder": map[string]string{"id": repo + "/" + workflow + "@refs/heads/main"}},
	}
}

// TestGitHubArtifactAttestations: provenance GitHub's attest-build-provenance
// pushed to the registry is labeled github-attestation, told by its verified
// content, with the signer workflow gh attestation verify needs; unverified
// copies aren't read, so they aren't.
func TestGitHubArtifactAttestations(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	evil := fulcioCert(t, evilSigner, ghIssuer)
	push := func(name string, predicate map[string]any, cert string) {
		idx := pushIndex(t, host+"/"+name+":1", nil, built, nil)
		d := descriptorOf(t, idx)
		attach(t, host+"/"+name, d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
		attach(t, host+"/"+name, d, bundleJSON(t, "https://slsa.dev/provenance/v1", d.Digest.String(), predicate, cert))
	}
	push("github", githubProvenance("https://github.com/acme/images", ".github/workflows/images.yml"), ours)
	push("cosign", provenancePredicate("https://github.com/acme/images", "abc123"), ours)
	push("forged", githubProvenance("https://github.com/acme/images", ".github/workflows/images.yml"), evil)

	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "github:1", "cosign:1", "forged:1"), Options{
		Name: "gh", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: verifier, Platforms: []string{"linux/amd64"},
		Policy: report.Policy{Required: []string{"provenance"}, TrustedSigners: verifier.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}
	const workflow = "github.com/acme/images/.github/workflows/images.yml"
	if p := img["github"].Evidence.Provenance; p.Status != "verified" || p.Source != "github-attestation" || p.SignerWorkflow != workflow ||
		p.Signer == nil || p.Signer.SourceRepository != "https://github.com/acme/images" {
		t.Errorf("GitHub provenance: %+v", p)
	}
	if s := img["github"].Source; s == nil || s.Basis != "provenance" || s.URL != "https://github.com/acme/images" || s.Revision != "abc123" {
		t.Errorf("GitHub provenance source: %+v", s)
	}
	if p := img["cosign"].Evidence.Provenance; p.Status != "verified" || p.Source != "cosign-attestation" || p.SignerWorkflow != workflow {
		t.Errorf("cosign provenance: %+v", p)
	}
	if p := img["forged"].Evidence.Provenance; p.Status != "failed" || p.Source != "cosign-attestation" || p.SignerWorkflow != "" {
		t.Errorf("unverified GitHub provenance: %+v", p)
	}
	if s := img["github"].Evidence.Signature; s.SignerWorkflow != workflow {
		t.Errorf("signature signer workflow: %+v", s)
	}
}

func TestSignerWorkflow(t *testing.T) {
	for s, want := range map[report.Signer]string{
		{Identity: ourSigner, Issuer: ghIssuer}: "github.com/acme/images/.github/workflows/images.yml",
		{Identity: "https://github.com/northcutted/clearcutt-factory/.github/workflows/fleet.yml@refs/tags/v0.2.0", Issuer: ghIssuer}: "github.com/northcutted/clearcutt-factory/.github/workflows/fleet.yml",
		{Identity: "alice@acme.com", Issuer: "https://accounts.google.com"}:                                                           "",
		{Identity: "https://github.com/acme/images", Issuer: ghIssuer}:                                                                "",
		{Key: "/etc/acme.pub"}: "",
	} {
		if got := signerWorkflow(s); got != want {
			t.Errorf("%+v: %q, want %q", s, got, want)
		}
	}
}

// provenanceBuilders makes the builder SLSA provenance names a check: a listed
// builder is verified (and says it was checked); any other, or none, is
// failed, and nothing is read from failed provenance (not its source, not
// its builder). A policy that reaches Build without validation (an empty
// entry) must not panic on provenance that names no builder.
func TestProvenanceBuilders(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	const runner = "https://github.com/actions/runner/github-hosted"
	const buildType = "https://actions.github.io/buildtypes/workflow/v1"
	withBuilder := func(builder string) map[string]any {
		p := provenancePredicate("https://github.com/acme/images", "abc123")
		p["buildDefinition"].(map[string]any)["buildType"] = buildType
		if builder != "" {
			p["runDetails"] = map[string]any{"builder": map[string]string{"id": builder}}
		}
		return p
	}
	for _, tc := range []struct {
		name      string
		builders  []string
		pred      map[string]any
		status    string
		checked   bool // provenance.builderChecked
		read      bool // images[].provenance and the source are read from it
		inDetail  string
		builderID string
	}{
		{"unchecked", nil, withBuilder("https://ci.example/other"), "verified", false, true, "weren't evaluated", "https://ci.example/other"},
		{"listed", []string{"https://ci.example/other", runner}, withBuilder(runner), "verified", true, true, "is one of the policy's provenanceBuilders", runner},
		{"another", []string{runner}, withBuilder("https://ci.example/other"), "failed", false, false, `"https://ci.example/other", not one of the policy's provenanceBuilders`, ""},
		{"unnamed", []string{runner}, withBuilder(""), "failed", false, false, "unnamed, not one of the policy's provenanceBuilders", ""},
		{"unreadable-empty-entry", []string{""}, map[string]any{}, "failed", false, false, "unnamed, not one of the policy's provenanceBuilders", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idx := pushIndex(t, host+"/"+tc.name+":1", nil, built, nil)
			d := descriptorOf(t, idx)
			attach(t, host+"/"+tc.name, d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
			attach(t, host+"/"+tc.name, d, bundleJSON(t, "https://slsa.dev/provenance/v1", d.Digest.String(), tc.pred, ours))
			verifier := acmeVerifier()
			r, err := Build(context.Background(), observe(t, host, tc.name+":1"), Options{
				Name: "provenance", Version: "test", GeneratedAt: "2026-10-26T00:00:00Z", Verifier: verifier,
				Policy: report.Policy{Required: []string{KindSignature, KindProvenance}, TrustedSigners: verifier.Signers, ProvenanceBuilders: tc.builders},
			})
			if err != nil {
				t.Fatal(err)
			}
			img := r.Images[0]
			ev := img.Evidence.Provenance
			if ev.Status != tc.status || !strings.Contains(ev.Detail, tc.inDetail) {
				t.Errorf("provenance evidence %s %q, want %s containing %q", ev.Status, ev.Detail, tc.status, tc.inDetail)
			}
			switch {
			case tc.read && (img.Provenance == nil || img.Provenance.BuilderID != tc.builderID || img.Provenance.BuildType != buildType || img.Provenance.BuilderChecked != tc.checked):
				t.Errorf("images[].provenance %+v, want builder %q checked %v", img.Provenance, tc.builderID, tc.checked)
			case !tc.read && img.Provenance != nil:
				t.Errorf("images[].provenance read from failed provenance: %+v", img.Provenance)
			}
			fromProvenance := img.Source != nil && img.Source.Basis == "provenance"
			if fromProvenance != tc.read {
				t.Errorf("source %+v; read from provenance: %v, want %v", img.Source, fromProvenance, tc.read)
			}
			if want := map[bool]string{true: "verified", false: "failed"}[tc.status == "verified"]; img.Verdict.Status != want {
				t.Errorf("verdict %+v, want %s", img.Verdict, want)
			}
			validateReport(t, r)
		})
	}
}
