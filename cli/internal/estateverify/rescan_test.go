package estateverify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// recordedGrype is real grype output over a two-package SBOM (lodash and a
// qualified wolfi openssl purl), with two openssl findings suppressed by a
// VEX document: testdata/grype-sbom-scan.json, trimmed.
func recordedGrype(t *testing.T) grypeResult {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "grype-sbom-scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r grypeResult
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// fakeScanner stands in for grype: it returns the recorded output and
// remembers what it was given.
type fakeScanner struct {
	result grypeResult
	err    error
	mu     sync.Mutex
	calls  []fakeScan
}

type fakeScan struct {
	sbom, vex []byte
}

func (f *fakeScanner) Scan(_ context.Context, sbom, vex []byte) (grypeResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeScan{sbom, vex})
	f.mu.Unlock()
	if f.err != nil {
		return grypeResult{}, f.err
	}
	return f.result, nil
}

func TestRecordedGrypeOutputReads(t *testing.T) {
	r := recordedGrype(t)
	if len(r.Matches) != 2 || len(r.IgnoredMatches) != 2 || r.Descriptor.Name != "grype" || r.Descriptor.Version == "" {
		t.Fatalf("recorded output: %d matches, %d ignored, %s %s", len(r.Matches), len(r.IgnoredMatches), r.Descriptor.Name, r.Descriptor.Version)
	}
	db := r.database()
	if db == nil || db.Schema != "v6.1.10" || !strings.HasPrefix(db.Built, "2026-10-25T") || !strings.HasSuffix(db.Built, "Z") {
		t.Errorf("database: %+v", db)
	}
	if r.IgnoredMatches[0].AppliedIgnoreRules[0].Namespace != "vex" || r.IgnoredMatches[0].Artifact.PURL == "" {
		t.Errorf("ignored match: %+v", r.IgnoredMatches[0])
	}
}

// TestRescanScansOnlyVerifiedSBOMs: the rescan scans the SBOM a trusted
// signer verified, per platform, and an image whose SBOM isn't verified on a
// platform is unknown, never clean. Both scans sit side by side in the
// report, the attested one as before.
func TestRescanScansOnlyVerifiedSBOMs(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours, evil := fulcioCert(t, ourSigner, ghIssuer), fulcioCert(t, evilSigner, ghIssuer)

	sbom := map[string]any{"bomFormat": "CycloneDX", "components": []any{
		map[string]string{"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
		map[string]string{"type": "library", "name": "openssl", "version": "3.0.1-r0", "purl": "pkg:apk/wolfi/openssl@3.0.1-r0?arch=x86_64&distro=wolfi-20230201"},
	}}
	attested := vulnPredicate([]map[string]any{grypeMatchJSON("CVE-OLD-1", "High", "lodash", "4.17.15", "4.17.21")}, nil)

	// app: SBOM and scan verified on both platforms.
	app := pushIndex(t, host+"/app:1", nil, built, nil)
	appDesc := descriptorOf(t, app)
	attach(t, host+"/app", appDesc, bundleJSON(t, PredicateCosignSign, appDesc.Digest.String(), map[string]any{}, ours))
	im, _ := app.IndexManifest()
	for _, d := range im.Manifests {
		attach(t, host+"/app", d, bundleJSON(t, "https://cyclonedx.org/bom", d.Digest.String(), sbom, ours))
		attach(t, host+"/app", d, bundleJSON(t, PredicateVuln, d.Digest.String(), attested, ours))
	}
	// half: the arm64 SBOM is signed by someone else.
	half := pushIndex(t, host+"/half:1", nil, built, nil)
	halfDesc := descriptorOf(t, half)
	attach(t, host+"/half", halfDesc, bundleJSON(t, PredicateCosignSign, halfDesc.Digest.String(), map[string]any{}, ours))
	him, _ := half.IndexManifest()
	for _, d := range him.Manifests {
		cert := ours
		if d.Platform.Architecture == "arm64" {
			cert = evil
		}
		attach(t, host+"/half", d, bundleJSON(t, "https://cyclonedx.org/bom", d.Digest.String(), sbom, cert))
	}
	// bare: no SBOM at all.
	pushIndex(t, host+"/bare:1", nil, built, nil)

	vexDir := t.TempDir()
	vexFile := filepath.Join(vexDir, "openssl.openvex.json")
	if err := os.WriteFile(vexFile, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://acme.example/vex/1","author":"acme","timestamp":"2026-10-01T00:00:00Z","version":1,
	 "statements":[{"vulnerability":{"name":"CVE-2022-3358"},"products":[{"@id":"pkg:oci/app?repository_url=`+host+`/app","subcomponents":[{"@id":"pkg:apk/wolfi/openssl@3.0.1-r0"}]}],"status":"not_affected","justification":"vulnerable_code_not_present"},
	  {"vulnerability":{"name":"CVE-2022-3786"},"products":[{"@id":"pkg:apk/wolfi/openssl"}],"status":"fixed"},
	  {"vulnerability":{"name":"CVE-NOWHERE"},"products":[{"@id":"pkg:oci/gone?repository_url=`+host+`/gone"}],"status":"not_affected","justification":"component_not_present"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	docs, err := ReadVEX(vexDir, []string{"openssl.openvex.json"})
	if err != nil {
		t.Fatal(err)
	}
	scanner := &fakeScanner{result: recordedGrype(t)}
	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "app:1", "half:1", "bare:1"), Options{
		Name: "rescan", Version: "test", GeneratedAt: "2026-10-18T12:00:00Z", Verifier: verifier, Scanner: scanner, VEX: docs,
		Policy: report.Policy{Required: []string{"signature"}, TrustedSigners: verifier.Signers, FailOn: "high", Rescan: true, VEX: describeVEX(docs)},
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
	if a.Rescan == nil || a.Rescan.Status != "scanned" || a.Rescan.Platforms["linux/amd64"] != "scanned" || a.Rescan.Platforms["linux/arm64"] != "scanned" {
		t.Fatalf("app rescan: %+v", a.Rescan)
	}
	fresh := a.Rescan.Vulnerabilities
	if fresh == nil || fresh.Source != "scan" || !strings.HasPrefix(fresh.Scanner, "grype 0.") || fresh.ScannedAt != "2026-10-18T12:00:00Z" || fresh.Database == nil || fresh.Database.Schema != "v6.1.10" {
		t.Fatalf("app fresh scan: %+v", fresh)
	}
	// Both scans, side by side: the attested one is untouched.
	if a.Vulnerabilities == nil || a.Vulnerabilities.Source != "attestation" || a.Vulnerabilities.Counts.High != 1 || a.Vulnerabilities.Findings[0].ID != "CVE-OLD-1" {
		t.Errorf("app attested scan: %+v", a.Vulnerabilities)
	}
	// The fresh scan: two lodash findings counted, two openssl findings
	// suppressed and attributed to their statements, never dropped.
	if fresh.Counts.High != 1 || fresh.Counts.Medium != 1 || len(fresh.Findings) != 4 {
		t.Errorf("fresh counts %+v, %d findings", fresh.Counts, len(fresh.Findings))
	}
	byID := map[string]report.Finding{}
	for _, f := range fresh.Findings {
		byID[f.ID] = f
	}
	if f := byID["CVE-2022-3358"]; !f.Suppressed || f.SuppressedBy == nil || f.SuppressedBy.Source != "vex" || f.SuppressedBy.File != "openssl.openvex.json" ||
		f.SuppressedBy.Document != "https://acme.example/vex/1" || f.SuppressedBy.Product != "pkg:oci/app?repository_url="+host+"/app" || f.SuppressedBy.Status != "not_affected" || f.SuppressedBy.Justification != "vulnerable_code_not_present" {
		t.Errorf("image-scoped suppression: %+v (%+v)", f, f.SuppressedBy)
	}
	if f := byID["CVE-2022-3786"]; !f.Suppressed || f.SuppressedBy == nil || f.SuppressedBy.Product != "pkg:apk/wolfi/openssl" || f.SuppressedBy.Status != "fixed" {
		t.Errorf("package-scoped suppression: %+v (%+v)", f, f.SuppressedBy)
	}
	if f := byID["GHSA-35jh-r3h4-6jhm"]; f.Suppressed || f.SuppressedBy != nil || f.Severity != "high" || len(f.Platforms) != 2 {
		t.Errorf("counted finding: %+v", f)
	}
	// What grype was given: the verified SBOM, and a VEX document scoped to
	// this image: the image statement rewritten to its subcomponent, the
	// package statement as it is, and nothing about the other image.
	if len(scanner.calls) != 3 { // app ×2 platforms, half ×1 (amd64 only); images run concurrently
		t.Fatalf("%d scans", len(scanner.calls))
	}
	appScans, halfScans := 0, 0
	for _, c := range scanner.calls {
		var doc struct {
			Statements []VEXStatement `json:"statements"`
		}
		if err := json.Unmarshal(c.vex, &doc); err != nil {
			t.Fatalf("scoped VEX: %v %s", err, c.vex)
		}
		if !strings.Contains(string(c.sbom), `"lodash"`) {
			t.Errorf("scanned something other than the verified SBOM: %s", c.sbom)
		}
		switch len(doc.Statements) {
		case 2: // app: the image statement rewritten to its subcomponent, then the package statement
			appScans++
			if doc.Statements[0].Products[0].ID != "pkg:apk/wolfi/openssl@3.0.1-r0" || doc.Statements[1].Products[0].ID != "pkg:apk/wolfi/openssl" {
				t.Errorf("scoped products: %+v", doc.Statements)
			}
		case 1: // half: only the package statement applies
			halfScans++
			if doc.Statements[0].Products[0].ID != "pkg:apk/wolfi/openssl" {
				t.Errorf("half's VEX: %+v", doc.Statements)
			}
		default:
			t.Errorf("scoped VEX with %d statements: %s", len(doc.Statements), c.vex)
		}
	}
	if appScans != 2 || halfScans != 1 {
		t.Errorf("%d scans of app, %d of half", appScans, halfScans)
	}
	// failOn gates on the worse of the two scans: the attested High fails it.
	if a.Verdict.Status != "failed" || !strings.Contains(strings.Join(a.Verdict.Reasons, ";"), "in this run's scan") || !strings.Contains(strings.Join(a.Verdict.Reasons, ";"), "1 vulnerabilities at high or above;") {
		t.Errorf("app verdict: %+v", a.Verdict)
	}

	h := img["half"]
	if h.Rescan == nil || h.Rescan.Status != "unknown" || h.Rescan.Platforms["linux/amd64"] != "scanned" || h.Rescan.Platforms["linux/arm64"] != "unknown" || h.Rescan.Vulnerabilities != nil ||
		!strings.Contains(h.Rescan.Detail, "no verified SBOM") {
		t.Errorf("half rescan: %+v", h.Rescan)
	}
	if h.Verdict.Status != "unverified" || !strings.Contains(strings.Join(h.Verdict.Reasons, ";"), "current vulnerabilities are unknown (the rescan is unknown") {
		t.Errorf("half verdict: %+v", h.Verdict)
	}
	b := img["bare"]
	if b.Rescan == nil || b.Rescan.Status != "unknown" || len(scanner.calls) != 3 {
		t.Errorf("bare rescan: %+v", b.Rescan)
	}

	// The summary totals the rescans, and the statement that named no image
	// is warned about, not dropped.
	if s := r.Summary.Rescan; s == nil || s.Scanned != 1 || s.Unknown != 2 || s.Counts.High != 1 || s.Suppressed != 2 || !strings.HasPrefix(s.Scanner, "grype") || s.Database == nil {
		t.Errorf("rescan summary: %+v", r.Summary.Rescan)
	}
	if w := strings.Join(r.Warnings, "\n"); !strings.Contains(w, "CVE-NOWHERE") || !strings.Contains(w, "none of the estate's images") {
		t.Errorf("warnings: %v", r.Warnings)
	}
	if len(r.Policy.VEX) != 1 || r.Policy.VEX[0].File != "openssl.openvex.json" || r.Policy.VEX[0].Statements != 3 {
		t.Errorf("policy vex: %+v", r.Policy.VEX)
	}
}

// grype failing leaves the rescan unknown with the reason, never clean.
func TestRescanGrypeFailureIsUnknown(t *testing.T) {
	img := &report.Image{Repository: "r", Digest: "sha256:" + strings.Repeat("a", 64), Evidence: report.Evidence{SBOM: report.EvidenceItem{Status: "verified"}}}
	platforms := []report.Platform{{Platform: "linux/amd64", Digest: "sha256:" + strings.Repeat("b", 64)}}
	data := imageData{sboms: map[string]sbomDoc{"linux/amd64": {raw: []byte(`{"bomFormat":"CycloneDX"}`)}}}
	scanner := &fakeScanner{err: errors.New("grype: exit status 1: failed to load vulnerability db")}
	got := rescanImage(context.Background(), img, platforms, nil, data, Options{Scanner: scanner, GeneratedAt: "2026-10-18T00:00:00Z"})
	if got.Status != "unknown" || got.Vulnerabilities != nil || !strings.Contains(got.Detail, "grype couldn't scan it") || got.Platforms["linux/amd64"] != "unknown" {
		t.Errorf("%+v", got)
	}
	// Not every platform image read: nothing is scanned.
	got = rescanImage(context.Background(), img, platforms, errors.New("arm64 unreadable"), data, Options{Scanner: &fakeScanner{result: recordedGrype(t)}})
	if got.Status != "unknown" || !strings.Contains(got.Detail, "Not every platform image") {
		t.Errorf("partial platforms: %+v", got)
	}
}

// TestScanSourceGating: what failOn gates on, by scanSource, over every
// combination of attested and fresh findings.
func TestScanSourceGating(t *testing.T) {
	clean := &report.Vulnerabilities{Source: "attestation", Findings: []report.Finding{}}
	bad := &report.Vulnerabilities{Source: "attestation", Counts: report.SeverityCounts{Critical: 1}, Findings: []report.Finding{{ID: "CVE-1", Severity: "critical", Platforms: []string{"linux/amd64"}}}}
	scanned := func(v *report.Vulnerabilities) *report.Rescan {
		c := *v
		c.Source = "scan"
		return &report.Rescan{Status: "scanned", Vulnerabilities: &c}
	}
	unknownRescan := &report.Rescan{Status: "unknown", Detail: "no verified SBOM."}
	signers := []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}
	for _, tc := range []struct {
		source   string
		attested *report.Vulnerabilities
		rescan   *report.Rescan
		want     string
	}{
		// attestation: the fresh scan doesn't matter.
		{"attestation", clean, scanned(bad), "verified"},
		{"attestation", bad, scanned(clean), "failed"},
		{"attestation", nil, scanned(clean), "unverified"},
		// rescan: the attested scan doesn't matter.
		{"rescan", bad, scanned(clean), "verified"},
		{"rescan", clean, scanned(bad), "failed"},
		{"rescan", clean, unknownRescan, "unverified"},
		{"rescan", clean, nil, "unverified"},
		// worst: either failing fails; either unknown leaves it unverified.
		{"worst", clean, scanned(clean), "verified"},
		{"worst", bad, scanned(clean), "failed"},
		{"worst", clean, scanned(bad), "failed"},
		{"worst", nil, scanned(clean), "unverified"},
		{"worst", clean, unknownRescan, "unverified"},
		{"worst", bad, unknownRescan, "failed"},
	} {
		img := allVerified()
		img.Vulnerabilities = tc.attested
		if tc.attested == nil {
			img.Evidence.VulnerabilityScan = report.EvidenceItem{Status: "missing"}
		}
		img.Rescan = tc.rescan
		p := report.Policy{TrustedSigners: signers, FailOn: "critical", Rescan: true, ScanSource: tc.source}
		if got := verdictAt(img, p, built); got.Status != tc.want {
			t.Errorf("scanSource %s, attested %v, rescan %v: %+v, want %s", tc.source, tc.attested != nil && tc.attested.Counts.Critical > 0, tc.rescan, got, tc.want)
		}
	}
	// Without --rescan the default is attestation; with it, worst.
	if scanSource(report.Policy{}) != "attestation" || scanSource(report.Policy{Rescan: true}) != "worst" || scanSource(report.Policy{Rescan: true, ScanSource: "rescan"}) != "rescan" {
		t.Error("scanSource defaults")
	}
	if err := ValidatePolicy(report.Policy{ScanSource: "newest"}); err == nil {
		t.Error("accepted scanSource newest")
	}
}

// maxScanAgeDays measures a rescan by its database's build time.
func TestMaxScanAgeUsesTheRescansDatabase(t *testing.T) {
	signers := []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	img := allVerified()
	img.Vulnerabilities = &report.Vulnerabilities{Source: "attestation", ScannedAt: "2026-09-01T00:00:00Z", Findings: []report.Finding{}}
	p := report.Policy{TrustedSigners: signers, MaxScanAgeDays: 7, Rescan: true}
	if got := verdictAt(img, p, now); got.Status != "unverified" {
		t.Errorf("old attested scan, no rescan: %+v", got)
	}
	img.Rescan = &report.Rescan{Status: "scanned", Vulnerabilities: &report.Vulnerabilities{Source: "scan", ScannedAt: "2026-10-18T12:00:00Z", Database: &report.ScannerDatabase{Built: "2026-10-18T06:00:00Z"}, Findings: []report.Finding{}}}
	if got := verdictAt(img, p, now); got.Status != "verified" {
		t.Errorf("fresh rescan: %+v", got)
	}
	img.Rescan.Vulnerabilities.Database.Built = "2026-09-20T00:00:00Z"
	if got := verdictAt(img, p, now); got.Status != "unverified" || !strings.Contains(got.Reasons[0], "database is 28 days old") {
		t.Errorf("stale database: %+v", got)
	}
}

// Observe-only images keep their verdict but don't count toward the
// estate's, and the patterns match repositories or repository:tag.
func TestObserveOnly(t *testing.T) {
	for _, tc := range []struct {
		patterns []string
		repo     string
		tags     []string
		want     bool
	}{
		{[]string{"cgr.dev/chainguard/*"}, "cgr.dev/chainguard/wolfi-base", []string{"latest"}, true},
		{[]string{"cgr.dev/chainguard/*"}, "ghcr.io/acme/wolfi-base", nil, false},
		{[]string{"ghcr.io/acme/app:canary"}, "ghcr.io/acme/app", []string{"canary"}, true},
		{[]string{"ghcr.io/acme/app:canary"}, "ghcr.io/acme/app", []string{"1"}, false},
		{nil, "ghcr.io/acme/app", nil, false},
	} {
		if got := observeOnly(tc.patterns, tc.repo, tc.tags); got != tc.want {
			t.Errorf("observe %v on %s %v = %v", tc.patterns, tc.repo, tc.tags, got)
		}
	}
	r := &report.Report{Policy: report.Policy{Rescan: true}, Images: []report.Image{
		{ID: "a", Verdict: report.Verdict{Status: "failed"}, ObserveOnly: true},
		{ID: "b", Verdict: report.Verdict{Status: "verified"}},
		{ID: "c", Verdict: report.Verdict{Status: "unverified"}},
	}}
	s := summarize(r)
	if s.Verdicts != (report.VerdictCounts{Verified: 1, Unverified: 1, ObserveOnly: 1}) || s.Rescan == nil || s.Rescan.Unknown != 3 {
		t.Errorf("summary %+v %+v", s.Verdicts, s.Rescan)
	}
	if err := ValidatePolicy(report.Policy{Observe: []string{"["}}); err == nil {
		t.Error("accepted a bad pattern")
	}
}

func TestNothingChecked(t *testing.T) {
	unknown := report.EvidenceItem{Status: "unknown"}
	all := report.Evidence{Signature: unknown, SBOM: unknown, VulnerabilityScan: unknown, Provenance: unknown, Recipe: unknown, Rebase: unknown, Tests: unknown}
	r := &report.Report{Images: []report.Image{{Evidence: all}, {Evidence: all}}}
	if !NothingChecked(r) {
		t.Error("every item unknown isn't nothing checked")
	}
	one := all
	one.Signature = report.EvidenceItem{Status: "missing"}
	r.Images[1].Evidence = one
	if NothingChecked(r) {
		t.Error("a decided item means something was checked")
	}
	if NothingChecked(&report.Report{}) {
		t.Error("no images isn't nothing checked")
	}
}

// TestVEXScoping pins the rule for which image a VEX product names.
func TestVEXScoping(t *testing.T) {
	img := imageIdentity{repository: "ghcr.io/acme/app", tags: []string{"1.2"}, digest: "sha256:" + strings.Repeat("a", 64), platform: "linux/amd64", platformDigest: "sha256:" + strings.Repeat("b", 64)}
	for _, tc := range []struct {
		product string
		want    bool
	}{
		{"pkg:oci/app@sha256%3A" + strings.Repeat("a", 64), true},
		{"pkg:oci/app@sha256:" + strings.Repeat("b", 64), true}, // this platform
		{"pkg:oci/app@sha256%3A" + strings.Repeat("c", 64), false},
		{"pkg:oci/app?repository_url=ghcr.io/acme/app", true},
		{"pkg:oci/app?repository_url=ghcr.io/acme/app&tag=1.2", true},
		{"pkg:oci/app?repository_url=ghcr.io/acme/app&tag=2.0", false},
		{"pkg:oci/app?repository_url=ghcr.io/acme/other", false},
		{"pkg:oci/app", false}, // names no image
		{"pkg:docker/app?repository_url=ghcr.io/acme/app", true},
		{"ghcr.io/acme/app", true},
		{"ghcr.io/acme/app:1.2", true},
		{"ghcr.io/acme/app:2.0", false},
		{"ghcr.io/acme/app@sha256:" + strings.Repeat("a", 64), true},
		{"sha256:" + strings.Repeat("a", 64), true},
		{"ghcr.io/acme/apple", false},
	} {
		if got := productNamesImage(tc.product, img); got != tc.want {
			t.Errorf("%s names the image: %v, want %v", tc.product, got, tc.want)
		}
	}
	for product, kind := range map[string]string{"pkg:apk/wolfi/openssl@3.0": productPackage, "pkg:golang/golang.org/x/net": productPackage, "pkg:oci/app": productImage, "ghcr.io/acme/app": productImage, "": productOther} {
		if got := productKind(product); got != kind {
			t.Errorf("kind of %q: %s, want %s", product, got, kind)
		}
	}
	for _, tc := range []struct {
		product, artifact string
		want              bool
	}{
		{"pkg:apk/wolfi/openssl@3.0.1-r0", "pkg:apk/wolfi/openssl@3.0.1-r0?arch=x86_64&distro=wolfi-20230201", true},
		{"pkg:apk/wolfi/openssl", "pkg:apk/wolfi/openssl@3.0.1-r0?arch=x86_64", true},
		{"pkg:apk/wolfi/openssl@3.0.1-r0?arch=x86_64", "pkg:apk/wolfi/openssl@3.0.1-r0?arch=x86_64&distro=w", true},
		{"pkg:apk/wolfi/openssl@3.0.1-r0?arch=aarch64", "pkg:apk/wolfi/openssl@3.0.1-r0?arch=x86_64", false},
		{"pkg:apk/wolfi/openssl@3.0.2-r0", "pkg:apk/wolfi/openssl@3.0.1-r0", false},
		{"pkg:apk/alpine/openssl", "pkg:apk/wolfi/openssl@3.0.1-r0", false},
		{"pkg:npm/lodash@4.17.15", "pkg:npm/lodash@4.17.15", true},
	} {
		if got := purlMatches(tc.product, tc.artifact); got != tc.want {
			t.Errorf("%s matches %s: %v, want %v", tc.product, tc.artifact, got, tc.want)
		}
	}
	// A statement about the image with no subcomponents covers every package.
	docs := []VEXDocument{{File: "v.json", ID: "doc", Statements: []VEXStatement{{Vulnerability: vexVulnerability{Name: "CVE-X"}, Products: []vexProduct{{ID: "ghcr.io/acme/app"}}, Status: "not_affected"}}}}
	raw, scoped := scopeVEX(docs, img, []string{"pkg:npm/a@1", "pkg:npm/b@2"})
	if raw == nil || len(scoped) != 1 || !scoped[0].anyPackage || len(scoped[0].Products) != 2 || scoped[0].Products[1].ID != "pkg:npm/b@2" {
		t.Errorf("expanded statement: %+v", scoped)
	}
	m := grypeMatch{}
	m.Vulnerability.ID = "GHSA-1"
	m.RelatedVulnerabilities = []struct {
		ID string `json:"id"`
	}{{"CVE-X"}}
	m.Artifact.PURL = "pkg:npm/b@2"
	m.AppliedIgnoreRules = []struct {
		Namespace string `json:"namespace"`
		MatchType string `json:"match-type"`
		VEXStatus string `json:"vex-status"`
	}{{Namespace: "vex", VEXStatus: "not_affected"}}
	if by := attributeSuppressions(scoped, m); by == nil || by.Source != "vex" || by.Document != "doc" || by.Product != "ghcr.io/acme/app" {
		t.Errorf("attribution by alias: %+v", by)
	}
	m.AppliedIgnoreRules[0].Namespace = ""
	m.AppliedIgnoreRules[0].MatchType = "exact-indirect-match"
	if by := attributeSuppressions(scoped, m); by == nil || by.Source != "scanner" {
		t.Errorf("grype's own rule: %+v", by)
	}
	if raw, _ := scopeVEX(docs, imageIdentity{repository: "ghcr.io/acme/other"}, nil); raw != nil {
		t.Error("a statement about another image was passed to grype")
	}
}

func TestReadVEXRefusesWhatIsntOpenVEX(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"notvex.json":    `{"statements":[]}`,
		"noproduct.json": `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-1"},"products":[],"status":"not_affected"}]}`,
		"nostatus.json":  `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:npm/a"}]}]}`,
		"ok.json":        `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","statements":[{"vulnerability":{"name":"CVE-1"},"products":["pkg:npm/a@1"],"status":"fixed"}]}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := ReadVEX(dir, []string{name})
		if (err == nil) != (name == "ok.json") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ReadVEX(dir, []string{"missing.json"}); err == nil {
		t.Error("read a missing file")
	}
	// A plain-string product (older documents) reads.
	docs, _ := ReadVEX(dir, []string{"ok.json"})
	if len(docs) != 1 || docs[0].Statements[0].Products[0].ID != "pkg:npm/a@1" {
		t.Errorf("%+v", docs)
	}
}
