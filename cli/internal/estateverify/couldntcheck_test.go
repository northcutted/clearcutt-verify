package estateverify

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// TestClassify tells "cosign couldn't check" from "it doesn't verify".
func TestClassify(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		err       string
		undecided bool
	}{
		{`cosign verify: exit status 1: error during command execution: Get "https://127.0.0.1:5999/v2/": dial tcp 127.0.0.1:5999: connect: connection refused`, true},
		{"error during command execution: getting trusted root: Get \"https://tuf-repo-cdn.sigstore.dev/timestamp.json\": dial tcp: lookup tuf-repo-cdn.sigstore.dev: no such host", true},
		{"GET https://ghcr.io/v2/acme/app/manifests/sha256-x: UNAUTHORIZED: authentication required", true},
		{"GET https://index.docker.io/v2/library/x/manifests/y: TOOMANYREQUESTS: You have reached your pull rate limit", true},
		{"GET https://ghcr.io/v2/acme/app/referrers/sha256:x: unexpected status code 503 Service Unavailable", true},
		{"net/http: TLS handshake timeout", true},
		{"error during command execution: no matching signatures: none of the expected identities matched what was in the certificate", false},
		{"error during command execution: no matching attestations: failed to verify signature: could not verify envelope: accepted signatures do not match threshold, Found: 0, Expected 1", false},
		{"error during command execution: no matching attestations: failed to verify log inclusion: not enough verified log entries from transparency log: 0 < 1", false},
		{"x509: certificate signed by unknown authority", false},
		// A certificate identity an attacker chose can't spell a network
		// failure: identities have no spaces.
		{"no matching signatures: none of the expected identities matched, got subjects [https://github.com/evil/x/.github/workflows/dial%20tcp%20no%20such%20host.yml@refs/heads/main]", false},
		{"no matching signatures: got subjects [https://github.com/evil/unauthorized:/.github/workflows/denied:.yml@refs/heads/main]", false},
	} {
		if got := couldntCheck(classify(ctx, errors.New(tc.err))); got != tc.undecided {
			t.Errorf("%q: undecided %v, want %v", tc.err, got, tc.undecided)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if !couldntCheck(classify(cancelled, errors.New("signal: killed"))) {
		t.Error("a cancelled run decided something")
	}
	if classify(ctx, nil) != nil {
		t.Error("nil isn't an error")
	}
}

// TestCosignThatCouldntCheckLeavesEvidenceUnknown: when cosign can't reach a
// registry or the transparency log, or can't run at all, the evidence it was
// asked about is unknown and the image unverified; never "not signed by a
// trusted signer", never failed.
func TestCosignThatCouldntCheckLeavesEvidenceUnknown(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	img := pushIndex(t, host+"/app:1", nil, built, nil)
	desc := descriptorOf(t, img)
	attach(t, host+"/app", desc, bundleJSON(t, PredicateCosignSign, desc.Digest.String(), map[string]any{}, ours))
	im, _ := img.IndexManifest()
	for _, d := range im.Manifests {
		attach(t, host+"/app", d, bundleJSON(t, "https://cyclonedx.org/bom", d.Digest.String(), sbomPredicate("openssl"), ours))
	}
	pushKeySignedAttestation(t, host+"/app", desc.Digest.String(), "https://slsa.dev/provenance/v1", provenancePredicate("https://github.com/acme/app", "abc"))

	offline := func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New(`error during command execution: Get "https://` + host + `/v2/": dial tcp: lookup registry: no such host`)
	}
	signers := []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}, {Key: "/keys/acme.pub"}}
	for name, v := range map[string]*Verifier{
		"offline":   {Signers: signers, Run: offline},
		"no cosign": {Signers: signers, Cosign: "/nonexistent/clearcutt-test/cosign"},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := Build(context.Background(), observe(t, host, "app:1"), Options{
				Name: "offline", Version: "test", GeneratedAt: "2026-10-18T00:00:00Z", Verifier: v,
				Policy: report.Policy{Required: []string{KindSignature, KindSBOM, KindProvenance}, TrustedSigners: signers},
			})
			if err != nil {
				t.Fatal(err)
			}
			a := r.Images[0]
			for kind, item := range map[string]report.EvidenceItem{KindSignature: a.Evidence.Signature, KindSBOM: a.Evidence.SBOM, KindProvenance: a.Evidence.Provenance} {
				if item.Status != "unknown" || !strings.Contains(item.Detail, "cosign couldn't check it") || strings.Contains(item.Detail, "not signed by a trusted signer") {
					t.Errorf("%s: %+v", kind, item)
				}
			}
			if a.Verdict.Status != "unverified" {
				t.Errorf("verdict %+v", a.Verdict)
			}
			validateReport(t, r)
		})
	}
}

// TestKeyThatCouldntBeCheckedIsUndecided: a copy one trusted key definitely
// didn't sign, and cosign couldn't check against another, may still be the
// other's: unknown, not failed.
func TestKeyThatCouldntBeCheckedIsUndecided(t *testing.T) {
	run := func(offline bool) func(context.Context, string, ...string) ([]byte, error) {
		return func(_ context.Context, _ string, args ...string) ([]byte, error) {
			for i, a := range args {
				if a == "--key" && args[i+1] == "/keys/b.pub" && offline {
					return nil, errors.New("Get \"https://rekor.example/api/v1/log\": dial tcp: i/o timeout")
				}
			}
			return nil, errors.New("no matching signatures: invalid signature when validating ASN.1 encoded signature")
		}
	}
	subj := Subject{Ref: "r@sha256:" + strings.Repeat("a", 64), Kind: KindSignature, PredicateType: PredicateCosignSign}
	signers := []report.Signer{{Key: "/keys/a.pub"}, {Key: "/keys/b.pub"}}
	if _, err := (&Verifier{Signers: signers, Run: run(true)}).Verify(context.Background(), subj); !couldntCheck(err) {
		t.Errorf("one key unchecked: %v", err)
	}
	if _, err := (&Verifier{Signers: signers, Run: run(false)}).Verify(context.Background(), subj); err == nil || couldntCheck(err) || !strings.Contains(err.Error(), "not signed by a trusted signer") {
		t.Errorf("both keys checked: %v", err)
	}
}

// TestUndecidedPrecheckVerifiesEveryClaim: when copies name two acceptable
// signers, cosign is first asked which statements are genuine; if it can't
// say, no claim is dropped as forged on that account.
func TestUndecidedPrecheckVerifiesEveryClaim(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	img := pushIndex(t, host+"/app:1", nil, built, nil)
	desc := descriptorOf(t, img)
	d := desc.Digest.String()
	other := "https://github.com/acme/images/.github/workflows/other.yml@refs/heads/main"
	attach(t, host+"/app", desc, bundleJSON(t, PredicateRecipe, d, recipePredicate("sha256:"+strings.Repeat("b", 64)), fulcioCert(t, ourSigner, ghIssuer)))
	attach(t, host+"/app", desc, bundleJSON(t, PredicateRecipe, d, recipePredicate("sha256:"+strings.Repeat("c", 64)), fulcioCert(t, other, ghIssuer)))
	fake := acmeVerifier()
	v := &Verifier{Signers: fake.Signers, Run: func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		for _, a := range args {
			if a == "--certificate-identity-regexp" {
				// The precheck, against the trusted signer's expression.
				return nil, errors.New("dial tcp: lookup rekor.sigstore.dev: no such host")
			}
		}
		return fake.Run(ctx, bin, args...)
	}}
	found, err := (&Discoverer{}).Discover(context.Background(), host+"/app", d)
	if err != nil {
		t.Fatal(err)
	}
	item, verified := verifyEvidence(context.Background(), v, host+"/app", d, KindRecipe, "", found)
	if item.Status != "verified" || len(verified) != 2 {
		t.Errorf("recipe %+v, %d verified", item, len(verified))
	}
}

// TestPartialPlatformListIsUnknown: when one platform image can't be read,
// what is attached to each platform image is unknown for the image, not
// judged on the platform images that could be read.
func TestPartialPlatformListIsUnknown(t *testing.T) {
	reg := ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true))
	var refuse atomic.Value
	refuse.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d := refuse.Load().(string); d != "" && strings.HasSuffix(r.URL.Path, "/manifests/"+d) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}`)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	img := pushIndex(t, host+"/app:1", nil, built, nil)
	desc := descriptorOf(t, img)
	attach(t, host+"/app", desc, bundleJSON(t, PredicateCosignSign, desc.Digest.String(), map[string]any{}, ours))
	im, _ := img.IndexManifest()
	var arm string
	for _, d := range im.Manifests {
		attach(t, host+"/app", d, bundleJSON(t, "https://cyclonedx.org/bom", d.Digest.String(), sbomPredicate("openssl"), ours))
		attach(t, host+"/app", d, bundleJSON(t, PredicateVuln, d.Digest.String(), vulnPredicate(nil, nil), ours))
		if d.Platform.Architecture == "arm64" {
			arm = d.Digest.String()
		}
	}
	observations := observe(t, host, "app:1")
	verifier := acmeVerifier()
	policy := report.Policy{Required: []string{KindSignature, KindSBOM}, TrustedSigners: verifier.Signers, FailOn: "critical"}
	build := func(platforms ...string) report.Image {
		t.Helper()
		r, err := Build(context.Background(), observations, Options{Name: "p", Version: "test", GeneratedAt: "2026-10-18T00:00:00Z", Verifier: verifier, Policy: policy, Platforms: platforms})
		if err != nil {
			t.Fatal(err)
		}
		validateReport(t, r)
		return r.Images[0]
	}
	if a := build(); a.Verdict.Status != "verified" || a.Evidence.SBOM.Status != "verified" {
		t.Fatalf("control: every platform read: %+v %+v", a.Evidence.SBOM, a.Verdict)
	}

	refuse.Store(arm)
	a := build()
	for kind, item := range map[string]report.EvidenceItem{KindSBOM: a.Evidence.SBOM, KindVulnerabilityScan: a.Evidence.VulnerabilityScan} {
		if item.Status != "unknown" || !strings.Contains(item.Detail, "Not every platform image could be read") {
			t.Errorf("%s with a platform unread: %+v", kind, item)
		}
	}
	if a.Vulnerabilities != nil || a.Packages != nil || a.PackagesSource != nil {
		t.Errorf("read findings or packages off some platforms: %+v %v %+v", a.Vulnerabilities, a.Packages, a.PackagesSource)
	}
	if a.Verdict.Status != "unverified" || a.Evidence.Signature.Status != "verified" {
		t.Errorf("verdict %+v, signature %+v", a.Verdict, a.Evidence.Signature)
	}

	// Reading only platforms the image doesn't have is not finding nothing.
	refuse.Store("")
	a = build("linux/s390x")
	if a.Evidence.SBOM.Status != "unknown" || a.Verdict.Status != "unverified" || a.Platforms == nil {
		t.Errorf("no platform selected: sbom %+v, verdict %+v, platforms %v", a.Evidence.SBOM, a.Verdict, a.Platforms)
	}
}

// TestReportRecordsThePlatformsRead: --platforms is in the report, so a
// reader knows the evidence describes those platforms only.
func TestReportRecordsThePlatformsRead(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	pushIndex(t, host+"/app:1", nil, built, nil)
	observations := observe(t, host, "app:1")
	for _, tc := range []struct {
		platforms []string
		want      string
	}{
		{nil, ""},
		{[]string{"linux/arm64", " linux/amd64", "linux/arm64", ""}, "linux/amd64,linux/arm64"},
	} {
		r, err := Build(context.Background(), observations, Options{Name: "p", Version: "test", GeneratedAt: "2026-10-18T00:00:00Z", Verifier: acmeVerifier(), Platforms: tc.platforms})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(r.Metadata.Platforms, ","); got != tc.want {
			t.Errorf("platforms %v recorded as %q, want %q", tc.platforms, got, tc.want)
		}
		if n := len(r.Images[0].Platforms); n != 2 {
			t.Errorf("platforms %v: read %d platform images", tc.platforms, n)
		}
		validateReport(t, r)
	}
}
