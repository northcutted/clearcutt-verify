package estateverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

const reusable = "https://github.com/acme/factory/.github/workflows/images.yml@refs/tags/v1"

func TestSignerOfSource(t *testing.T) {
	der := func(exts ...pkix.Extension) *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		u, _ := url.Parse(reusable)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u}, ExtraExtensions: exts}
		raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(raw)
		return cert
	}
	s := signerOf(der(pkix.Extension{Id: oidIssuerV2, Value: mustUTF8(ghIssuer)},
		pkix.Extension{Id: oidSourceRepository, Value: mustUTF8("https://github.com/acme/checkout")}, pkix.Extension{Id: oidSourceRef, Value: mustUTF8("refs/heads/main")}))
	if s.Identity != reusable || s.Issuer != ghIssuer || s.SourceRepository != "https://github.com/acme/checkout" || s.SourceRef != "refs/heads/main" {
		t.Errorf("v2 extensions: %+v", s)
	}
	// Older certificates carry only the v1 extensions, as raw strings.
	s = signerOf(der(pkix.Extension{Id: oidIssuerV1, Value: []byte(ghIssuer)},
		pkix.Extension{Id: oidWorkflowRepository, Value: []byte("acme/checkout")}, pkix.Extension{Id: oidWorkflowRef, Value: []byte("refs/heads/main")}))
	if s.Issuer != ghIssuer || s.SourceRepository != "https://github.com/acme/checkout" || s.SourceRef != "refs/heads/main" {
		t.Errorf("v1 extensions: %+v", s)
	}
	if repo, ok := calledFromElsewhere(s); !ok || repo != "https://github.com/acme/checkout" {
		t.Errorf("a reusable workflow's caller: %q %v", repo, ok)
	}
	if _, ok := calledFromElsewhere(&report.Signer{Identity: "https://github.com/acme/checkout/.github/workflows/ci.yml@refs/heads/main", SourceRepository: "https://github.com/acme/checkout"}); ok {
		t.Error("a repository's own workflow is not called from elsewhere")
	}
}

// TestAccepts covers which certificates a trusted signer accepts before
// cosign is asked to verify them, and what cosign is then asked for.
func TestAccepts(t *testing.T) {
	cert := report.Signer{Identity: reusable, Issuer: ghIssuer, SourceRepository: "https://github.com/acme/checkout", SourceRef: "refs/heads/main"}
	factory := report.Signer{IdentityRegexp: `^https://github\.com/acme/factory/`, Issuer: ghIssuer}
	with := func(f func(*report.Signer)) report.Signer {
		s := factory
		f(&s)
		return s
	}
	for _, c := range []struct {
		name        string
		signer      report.Signer
		cert        report.Signer
		imageSource string
		want        string // "" when accepted, else the error's text
	}{
		{"identity regexp", factory, cert, "", ""},
		{"exact identity", report.Signer{Identity: reusable, Issuer: ghIssuer}, cert, "", ""},
		{"another identity", report.Signer{Identity: ourSigner, Issuer: ghIssuer}, cert, "", "not " + ourSigner},
		{"another workflow", report.Signer{IdentityRegexp: `^https://github\.com/acme/images/`, Issuer: ghIssuer}, cert, "", "doesn't match"},
		{"another issuer", with(func(s *report.Signer) { s.Issuer = "https://gitlab.com" }), cert, "", "issued by"},
		{"repository", with(func(s *report.Signer) { s.SourceRepository = "https://github.com/acme/checkout" }), cert, "", ""},
		{"another repository", with(func(s *report.Signer) { s.SourceRepository = "https://github.com/acme/billing" }), cert, "", "not https://github.com/acme/billing"},
		{"owner", with(func(s *report.Signer) { s.SourceRepositoryOwner = "https://github.com/acme" }), cert, "", ""},
		{"owner with a trailing slash", with(func(s *report.Signer) { s.SourceRepositoryOwner = "https://github.com/acme/" }), cert, "", ""},
		{"owner with a trailing slash, another owner", with(func(s *report.Signer) { s.SourceRepositoryOwner = "https://github.com/acme/" }),
			report.Signer{Identity: reusable, Issuer: ghIssuer, SourceRepository: "https://github.com/acme-evil/x"}, "", "not a repository of"},
		{"another owner", with(func(s *report.Signer) { s.SourceRepositoryOwner = "https://github.com/acme" }),
			report.Signer{Identity: reusable, Issuer: ghIssuer, SourceRepository: "https://github.com/acme-evil/x"}, "", "not a repository of"},
		{"owner, no repository named", with(func(s *report.Signer) { s.SourceRepositoryOwner = "https://github.com/acme" }),
			report.Signer{Identity: reusable, Issuer: ghIssuer}, "", "not a repository of"},
		{"image source", with(func(s *report.Signer) { s.SourceMatchesImage = true }), cert, "https://github.com/acme/checkout.git", ""},
		{"image source, none", with(func(s *report.Signer) { s.SourceMatchesImage = true }), cert, "", "names no source"},
		{"image source, another", with(func(s *report.Signer) { s.SourceMatchesImage = true }), cert, "https://github.com/acme/billing", "signed in https://github.com/acme/checkout, not https://github.com/acme/billing"},
		{"image source, no repository named", with(func(s *report.Signer) { s.SourceMatchesImage = true }),
			report.Signer{Identity: reusable, Issuer: ghIssuer}, "https://github.com/acme/checkout", "an unnamed repository"},
		{"image source, outside the owner", with(func(s *report.Signer) {
			s.SourceMatchesImage, s.SourceRepositoryOwner = true, "https://github.com/acme"
		}),
			cert, "https://github.com/mallory/x", "not a repository of"},
		{"ref", with(func(s *report.Signer) { s.SourceRef = "refs/heads/main" }), cert, "", ""},
		{"another ref", with(func(s *report.Signer) { s.SourceRef = "refs/heads/release" }), cert, "", "not refs/heads/release"},
		{"not GitHub", with(func(s *report.Signer) { s.SourceRepository = "https://gitlab.com/acme/a" }), cert, "", "not https://github.com/OWNER/REPO"},
	} {
		err := accepts(c.signer, c.cert, c.imageSource)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}

	flags, signer := exactFlags(cert)
	if strings.Join(flags, " ") != "--certificate-identity "+reusable+" --certificate-oidc-issuer "+ghIssuer+
		" --certificate-github-workflow-repository acme/checkout --certificate-github-workflow-ref refs/heads/main" || signer != cert {
		t.Errorf("exact flags %q, signer %+v", flags, signer)
	}
	// Outside GitHub Actions, cosign can check only identity and issuer, so
	// the signer named is only that.
	flags, signer = exactFlags(report.Signer{Identity: "https://gitlab.com/acme/a//.gitlab-ci.yml@refs/heads/main", Issuer: "https://gitlab.com", SourceRepository: "https://gitlab.com/acme/a"})
	if len(flags) != 4 || signer.SourceRepository != "" {
		t.Errorf("gitlab flags %q, signer %+v", flags, signer)
	}
	if _, err := signerFlags(report.Signer{IdentityRegexp: "^https://gitlab\\.com/acme/", Issuer: "https://gitlab.com", SourceRepository: "https://github.com/acme/a"}); err == nil {
		t.Error("accepted source constraints without the GitHub issuer")
	}
}

// TestReusableWorkflowSigner verifies images signed by a reusable workflow.
// checkout was built in its own repository; spoof claims to be checkout but
// was built by a run in mallory's repository, calling the same workflow.
func TestReusableWorkflowSigner(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	reusableAcme := "https://github.com/acme/factory/.github/workflows/images.yml@refs/tags/v1"
	for repo, caller := range map[string]string{"checkout": "https://github.com/acme/checkout", "spoof": "https://github.com/mallory/evil"} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		cf, _ := img.ConfigFile()
		cf = cf.DeepCopy()
		cf.OS, cf.Architecture = "linux", "amd64"
		cf.Config.Labels = map[string]string{"org.opencontainers.image.source": "https://github.com/acme/checkout"}
		if img, err = mutate.ConfigFile(img, cf); err != nil {
			t.Fatal(err)
		}
		r, _ := name.ParseReference(host + "/" + repo + ":1")
		if err := remote.Write(r, img); err != nil {
			t.Fatal(err)
		}
		d := descriptorOf(t, img)
		attach(t, host+"/"+repo, v1.Descriptor{MediaType: d.MediaType, Digest: d.Digest, Size: d.Size},
			bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, fulcioCertFrom(t, reusableAcme, ghIssuer, caller)))
	}
	signature := func(signer report.Signer) map[string]report.EvidenceItem {
		signer.IdentityRegexp, signer.Issuer = `^https://github\.com/acme/factory/\.github/workflows/images\.yml@`, ghIssuer
		v := acmeVerifier()
		v.Signers = []report.Signer{signer}
		r, err := Build(context.Background(), observe(t, host, "checkout:1", "spoof:1"), Options{
			Name: "reusable", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: v,
			Policy: report.Policy{Required: []string{"signature"}, TrustedSigners: v.Signers},
		})
		if err != nil {
			t.Fatal(err)
		}
		validateReport(t, r)
		out := map[string]report.EvidenceItem{}
		for _, i := range r.Images {
			out[i.ID] = i.Evidence.Signature
		}
		return out
	}

	// Trusting the workflow alone trusts every caller: neither is verified.
	got := signature(report.Signer{})
	for _, id := range []string{"checkout", "spoof"} {
		if got[id].Status != "present" || !strings.Contains(got[id].Detail, "called from") {
			t.Errorf("unconstrained, %s: %+v", id, got[id])
		}
	}
	if got["checkout"].Signer == nil || got["checkout"].Signer.SourceRepository != "https://github.com/acme/checkout" {
		t.Errorf("the signer's repository isn't reported: %+v", got["checkout"].Signer)
	}
	for _, s := range []report.Signer{{SourceRepositoryOwner: "https://github.com/acme"}, {SourceMatchesImage: true}} {
		got := signature(s)
		if got["checkout"].Status != "verified" || got["spoof"].Status != "failed" {
			t.Errorf("%+v: checkout %+v, spoof %+v", s, got["checkout"], got["spoof"])
		}
	}
}
