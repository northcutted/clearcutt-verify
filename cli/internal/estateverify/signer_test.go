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

	"github.com/northcutted/clearcutt/internal/report"
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

func TestCallerFlags(t *testing.T) {
	cert := &report.Signer{Identity: reusable, SourceRepository: "https://github.com/acme/checkout"}
	for _, c := range []struct {
		name   string
		signer report.Signer
		subj   Subject
		want   string // flags, or the error's text
	}{
		{"none", report.Signer{}, Subject{Signer: cert}, ""},
		{"exact", report.Signer{SourceRepository: "https://github.com/acme/checkout", SourceRef: "refs/heads/main"}, Subject{},
			"--certificate-github-workflow-repository acme/checkout --certificate-github-workflow-ref refs/heads/main"},
		{"owner, from the certificate", report.Signer{SourceRepositoryOwner: "https://github.com/acme"}, Subject{Signer: cert}, "--certificate-github-workflow-repository acme/checkout"},
		{"owner, another's", report.Signer{SourceRepositoryOwner: "https://github.com/acme"}, Subject{Signer: &report.Signer{SourceRepository: "https://github.com/acme-evil/x"}}, "not a repository of"},
		{"owner, unknown", report.Signer{SourceRepositoryOwner: "https://github.com/acme"}, Subject{}, "not a repository of"},
		{"image source", report.Signer{SourceMatchesImage: true}, Subject{ImageSource: "https://github.com/acme/checkout.git"}, "--certificate-github-workflow-repository acme/checkout"},
		{"image source, none", report.Signer{SourceMatchesImage: true}, Subject{}, "names no source"},
		{"image source, outside the owner", report.Signer{SourceMatchesImage: true, SourceRepositoryOwner: "https://github.com/acme"}, Subject{ImageSource: "https://github.com/mallory/x"}, "not a repository of"},
		{"image source, not the repository", report.Signer{SourceMatchesImage: true, SourceRepository: "https://github.com/acme/a"}, Subject{ImageSource: "https://github.com/acme/b"}, "not https://github.com/acme/a"},
		{"not GitHub", report.Signer{SourceRepository: "https://gitlab.com/acme/a"}, Subject{}, "not https://github.com/OWNER/REPO"},
	} {
		flags, err := callerFlags(c.signer, c.subj)
		got := strings.Join(flags, " ")
		if err != nil {
			got = err.Error()
		}
		if (c.want == "" && got != "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
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
