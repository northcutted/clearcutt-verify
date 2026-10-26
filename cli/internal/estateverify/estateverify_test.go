package estateverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

const (
	ghIssuer   = "https://token.actions.githubusercontent.com"
	ourSigner  = "https://github.com/acme/images/.github/workflows/images.yml@refs/heads/main"
	evilSigner = "https://github.com/mallory/images/.github/workflows/x.yml@refs/heads/main"
)

// fulcioCert makes a certificate shaped like Fulcio's: the identity as a URI
// SAN, the issuer in the v2 extension, and for GitHub Actions the repository
// whose run signed (the workflow's own).
func fulcioCert(t *testing.T, identity, issuer string) string {
	t.Helper()
	repo := ""
	if rest, ok := strings.CutPrefix(identity, "https://github.com/"); ok && issuer == ghIssuer {
		parts := strings.SplitN(rest, "/", 3)
		repo = "https://github.com/" + parts[0] + "/" + parts[1]
	}
	return fulcioCertFrom(t, identity, issuer, repo)
}

// fulcioCertFrom also names the repository whose run signed (the Source
// Repository URI extension), as GitHub Actions certificates do.
func fulcioCertFrom(t *testing.T, identity, issuer, sourceRepo string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(identity)
	iss, _ := asn1.Marshal(issuer)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		URIs:            []*url.URL{u},
		ExtraExtensions: []pkix.Extension{{Id: oidIssuerV2, Value: iss}},
	}
	if sourceRepo != "" {
		v, _ := asn1.MarshalWithParams(sourceRepo, "utf8")
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidSourceRepository, Value: v},
			pkix.Extension{Id: oidSourceRef, Value: mustUTF8("refs/heads/main")})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func mustUTF8(v string) []byte {
	b, _ := asn1.MarshalWithParams(v, "utf8")
	return b
}

// bundleJSON is a Sigstore bundle holding an in-toto statement.
func bundleJSON(t *testing.T, predicateType, subjectDigest string, predicate any, cert string) []byte {
	t.Helper()
	return bundleAt(t, predicateType, subjectDigest, predicate, cert, 1791200000)
}

// bundleAt is a bundle whose transparency log entry says it was logged at
// integratedTime (which nothing verifies but cosign).
func bundleAt(t *testing.T, predicateType, subjectDigest string, predicate any, cert string, integratedTime int64) []byte {
	t.Helper()
	st, _ := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "x", "digest": map[string]string{"sha256": strings.TrimPrefix(subjectDigest, "sha256:")}}},
		"predicateType": predicateType,
		"predicate":     predicate,
	})
	b, _ := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{"rawBytes": cert},
			"tlogEntries": []any{map[string]string{"integratedTime": fmt.Sprint(integratedTime)}},
		},
		"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(st), "payloadType": "application/vnd.in-toto+json"},
	})
	return b
}

func TestDecodeBundle(t *testing.T) {
	cert := fulcioCert(t, ourSigner, ghIssuer)
	f, err := decodeBundle(bundleJSON(t, "https://cyclonedx.org/bom", "sha256:"+strings.Repeat("a", 64), map[string]any{"bomFormat": "CycloneDX"}, cert))
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != KindSBOM || f.Subject != "sha256:"+strings.Repeat("a", 64) || f.Signer == nil || f.Signer.Identity != ourSigner || f.Signer.Issuer != ghIssuer {
		t.Errorf("decoded %+v (signer %+v)", f, f.Signer)
	}
	if f.Timestamp != time.Unix(1791200000, 0).UTC().Format(time.RFC3339) {
		t.Errorf("timestamp %q", f.Timestamp)
	}
}

func TestKindOf(t *testing.T) {
	for pt, want := range map[string]string{
		PredicateCosignSign:                               KindSignature,
		"https://spdx.dev/Document":                       KindSBOM,
		"https://cyclonedx.org/bom/v1.6":                  KindSBOM,
		PredicateVuln:                                     KindVulnerabilityScan,
		"https://slsa.dev/provenance/v1":                  KindProvenance,
		"https://slsa.dev/provenance/v0.2":                KindProvenance,
		PredicateRecipe:                                   KindRecipe,
		legacyPredicateRebase:                             KindRebase,
		"https://in-toto.io/attestation/test-result/v0.1": KindTests,
		PredicateReproduction:                             KindReproduction,
		"https://apko.dev/image-configuration":            "",
	} {
		if got := KindOf(pt); got != want {
			t.Errorf("KindOf(%s) = %q, want %q", pt, got, want)
		}
	}
}

func TestSignerFlags(t *testing.T) {
	for _, c := range []struct {
		signer report.Signer
		want   string
	}{
		{report.Signer{IdentityRegexp: ".*", Issuer: ghIssuer}, "wildcard"},
		{report.Signer{IdentityRegexp: "^https://github.com/.*", Issuer: ghIssuer}, "wildcard"},
		// Not anchored, and any owner.
		{report.Signer{IdentityRegexp: `https://github\.com/.*`, Issuer: ghIssuer}, "wildcard"},
		{report.Signer{IdentityRegexp: `^https://github\.com/[^/]+/images/`, Issuer: ghIssuer}, "wildcard"},
		{report.Signer{IdentityRegexp: `^https://github\.com/(acme|[a-z-]+)/`, Issuer: ghIssuer}, "wildcard"},
		// acme-evil is another owner.
		{report.Signer{IdentityRegexp: `^https://github\.com/acme`, Issuer: ghIssuer}, "acmeclearcuttprobe"},
		{report.Signer{IdentityRegexp: `^https://github\.com/northcutted(-[a-z]+)?/`, Issuer: ghIssuer}, "northcutted-clearcuttprobe/"},
		{report.Signer{IdentityRegexp: `^https://github\.com/[^/]*northcutted/`, Issuer: ghIssuer}, "clearcuttprobenorthcutted/"},
		// An unescaped dot matches other owners too.
		{report.Signer{IdentityRegexp: `^https://github\.com/north.utted/`, Issuer: ghIssuer}, "wildcard"},
		// Other forges' owners end too.
		{report.Signer{IdentityRegexp: `^https://gitlab\.com/acme`, Issuer: "https://gitlab.com"}, "gitlab.com/acmeclearcuttprobe"},
		// An email domain that goes on is someone else's.
		{report.Signer{IdentityRegexp: `^.*@acme\.com`, Issuer: "https://accounts.google.com"}, "acme.com.clearcuttprobe.example"},
		{report.Signer{IdentityRegexp: `^https://github\.com/acme.*/`, Issuer: ghIssuer}, "wildcard"},
		{report.Signer{IdentityRegexp: `https://github\.com/acme/`, Issuer: ghIssuer}, "unanchored"},
		{report.Signer{IdentityRegexp: `(?m)^https://github\.com/acme/`, Issuer: ghIssuer}, "unanchored"},
		{report.Signer{IdentityRegexp: `^https://github\.com/acme/(`, Issuer: ghIssuer}, "missing closing"},
		{report.Signer{Identity: ourSigner}, "no OIDC issuer"},
	} {
		if _, err := signerFlags(c.signer); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.signer, err, c.want)
		}
	}
	for _, re := range []string{
		`^https://github\.com/acme/`,
		`^https://github\.com/(acme|acme-labs)/`,
		`^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v`,
		`^https://github\.com/acme/images/\.github/workflows/release\.yml@refs/heads/main$`,
		`^(https://github\.com/acme/|https://gitlab\.com/acme/)`,
		`^https://github\.com/acme-(dev|prod)/images/`,
		`^.*@acme\.com$`,
		`^alice@acme\.com$`,
	} {
		if _, err := signerFlags(report.Signer{IdentityRegexp: re, Issuer: ghIssuer}); err != nil {
			t.Errorf("refused %s: %v", re, err)
		}
	}
	got, err := signerFlags(report.Signer{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer})
	if err != nil || strings.Join(got, " ") != `--certificate-identity-regexp ^https://github\.com/acme/ --certificate-oidc-issuer `+ghIssuer {
		t.Errorf("flags %v, %v", got, err)
	}
	if got, _ := signerFlags(report.Signer{Key: "cosign.pub"}); strings.Join(got, " ") != "--key cosign.pub" {
		t.Errorf("key flags %v", got)
	}
	no, yes := false, true
	if got, _ := signerFlags(report.Signer{Key: "cosign.pub", Tlog: &no}); strings.Join(got, " ") != "--key cosign.pub --insecure-ignore-tlog=true" {
		t.Errorf("key flags without a transparency log %v", got)
	}
	if got, _ := signerFlags(report.Signer{Key: "cosign.pub", Tlog: &yes}); strings.Join(got, " ") != "--key cosign.pub" {
		t.Errorf("key flags with tlog: true %v", got)
	}
	// A keyless certificate is only as good as the log entry that dates it.
	if _, err := signerFlags(report.Signer{Identity: ourSigner, Issuer: ghIssuer, Tlog: &no}); err == nil || !strings.Contains(err.Error(), "applies to key signers") {
		t.Errorf("keyless signer without a transparency log: %v", err)
	}
}

// envelope is a DSSE envelope as cosign prints one it verified.
func envelope(t *testing.T, predicateType, digest string) []byte {
	t.Helper()
	st, _ := json.Marshal(map[string]any{"predicateType": predicateType,
		"subject": []any{map[string]any{"digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}}})
	env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": st})
	return append(env, '\n')
}

// TestVerifierVerifiesTheCertificatesSigner: cosign is asked for exactly the
// signer the certificate names, once a trusted signer accepts it, and only
// what it prints about this digest and type counts.
func TestVerifierVerifiesTheCertificatesSigner(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	var calls []string
	out := envelope(t, "https://cyclonedx.org/bom", digest)
	v := &Verifier{
		Signers: []report.Signer{{IdentityRegexp: `^https://github\.com/other/`, Issuer: ghIssuer}, {IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}},
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(args, " "))
			return out, nil
		},
	}
	cert := &report.Signer{Identity: ourSigner, Issuer: ghIssuer, SourceRepository: "https://github.com/acme/images", SourceRef: "refs/heads/main"}
	subj := Subject{Ref: "r@" + digest, Kind: KindSBOM, PredicateType: "https://cyclonedx.org/bom", Signer: cert}
	res, err := v.Verify(context.Background(), subj)
	if err != nil || res.Trusted.IdentityRegexp != `^https://github\.com/acme/` || res.Signer != *cert || len(res.Statements) != 1 {
		t.Fatalf("verify: %+v, %v", res, err)
	}
	want := "verify-attestation --type https://cyclonedx.org/bom --output json --certificate-identity " + ourSigner + " --certificate-oidc-issuer " + ghIssuer +
		" --certificate-github-workflow-repository acme/images --certificate-github-workflow-ref refs/heads/main r@" + digest
	if len(calls) != 1 || calls[0] != want {
		t.Errorf("calls %q", calls)
	}

	// cosign's output is about another digest, or another type: nothing verified.
	for _, o := range [][]byte{envelope(t, "https://cyclonedx.org/bom", "sha256:"+strings.Repeat("b", 64)), envelope(t, PredicateVuln, digest), []byte("not json")} {
		out = o
		if _, err := v.Verify(context.Background(), subj); err == nil {
			t.Errorf("verified %s", o)
		}
	}
	// A certificate no trusted signer accepts isn't run past cosign.
	calls = nil
	subj.Signer = &report.Signer{Identity: evilSigner, Issuer: ghIssuer}
	if _, err := v.Verify(context.Background(), subj); err == nil || !strings.Contains(err.Error(), "doesn't match") || len(calls) != 0 {
		t.Errorf("untrusted signer: %v (calls %q)", err, calls)
	}
	subj.Signer = nil
	if _, err := v.Verify(context.Background(), subj); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("no certificate: %v", err)
	}
	// A signature over another digest, or a bundle of another type, isn't
	// a signature over this image.
	subj.Kind, subj.Signer = KindSignature, cert
	for o, ok := range map[string]bool{
		`[{"critical":{"image":{"docker-manifest-digest":"` + digest + `"},"type":"cosign container image signature"}}]`:                    true,
		`[{"critical":{"image":{"docker-manifest-digest":"` + digest + `"},"type":"` + PredicateCosignSign + `"}}]`:                         true,
		`[{"critical":{"image":{"docker-manifest-digest":"` + digest + `"},"type":"https://cyclonedx.org/bom"}}]`:                           false,
		`[{"critical":{"image":{"docker-manifest-digest":"sha256:` + strings.Repeat("b", 64) + `"},"type":"` + PredicateCosignSign + `"}}]`: false,
	} {
		out = []byte(o)
		if _, err := v.Verify(context.Background(), subj); (err == nil) != ok {
			t.Errorf("signature %s: %v", o, err)
		}
	}
	// Keys verify evidence with no certificate.
	kv := &Verifier{Signers: []report.Signer{{Key: "cosign.pub"}}, Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "--key cosign.pub") {
			return nil, errors.New("no key")
		}
		return envelope(t, "https://cyclonedx.org/bom", digest), nil
	}}
	if res, err := kv.Verify(context.Background(), Subject{Ref: "r@" + digest, Kind: KindSBOM, PredicateType: "https://cyclonedx.org/bom"}); err != nil || res.Signer.Key != "cosign.pub" {
		t.Errorf("key: %+v %v", res, err)
	}
	if _, err := (&Verifier{}).Verify(context.Background(), Subject{Ref: "r@sha256:x", Kind: KindSignature}); !errors.Is(err, ErrNoSigner) {
		t.Errorf("no signers: %v", err)
	}
}

func grypeMatchJSON(id, sev, pkgName, version string, fix ...string) map[string]any {
	return map[string]any{
		"vulnerability": map[string]any{"id": id, "severity": sev, "fix": map[string]any{"versions": fix}},
		"artifact":      map[string]any{"name": pkgName, "version": version},
	}
}

func vulnPredicate(matches, ignored []map[string]any) map[string]any {
	if matches == nil {
		matches = []map[string]any{} // grype lists no matches as []
	}
	return map[string]any{
		"scanner": map[string]any{"uri": "pkg:github/anchore/grype@0.118.0", "version": "0.118.0",
			"result": map[string]any{"matches": matches, "ignoredMatches": ignored, "descriptor": map[string]string{"name": "grype", "version": "0.118.0"}}},
		"metadata": map[string]string{"scanStartedOn": "2026-10-05T21:39:00Z", "scanFinishedOn": "2026-10-05T21:39:15Z"},
	}
}

func TestMergeVulnerabilities(t *testing.T) {
	read := func(p map[string]any) vulnScan {
		b, _ := json.Marshal(p)
		s, err := readVulnPredicate(b)
		if err != nil {
			t.Fatalf("unreadable predicate: %v", err)
		}
		return s
	}
	amd := read(vulnPredicate([]map[string]any{grypeMatchJSON("CVE-1", "High", "openssl", "3.0", "3.1"), grypeMatchJSON("CVE-2", "Medium", "zlib", "1.3")},
		[]map[string]any{grypeMatchJSON("CVE-3", "Critical", "glibc", "2.40")}))
	arm := read(vulnPredicate([]map[string]any{grypeMatchJSON("CVE-1", "High", "openssl", "3.0", "3.1")}, nil))
	v := mergeVulnerabilities(map[string]vulnScan{"linux/amd64": amd, "linux/arm64": arm})
	if v.Scanner != "grype 0.118.0" || v.ScannedAt != "2026-10-05T21:39:15Z" {
		t.Errorf("scanner %q at %q", v.Scanner, v.ScannedAt)
	}
	if v.Counts.High != 1 || v.Counts.Medium != 1 || v.Counts.Critical != 0 || v.Fixable.High != 1 || v.Fixable.Medium != 0 {
		t.Errorf("counts %+v fixable %+v", v.Counts, v.Fixable)
	}
	if len(v.Findings) != 3 || v.Findings[0].ID != "CVE-3" || !v.Findings[0].Suppressed || strings.Join(v.Findings[1].Platforms, ",") != "linux/amd64,linux/arm64" {
		t.Errorf("findings %+v", v.Findings)
	}
}

func TestReadSBOM(t *testing.T) {
	cdx := `{"bomFormat":"CycloneDX","components":[
	  {"type":"library","name":"jq","version":"1.8.1","purl":"pkg:apk/wolfi/jq@1.8.1?arch=x86_64"},
	  {"type":"file","name":"/etc/passwd"},
	  {"type":"library","name":"golang.org/x/net","version":"v0.38.0","purl":"pkg:golang/golang.org/x/net@v0.38.0"}]}`
	pkgs, ok := readSBOM(json.RawMessage(cdx))
	if !ok || len(pkgs) != 2 || pkgs[0].Type != "apk" || pkgs[1].Type != "golang" {
		t.Errorf("cyclonedx: %+v %v", pkgs, ok)
	}
	spdx := `{"spdxVersion":"SPDX-2.3","packages":[{"name":"ca-certificates","versionInfo":"2026","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/wolfi/ca-certificates@2026"}]},{"name":"no-purl"}]}`
	if pkgs, ok := readSBOM(json.RawMessage(spdx)); !ok || len(pkgs) != 1 || pkgs[0].Name != "ca-certificates" {
		t.Errorf("spdx: %+v %v", pkgs, ok)
	}
}

func recipePredicate(baseDigest string) map[string]any {
	return map[string]any{
		"factory":  map[string]string{"version": "v0.1.0"},
		"build":    map[string]any{"sourceDateEpoch": 1790985600},
		"manifest": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata:\n  name: hello\nstack:\n  metadata:\n    name: go\n",
		"lock": "builder:\n  buildkit: {ref: moby/buildkit, digest: sha256:b}\n  frontend: {ref: docker/dockerfile, digest: sha256:f}\n" +
			"base:\n  ref: base:latest\n  digest: " + baseDigest + "\napp:\n  build: {ref: golang:1, digest: sha256:c}\n",
	}
}

func TestReadRecipe(t *testing.T) {
	b, _ := json.Marshal(recipePredicate("sha256:" + strings.Repeat("e", 64)))
	f, base, ok := readRecipe(b)
	if !ok || f.Kind != "App" || f.Name != "hello" || f.Stack != "go" || f.Version != "v0.1.0" || f.SourceDateEpoch != 1790985600 {
		t.Fatalf("recipe %+v %v", f, ok)
	}
	if base == nil || base.Ref != "base:latest" || f.Inputs == nil || f.Inputs.Images != 4 {
		t.Errorf("base %+v inputs %+v", base, f.Inputs)
	}
}

func TestReadProvenanceSource(t *testing.T) {
	p := `{"buildDefinition":{"externalParameters":{"workflow":{"repository":"https://github.com/acme/images","ref":"refs/heads/main"}},
	  "resolvedDependencies":[{"uri":"git+https://github.com/acme/images@refs/heads/main","digest":{"gitCommit":"5a95adf"}}]}}`
	s, ok := readProvenanceSource(json.RawMessage(p))
	if !ok || s.URL != "https://github.com/acme/images" || s.Revision != "5a95adf" || s.Basis != "provenance" {
		t.Errorf("source %+v %v", s, ok)
	}
}

func TestReadProvenanceDetails(t *testing.T) {
	for raw, want := range map[string]*report.Provenance{
		`{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1"},"runDetails":{"builder":{"id":"https://github.com/actions/runner"}}}`: {
			BuilderID: "https://github.com/actions/runner", BuildType: "https://actions.github.io/buildtypes/workflow/v1"},
		// SLSA v0.2.
		`{"builder":{"id":"https://ci.example/b"},"buildType":"https://ci.example/t"}`: {BuilderID: "https://ci.example/b", BuildType: "https://ci.example/t"},
		`{"buildDefinition":{"buildType":"https://ci.example/t"}}`:                     {BuildType: "https://ci.example/t"},
		`{}`: nil,
		`[`:  nil,
	} {
		got := readProvenanceDetails(json.RawMessage(raw))
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%s: %+v, want %+v", raw, got, want)
		}
	}
}

func TestVerdict(t *testing.T) {
	ok := report.EvidenceItem{Status: "verified"}
	// A rebased image: its verified rebase record stands in for the recipe.
	img := report.Image{Evidence: report.Evidence{Signature: ok, SBOM: ok, VulnerabilityScan: ok, Provenance: ok,
		Recipe: report.EvidenceItem{Status: "not-applicable"}, Rebase: ok, Tests: report.EvidenceItem{Status: "missing"}},
		Vulnerabilities: &report.Vulnerabilities{Findings: []report.Finding{{ID: "CVE-1", Severity: "critical"}}}}
	acme := []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}
	p := report.Policy{Required: []string{"signature", "sbom", "recipe"}, TrustedSigners: acme, FailOn: "critical", OnlyFixed: true}
	if v := verdict(img, p); v.Status != "verified" {
		t.Errorf("unfixable critical with onlyFixed: %+v", v)
	}
	p.OnlyFixed = false
	if v := verdict(img, p); v.Status != "failed" || !strings.Contains(v.Reasons[0], "1 vulnerabilities at critical") {
		t.Errorf("critical without onlyFixed: %+v", v)
	}
	p.FailOn = ""
	img.Evidence.SBOM = report.EvidenceItem{Status: "present"}
	if v := verdict(img, p); v.Status != "unverified" {
		t.Errorf("present sbom: %+v", v)
	}
	img.Evidence.Signature = report.EvidenceItem{Status: "failed"}
	if v := verdict(img, p); v.Status != "failed" || len(v.Reasons) != 2 {
		t.Errorf("failed signature: %+v", v)
	}
	p = report.Policy{MaxDaysBehind: 7, TrustedSigners: acme}
	img.Base = &report.BaseLink{DaysBehind: 9, Drift: "stale", Strength: "proof", Method: "layer-prefix"}
	if v := verdict(img, p); v.Status != "failed" {
		t.Errorf("stale base: %+v", v)
	}
	img.Base = nil
	if v := verdict(img, p); v.Status != "unverified" || !strings.Contains(v.Reasons[0], "couldn't be measured") {
		t.Errorf("unresolved base: %+v", v)
	}
	img.Root = "other images are built on it"
	if v := verdict(img, p); v.Status != "verified" {
		t.Errorf("root: %+v", v)
	}
}

// built is when test images were created, unless a test says otherwise.
var built = time.Unix(1790985600, 0)

// pushIndex pushes an amd64+arm64 index whose images start with base's
// layers (when base is set) and adds one layer.
func pushIndex(t *testing.T, ref string, base v1.ImageIndex, created time.Time, anns func(arch string) map[string]string) v1.ImageIndex {
	t.Helper()
	var adds []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "arm64"} {
		img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON)
		if base != nil {
			im, _ := base.IndexManifest()
			for _, d := range im.Manifests {
				if d.Platform.Architecture == arch {
					img, _ = base.Image(d.Digest)
				}
			}
		}
		l, err := random.Layer(64, types.OCILayer)
		if err != nil {
			t.Fatal(err)
		}
		if img, err = mutate.AppendLayers(img, l); err != nil {
			t.Fatal(err)
		}
		cf, _ := img.ConfigFile()
		cf = cf.DeepCopy()
		cf.OS, cf.Architecture = "linux", arch
		cf.Created = v1.Time{Time: created}
		if img, err = mutate.ConfigFile(img, cf); err != nil {
			t.Fatal(err)
		}
		if anns != nil {
			img = mutate.Annotations(img, anns(arch)).(v1.Image)
		}
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	idx := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, adds...), types.OCIImageIndex)
	r, _ := name.ParseReference(ref)
	if err := remote.WriteIndex(r, idx); err != nil {
		t.Fatal(err)
	}
	return idx
}

// attach pushes a Sigstore bundle as a referrer of repo@subject, the way
// cosign v3 does (empty config, bundle layer, subject), and returns where.
func attach(t *testing.T, repo string, subject v1.Descriptor, bundle []byte) string {
	t.Helper()
	img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), "application/vnd.oci.empty.v1+json")
	img, err := mutate.Append(img, mutate.Addendum{Layer: static.NewLayer(bundle, "application/vnd.dev.sigstore.bundle.v0.3+json")})
	if err != nil {
		t.Fatal(err)
	}
	withSubject := mutate.Subject(img, subject).(v1.Image)
	d, _ := withSubject.Digest()
	r, _ := name.ParseReference(repo + "@" + d.String())
	if err := remote.Write(r, withSubject); err != nil {
		t.Fatal(err)
	}
	return r.String()
}

func descriptorOf(t *testing.T, w partial.Describable) v1.Descriptor {
	t.Helper()
	d, err := partial.Descriptor(w)
	if err != nil {
		t.Fatal(err)
	}
	return *d
}

// acmeVerifier stands in for cosign: only evidence signed by acme verifies,
// except the forged copies (attachments by reference), whose certificates
// no certificate authority issued.
func acmeVerifier(forged ...string) *Verifier {
	fake := map[string]bool{}
	for _, f := range forged {
		fake[f] = true
	}
	return &Verifier{
		Signers: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}},
		Run: func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			return fakeCosign(ctx, fake, args)
		},
	}
}

// fakeCosign verifies the way cosign does: every attached copy whose
// certificate is genuine (acme's, and not forged) and matches the flags, and
// it prints what it verified (a JSON array of signed payloads for verify, a
// DSSE envelope per line for verify-attestation).
func fakeCosign(ctx context.Context, forged map[string]bool, args []string) ([]byte, error) {
	ref := args[len(args)-1]
	repo, digest, _ := strings.Cut(ref, "@")
	flag := func(name string) string {
		for i := 0; i+1 < len(args)-1; i++ {
			if args[i] == name {
				return args[i+1]
			}
		}
		return ""
	}
	found, err := (&Discoverer{}).Discover(ctx, repo, digest)
	if err != nil {
		return nil, err
	}
	var sigs []map[string]any
	var out bytes.Buffer
	key := flag("--key")
	for _, f := range found {
		s := f.Signer
		switch {
		case f.Format == FormatRawReferrer || forged[f.Ref]:
			continue
		case key != "":
			// Key-signed copies carry no certificate; acme's key signed them.
			if s != nil && s.Key == "" || !strings.HasSuffix(key, "acme.pub") {
				continue
			}
		case s == nil || !strings.HasPrefix(s.Identity, "https://github.com/acme/"):
			continue
		}
		if id := flag("--certificate-identity"); id != "" && s.Identity != id {
			continue
		}
		if re := flag("--certificate-identity-regexp"); re != "" && !regexp.MustCompile(re).MatchString(s.Identity) {
			continue
		}
		if iss := flag("--certificate-oidc-issuer"); iss != "" && s.Issuer != iss {
			continue
		}
		if r := flag("--certificate-github-workflow-repository"); r != "" && s.SourceRepository != "https://github.com/"+r {
			continue
		}
		if r := flag("--certificate-github-workflow-ref"); r != "" && s.SourceRef != r {
			continue
		}
		if args[0] == "verify" {
			// cosign v3 accepts a bundle of any type as a signature.
			typ := f.PredicateType
			if f.Format == FormatCosignTag && f.Kind == KindSignature {
				typ = cosignImageSignature
			}
			sigs = append(sigs, map[string]any{"critical": map[string]any{"image": map[string]string{"docker-manifest-digest": firstNonEmpty(f.Subject, digest)}, "type": typ}})
			continue
		}
		if f.PredicateType != flag("--type") {
			continue
		}
		env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": f.Statement, "signatures": []any{}})
		out.Write(append(env, '\n'))
	}
	if args[0] == "verify" {
		if len(sigs) == 0 {
			return nil, errors.New("no matching signatures")
		}
		b, _ := json.Marshal(sigs)
		return append(b, '\n'), nil
	}
	if out.Len() == 0 {
		return nil, errors.New("no matching attestations")
	}
	return out.Bytes(), nil
}

// observe reads images from the test registry, named by repository.
func observe(t *testing.T, host string, refs ...string) estategraph.Observations {
	t.Helper()
	var observations estategraph.Observations
	repos := map[string]int{}
	for _, ref := range refs {
		repo, _, _ := strings.Cut(ref, ":")
		repos[repo]++
	}
	for _, ref := range refs {
		obs, err := estategraph.RegistryObserver{}.Observe(context.Background(), host+"/"+ref)
		if err != nil {
			t.Fatal(err)
		}
		// IDs are URL path segments: the repository, with the tag when the
		// repository is listed more than once.
		repo, tag, _ := strings.Cut(ref, ":")
		obs.ID = strings.ReplaceAll(repo, "/", "-")
		if repos[repo] > 1 {
			obs.ID += "-" + tag
		}
		observations.Images = append(observations.Images, obs)
	}
	return observations
}

// validateReport checks a report against the contract.
func validateReport(t *testing.T, r *report.Report) {
	t.Helper()
	raw, _ := json.Marshal(r)
	schema, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "..", "contract", "estate-report.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err := schema.Validate(inst); err != nil {
		t.Errorf("report doesn't match the contract: %v", err)
	}
	if os.Getenv("DUMP") != "" {
		fmt.Println(string(raw))
	}
}

// TestBuild verifies a small estate in a registry: a base, a factory app on
// it with signed evidence, and an unsigned image; the report must match the
// contract.
func TestBuild(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ctx := context.Background()

	base := pushIndex(t, host+"/base:latest", nil, built, nil)
	baseIdx, _ := base.Digest()
	baseIM, _ := base.IndexManifest()
	app := pushIndex(t, host+"/app:1", base, built, func(arch string) map[string]string {
		for _, d := range baseIM.Manifests {
			if d.Platform.Architecture == arch {
				return map[string]string{"org.opencontainers.image.base.name": host + "/base:latest", "org.opencontainers.image.base.digest": d.Digest.String()}
			}
		}
		return nil
	})
	pushIndex(t, host+"/other:1", nil, built, nil)

	ours, evil := fulcioCert(t, ourSigner, ghIssuer), fulcioCert(t, evilSigner, ghIssuer)
	appDesc := descriptorOf(t, app)
	appIdx := appDesc.Digest.String()
	attach(t, host+"/app", appDesc, bundleJSON(t, PredicateCosignSign, appIdx, map[string]any{}, ours))
	attach(t, host+"/app", appDesc, bundleJSON(t, PredicateRecipe, appIdx, recipePredicate(baseIdx.String()), ours))
	attach(t, host+"/app", appDesc, bundleJSON(t, "https://slsa.dev/provenance/v1", appIdx, map[string]any{}, evil))
	im, _ := app.IndexManifest()
	for _, d := range im.Manifests {
		attach(t, host+"/app", d, bundleJSON(t, "https://cyclonedx.org/bom", d.Digest.String(), map[string]any{"bomFormat": "CycloneDX",
			"components": []any{map[string]string{"type": "library", "name": "openssl", "version": "3.0", "purl": "pkg:apk/wolfi/openssl@3.0?arch=" + d.Platform.Architecture}}}, ours))
		attach(t, host+"/app", d, bundleJSON(t, PredicateVuln, d.Digest.String(), vulnPredicate([]map[string]any{grypeMatchJSON("CVE-1", "High", "openssl", "3.0", "3.1")}, nil), ours))
	}

	verifier := acmeVerifier()
	observations := observe(t, host, "base:latest", "app:1", "other:1")
	r, err := Build(ctx, observations, Options{
		Name: "test", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{Required: []string{"signature", "sbom", "vulnerabilityScan", "recipe"}, TrustedSigners: verifier.Signers, FailOn: "high", OnlyFixed: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}

	a := img["app"]
	if a.Evidence.Signature.Status != "verified" || a.Evidence.SBOM.Status != "verified" || a.Evidence.VulnerabilityScan.Status != "verified" || a.Evidence.Recipe.Status != "verified" {
		t.Errorf("app evidence: %+v", a.Evidence)
	}
	if a.Evidence.Provenance.Status != "failed" || a.Evidence.Provenance.Signer == nil || a.Evidence.Provenance.Signer.Identity != evilSigner {
		t.Errorf("provenance signed by someone else: %+v", a.Evidence.Provenance)
	}
	if a.Evidence.SBOM.Platforms["linux/arm64"] != "verified" || a.Evidence.Rebase.Status != "not-applicable" || a.Evidence.Tests.Status != "missing" {
		t.Errorf("app evidence details: %+v", a.Evidence)
	}
	if a.Base == nil || a.Base.Strength != "proof" || a.Base.ImageID != "base" || a.Base.Drift != "current" {
		t.Errorf("app base: %+v", a.Base)
	}
	if a.Builder.Kind != "clearcutt-factory" || a.Factory == nil || a.Factory.Name != "hello" || a.Factory.Stack != "go" {
		t.Errorf("app factory: %+v %+v", a.Builder, a.Factory)
	}
	if ps := a.PackagesSource; ps == nil || ps.Evidence != "sbom" || ps.Status != "verified" || strings.Join(ps.Platforms, ",") != "linux/amd64,linux/arm64" {
		t.Errorf("app packages source: %+v", a.PackagesSource)
	}
	if a.Vulnerabilities == nil || a.Vulnerabilities.Counts.High != 1 || len(a.Vulnerabilities.Findings[0].Platforms) != 2 {
		t.Errorf("app vulnerabilities: %+v", a.Vulnerabilities)
	}
	if a.Verdict.Status != "failed" || !strings.Contains(strings.Join(a.Verdict.Reasons, ";"), "1 fixable vulnerabilities at high") {
		t.Errorf("app verdict: %+v", a.Verdict)
	}
	if a.Reproducibility.Status != "not-checked" || a.Reproducibility.Method != "recipe-rebuild" {
		t.Errorf("app reproducibility: %+v", a.Reproducibility)
	}
	o := img["other"]
	if o.Evidence.Signature.Status != "missing" || o.Verdict.Status != "failed" || o.Reproducibility.Status != "no-recipe" || o.Vulnerabilities != nil {
		t.Errorf("unsigned image: %+v %+v", o.Evidence.Signature, o.Verdict)
	}
	if img["base"].Root == "" {
		t.Errorf("base is not a root: %+v", img["base"])
	}
	if len(r.Packages) != 1 || r.Packages[0].PURL != "pkg:apk/wolfi/openssl@3.0" || strings.Join(r.Packages[0].Images, ",") != "app" {
		t.Errorf("packages %+v", r.Packages)
	}
	if r.Summary.Verdicts.Failed != 3 || r.Summary.Evidence["signature"].Verified != 1 || r.Summary.Vulnerabilities.Scanned != 1 || r.Summary.Bases.Proven != 1 {
		t.Errorf("summary %+v", r.Summary)
	}

	validateReport(t, r)
}

func TestVerdictScanAge(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	img := report.Image{Vulnerabilities: &report.Vulnerabilities{ScannedAt: "2026-10-01T00:00:00Z"},
		Evidence: report.Evidence{VulnerabilityScan: report.EvidenceItem{Status: "verified"}}}
	p := report.Policy{MaxScanAgeDays: 7, TrustedSigners: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}}
	if v := verdictAt(img, p, now); v.Status != "unverified" || !strings.Contains(v.Reasons[0], "9 days old (limit 7)") {
		t.Errorf("old scan: %+v", v)
	}
	p.MaxScanAgeDays = 14
	if v := verdictAt(img, p, now); v.Status != "verified" {
		t.Errorf("recent scan: %+v", v)
	}
	img.Vulnerabilities.ScannedAt = ""
	if v := verdictAt(img, p, now); v.Status != "unverified" || !strings.Contains(v.Reasons[0], "age is unknown") {
		t.Errorf("no scan time: %+v", v)
	}
	// With no verified scan there is no age to measure: unknown, not fresh.
	signed := report.Image{Evidence: report.Evidence{Signature: report.EvidenceItem{Status: "verified"}}}
	if v := verdictAt(signed, p, now); v.Status != "unverified" || !strings.Contains(v.Reasons[0], "age is unknown") {
		t.Errorf("no scan: %+v", v)
	}
	signed.Vulnerabilities = img.Vulnerabilities
	signed.Evidence.VulnerabilityScan.Status = "present"
	if v := verdictAt(signed, p, now); v.Status != "unverified" || !strings.Contains(v.Reasons[0], "age is unknown") {
		t.Errorf("scan not verified on every platform: %+v", v)
	}
}
