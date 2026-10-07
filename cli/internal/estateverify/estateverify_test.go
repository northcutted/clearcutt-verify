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
// SAN, the issuer in the v2 extension.
func fulcioCert(t *testing.T, identity, issuer string) string {
	t.Helper()
	return fulcioCertFrom(t, identity, issuer, "")
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
			"tlogEntries": []any{map[string]string{"integratedTime": "1791200000"}},
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
		"https://apko.dev/image-configuration":            "",
	} {
		if got := KindOf(pt); got != want {
			t.Errorf("KindOf(%s) = %q, want %q", pt, got, want)
		}
	}
}

func TestSignerFlags(t *testing.T) {
	for _, s := range []report.Signer{{IdentityRegexp: ".*", Issuer: ghIssuer}, {IdentityRegexp: "^https://github.com/.*", Issuer: ghIssuer}, {Identity: ourSigner}} {
		if _, err := signerFlags(s); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	got, err := signerFlags(report.Signer{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer})
	if err != nil || strings.Join(got, " ") != `--certificate-identity-regexp ^https://github\.com/acme/ --certificate-oidc-issuer `+ghIssuer {
		t.Errorf("flags %v, %v", got, err)
	}
	if got, _ := signerFlags(report.Signer{Key: "cosign.pub"}); strings.Join(got, " ") != "--key cosign.pub" {
		t.Errorf("key flags %v", got)
	}
}

func TestVerifierTriesEachSigner(t *testing.T) {
	var calls []string
	v := &Verifier{
		Signers: []report.Signer{{IdentityRegexp: `^https://github\.com/other/`, Issuer: ghIssuer}, {IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}},
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(args, " "))
			if strings.Contains(strings.Join(args, " "), "acme") {
				return nil, nil
			}
			return nil, errors.New("no matching signatures")
		},
	}
	s, err := v.Verify(context.Background(), Subject{Ref: "r@sha256:x", Kind: KindSBOM, PredicateType: "https://cyclonedx.org/bom"})
	if err != nil || s.IdentityRegexp != `^https://github\.com/acme/` {
		t.Fatalf("verify: %+v, %v", s, err)
	}
	if len(calls) != 2 || !strings.HasPrefix(calls[1], "verify-attestation --type https://cyclonedx.org/bom --output json") {
		t.Errorf("calls %q", calls)
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
	return map[string]any{
		"scanner": map[string]any{"uri": "pkg:github/anchore/grype@0.118.0", "version": "0.118.0",
			"result": map[string]any{"matches": matches, "ignoredMatches": ignored, "descriptor": map[string]string{"name": "grype", "version": "0.118.0"}}},
		"metadata": map[string]string{"scanStartedOn": "2026-10-05T21:39:00Z", "scanFinishedOn": "2026-10-05T21:39:15Z"},
	}
}

func TestMergeVulnerabilities(t *testing.T) {
	read := func(p map[string]any) vulnScan {
		b, _ := json.Marshal(p)
		s, ok := readVulnPredicate(b)
		if !ok {
			t.Fatal("unreadable predicate")
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

func TestVerdict(t *testing.T) {
	ok := report.EvidenceItem{Status: "verified"}
	img := report.Image{Evidence: report.Evidence{Signature: ok, SBOM: ok, VulnerabilityScan: ok, Provenance: ok,
		Recipe: report.EvidenceItem{Status: "not-applicable"}, Rebase: report.EvidenceItem{Status: "not-applicable"}, Tests: report.EvidenceItem{Status: "missing"}},
		Vulnerabilities: &report.Vulnerabilities{Findings: []report.Finding{{ID: "CVE-1", Severity: "critical"}}}}
	p := report.Policy{Required: []string{"signature", "sbom", "recipe"}, FailOn: "critical", OnlyFixed: true}
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
	p = report.Policy{MaxDaysBehind: 7}
	img.Base = &report.BaseLink{DaysBehind: 9, Drift: "stale"}
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
// cosign v3 does (empty config, bundle layer, subject).
func attach(t *testing.T, repo string, subject v1.Descriptor, bundle []byte) {
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
}

func descriptorOf(t *testing.T, w partial.Describable) v1.Descriptor {
	t.Helper()
	d, err := partial.Descriptor(w)
	if err != nil {
		t.Fatal(err)
	}
	return *d
}

// acmeVerifier stands in for cosign: only evidence signed by acme verifies.
func acmeVerifier() *Verifier {
	return &Verifier{
		Signers: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}},
		Run: func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			ref := args[len(args)-1]
			repo, digest, _ := strings.Cut(ref, "@")
			typ := PredicateCosignSign
			if args[0] == "verify-attestation" {
				typ = args[2]
			}
			caller := ""
			for i, a := range args {
				if a == "--certificate-github-workflow-repository" {
					caller = "https://github.com/" + args[i+1]
				}
			}
			found, err := (&Discoverer{}).Discover(ctx, repo, digest)
			if err != nil {
				return nil, err
			}
			for _, f := range found {
				if f.PredicateType == typ && f.Signer != nil && strings.HasPrefix(f.Signer.Identity, "https://github.com/acme/") &&
					(caller == "" || f.Signer.SourceRepository == caller) {
					return nil, nil
				}
			}
			return nil, errors.New("no matching signatures")
		},
	}
}

// observe reads images from the test registry, named by repository.
func observe(t *testing.T, host string, refs ...string) estategraph.Observations {
	t.Helper()
	var observations estategraph.Observations
	for _, ref := range refs {
		obs, err := estategraph.RegistryObserver{}.Observe(context.Background(), host+"/"+ref)
		if err != nil {
			t.Fatal(err)
		}
		obs.ID, _, _ = strings.Cut(ref, ":")
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
