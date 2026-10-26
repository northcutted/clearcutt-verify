package estateverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// The fixtures below are built by hand from each format's specification,
// as the tools that write them (notation, docker buildx, cosign attach
// sbom) aren't run by the tests:
//   - Notation: https://github.com/notaryproject/specifications
//     (specs/signature-specification.md, signature-envelope-jws.md)
//   - BuildKit: https://docs.docker.com/build/metadata/attestations/attestation-storage/
//   - cosign attach sbom: the sha256-<hex>.sbom tag, one layer holding the
//     document.

const notarySubject = "CN=Acme Release Signer,O=Acme Rockets,C=US"

// notationJWS is a Notation JWS envelope (JSON serialization) whose x5c
// names a certificate for notarySubject. Nothing checks its signature.
func notationJWS(t *testing.T, subject v1.Descriptor) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		Subject: pkix.Name{CommonName: "Acme Release Signer", Organization: []string{"Acme Rockets"}, Country: []string{"US"}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"targetArtifact": subject})
	protected, _ := json.Marshal(map[string]any{"alg": "ES256", "cty": "application/vnd.cncf.notary.payload.v1+json",
		"crit": []string{"io.cncf.notary.signingScheme"}, "io.cncf.notary.signingScheme": "notary.x509"})
	env, _ := json.Marshal(map[string]any{
		"payload":   base64.RawURLEncoding.EncodeToString(payload),
		"protected": base64.RawURLEncoding.EncodeToString(protected),
		"header":    map[string]any{"x5c": []string{base64.StdEncoding.EncodeToString(der)}, "io.cncf.notary.signingAgent": "notation-go/1.3.0"},
		"signature": base64.RawURLEncoding.EncodeToString([]byte("not checked")),
	})
	return env
}

// attachNotation attaches a Notation signature to repo@subject. With
// artifactType it is the OCI 1.1 form (artifactType, empty config); without,
// the form for registries that don't keep artifactType (the config's media
// type says it).
func attachNotation(t *testing.T, repo string, subject v1.Descriptor, artifactType bool) string {
	t.Helper()
	config := types.MediaType(notationArtifactType)
	if artifactType {
		config = emptyMediaType
	}
	img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), config)
	img, err := mutate.Append(img, mutate.Addendum{Layer: static.NewLayer(notationJWS(t, subject), "application/jose+json")})
	if err != nil {
		t.Fatal(err)
	}
	img = mutate.Annotations(img, map[string]string{
		"io.cncf.notary.x509chain.thumbprint#S256": `["` + strings.Repeat("ab", 32) + `"]`,
		"org.opencontainers.image.created":         "2026-10-20T00:00:00Z",
	}).(v1.Image)
	img = mutate.Subject(img, subject).(v1.Image)
	if artifactType {
		img = &artifactTyped{Image: img, artifactType: notationArtifactType}
	}
	d, _ := img.Digest()
	r, _ := name.ParseReference(repo + "@" + d.String())
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	return r.String()
}

// attachCosignSBOM stores an SBOM in cosign's sha256-<hex>.sbom tag of
// repo for digest, as cosign attach sbom does.
func attachCosignSBOM(t *testing.T, repo, digest, mediaType string) string {
	t.Helper()
	img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON)
	img, err := mutate.Append(img, mutate.Addendum{Layer: static.NewLayer([]byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"forged","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/wolfi/forged@1"}]}]}`), types.MediaType(mediaType))})
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(repo + ":" + strings.Replace(digest, ":", "-", 1) + ".sbom")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	return tag.String()
}

// pushBuildx pushes a two-platform index the way docker buildx build
// --sbom=true --provenance=mode=max --push does: beside each platform image,
// an attestation manifest (platform unknown/unknown) whose annotations name
// it, holding an SPDX SBOM and SLSA v0.2 provenance as unsigned in-toto
// statements, each layer annotated with its predicate type.
func pushBuildx(t *testing.T, ref string) v1.ImageIndex {
	t.Helper()
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	for _, arch := range []string{"amd64", "arm64"} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		img = mutate.MediaType(img, types.OCIManifestSchema1)
		cf, _ := img.ConfigFile()
		cf = cf.DeepCopy()
		cf.OS, cf.Architecture, cf.Created = "linux", arch, v1.Time{Time: built}
		if img, err = mutate.ConfigFile(img, cf); err != nil {
			t.Fatal(err)
		}
		d, _ := img.Digest()
		statement := func(pt string, predicate any) mutate.Addendum {
			st, _ := json.Marshal(map[string]any{
				"_type":         "https://in-toto.io/Statement/v0.1",
				"predicateType": pt,
				"subject":       []any{map[string]any{"name": "pkg:docker/app@1?platform=linux%2F" + arch, "digest": map[string]string{"sha256": d.Hex}}},
				"predicate":     predicate,
			})
			return mutate.Addendum{Layer: static.NewLayer(st, "application/vnd.in-toto+json"), Annotations: map[string]string{inTotoPredicateType: pt}}
		}
		att := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON)
		att, err = mutate.Append(att,
			statement("https://spdx.dev/Document", map[string]any{"spdxVersion": "SPDX-2.3", "packages": []any{map[string]any{"name": "forged",
				"externalRefs": []any{map[string]string{"referenceType": "purl", "referenceLocator": "pkg:apk/wolfi/forged@1"}}}}}),
			statement("https://slsa.dev/provenance/v0.2", map[string]any{"builder": map[string]string{"id": "https://github.com/docker/buildx"}}))
		if err != nil {
			t.Fatal(err)
		}
		idx = mutate.AppendManifests(idx,
			mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}},
			mutate.IndexAddendum{Add: att, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"},
				Annotations: map[string]string{buildxReferenceType: buildxAttestation, buildxReferenceDigest: d.String()}}})
	}
	r, _ := name.ParseReference(ref)
	if err := remote.WriteIndex(r, idx); err != nil {
		t.Fatal(err)
	}
	return idx
}

// recordingVerifier is acmeVerifier, also recording what cosign was asked
// to check.
func recordingVerifier(asked *[]string, mu *sync.Mutex) *Verifier {
	v := acmeVerifier()
	run := v.Run
	v.Run = func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		mu.Lock()
		*asked = append(*asked, strings.Join(args, " "))
		mu.Unlock()
		return run(ctx, bin, args...)
	}
	return v
}

// TestNotationSignatureIsPresent: a Notation signature is found, in either
// manifest form and through the Referrers API or the referrers tag, and is
// present: clearcutt-verify doesn't verify Notation signatures, so it is
// never verified, never handed to cosign, and never stands in for, or
// crowds out, a signature cosign verified.
func TestNotationSignatureIsPresent(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		referrersAPI, typedForm bool
	}{
		{"OCI 1.1 form, Referrers API", true, true},
		{"config form, Referrers API", true, false},
		{"OCI 1.1 form, referrers tag", false, true},
		{"config form, referrers tag", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(tc.referrersAPI)))
			defer srv.Close()
			host := strings.TrimPrefix(srv.URL, "http://")
			notated := pushIndex(t, host+"/notated:1", nil, built, nil)
			nd := descriptorOf(t, notated)
			sig := attachNotation(t, host+"/notated", nd, tc.typedForm)
			both := pushIndex(t, host+"/both:1", nil, built, nil)
			bd := descriptorOf(t, both)
			attachNotation(t, host+"/both", bd, tc.typedForm)
			attach(t, host+"/both", bd, bundleJSON(t, PredicateCosignSign, bd.Digest.String(), map[string]any{}, fulcioCert(t, ourSigner, ghIssuer)))

			var mu sync.Mutex
			var asked []string
			verifier := recordingVerifier(&asked, &mu)
			// A key signer too: evidence without a certificate is checked
			// against keys, and a Notation signature must not be.
			verifier.Signers = append(verifier.Signers, report.Signer{Key: "acme.pub"})
			r, err := Build(context.Background(), observe(t, host, "notated:1", "both:1"), Options{
				Name: "notation", Version: "test", GeneratedAt: "2026-10-26T00:00:00Z", Verifier: verifier,
				Policy: report.Policy{Required: []string{KindSignature}, TrustedSigners: verifier.Signers},
			})
			if err != nil {
				t.Fatal(err)
			}
			validateReport(t, r)
			img := map[string]report.Image{}
			for _, i := range r.Images {
				img[i.ID] = i
			}
			n := img["notated"]
			s := n.Evidence.Signature
			if s.Status != "present" || s.Source != "notation-signature" || s.Ref != sig || s.Signer == nil || s.Signer.Identity != "x509.subject: "+notarySubject ||
				s.Timestamp != "2026-10-20T00:00:00Z" || !strings.Contains(s.Detail, "doesn't verify Notation signatures") {
				t.Errorf("notation signature: %+v (signer %+v)", s, s.Signer)
			}
			if n.Verdict.Status != "unverified" {
				t.Errorf("an image signed only with Notation: verdict %+v", n.Verdict)
			}
			for _, a := range asked {
				if strings.Contains(a, "/notated@") && strings.HasPrefix(a, "verify ") {
					t.Errorf("cosign was asked to check a Notation signature: %s", a)
				}
			}
			b := img["both"]
			if s := b.Evidence.Signature; s.Status != "verified" || s.Source != "cosign-signature" || !strings.Contains(s.Detail, "1 other attached copy") {
				t.Errorf("a Notation signature beside a verified cosign signature: %+v", s)
			}
		})
	}
}

// TestBuildxAttestationsArePresent: BuildKit's SBOMs and provenance, stored
// in the image index beside each platform image, are found and present:
// unsigned, so nothing in them is read (no packages, no source), and an
// image that needs them verified is unverified, not failed.
func TestBuildxAttestationsArePresent(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	idx := pushBuildx(t, host+"/app:1")
	d := descriptorOf(t, idx)
	attach(t, host+"/app", d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, fulcioCert(t, ourSigner, ghIssuer)))

	found, err := (&Discoverer{}).BuildxAttestations(context.Background(), host+"/app", d.Digest.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 4 {
		t.Fatalf("found %d buildx attestations, want an SBOM and provenance for each of 2 platforms: %+v", len(found), found)
	}

	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "app:1"), Options{
		Name: "buildx", Version: "test", GeneratedAt: "2026-10-26T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{Required: []string{KindSignature, KindSBOM, KindProvenance}, TrustedSigners: verifier.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	a := r.Images[0]
	if len(a.Platforms) != 2 {
		t.Errorf("attestation manifests read as platform images: %+v", a.Platforms)
	}
	sbom, prov := a.Evidence.SBOM, a.Evidence.Provenance
	if sbom.Status != "present" || sbom.Source != "buildx-attestation" || sbom.PredicateType != "https://spdx.dev/Document" ||
		sbom.Platforms["linux/amd64"] != "present" || sbom.Platforms["linux/arm64"] != "present" || !strings.Contains(sbom.Detail, "BuildKit") {
		t.Errorf("buildx SBOM: %+v", sbom)
	}
	if prov.Status != "present" || prov.Source != "buildx-attestation" || prov.PredicateType != "https://slsa.dev/provenance/v0.2" {
		t.Errorf("buildx provenance: %+v", prov)
	}
	if a.Packages != nil || a.Provenance != nil || (a.Source != nil && a.Source.Basis == "provenance") || len(r.Packages) != 0 {
		t.Errorf("an unsigned buildx attestation was read: packages %v, provenance %+v, source %+v, index %+v", a.Packages, a.Provenance, a.Source, r.Packages)
	}
	if a.Evidence.Signature.Status != "verified" || a.Verdict.Status != "unverified" {
		t.Errorf("signature %+v, verdict %+v", a.Evidence.Signature, a.Verdict)
	}
}

// TestCosignSBOMTagIsPresent: an SBOM in cosign's .sbom tag is found and
// present, on a platform image or, for platform images without one of
// their own, on the image index; it never crowds out an SBOM a trusted
// signer attested, and is never read.
func TestCosignSBOMTagIsPresent(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)

	// onindex: cosign attach sbom on the multi-platform tag (the index).
	onIndex := pushIndex(t, host+"/onindex:1", nil, built, nil)
	oi := descriptorOf(t, onIndex)
	sbomTag := attachCosignSBOM(t, host+"/onindex", oi.Digest.String(), "spdx+json")
	attach(t, host+"/onindex", oi, bundleJSON(t, PredicateCosignSign, oi.Digest.String(), map[string]any{}, ours))

	// mixed: amd64 has a verified SBOM attestation and a .sbom tag, arm64
	// only a .sbom tag of its own.
	mixed := pushIndex(t, host+"/mixed:1", nil, built, nil)
	md := descriptorOf(t, mixed)
	attach(t, host+"/mixed", md, bundleJSON(t, PredicateCosignSign, md.Digest.String(), map[string]any{}, ours))
	im, _ := mixed.IndexManifest()
	for _, p := range im.Manifests {
		attachCosignSBOM(t, host+"/mixed", p.Digest.String(), "application/vnd.cyclonedx+json")
		if p.Platform.Architecture == "amd64" {
			attach(t, host+"/mixed", p, bundleJSON(t, "https://cyclonedx.org/bom", p.Digest.String(), sbomPredicate("openssl"), ours))
		}
	}

	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "onindex:1", "mixed:1"), Options{
		Name: "sbomtag", Version: "test", GeneratedAt: "2026-10-26T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{Required: []string{KindSignature, KindSBOM}, TrustedSigners: verifier.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}
	o := img["onindex"]
	if s := o.Evidence.SBOM; s.Status != "present" || s.Source != "cosign-sbom-tag" || s.Ref != sbomTag || s.PredicateType != "spdx+json" ||
		s.Platforms["linux/amd64"] != "present" || s.Platforms["linux/arm64"] != "present" || !strings.Contains(s.Detail, "image index") {
		t.Errorf("an index's .sbom tag: %+v", s)
	}
	if o.Packages != nil || o.Verdict.Status != "unverified" {
		t.Errorf("onindex: packages %v, verdict %+v", o.Packages, o.Verdict)
	}
	m := img["mixed"]
	if s := m.Evidence.SBOM; s.Status != "present" || s.Platforms["linux/amd64"] != "verified" || s.Platforms["linux/arm64"] != "present" {
		t.Errorf("mixed SBOM: %+v", s)
	}
	if m.Packages == nil || *m.Packages != 1 || m.PackagesSource == nil || m.PackagesSource.Status != "present" || strings.Join(m.PackagesSource.Platforms, ",") != "linux/amd64" {
		t.Errorf("mixed: packages from the verified SBOM only: %v %+v", m.Packages, m.PackagesSource)
	}
	for _, p := range r.Packages {
		if p.Name == "forged" {
			t.Errorf("a package from an unsigned .sbom tag is in the index: %+v", p)
		}
	}
}

// TestIndexEvidenceForPlatformImages: a platform image with no SBOM or scan
// of its own is judged by what is attached to the image index (a signed
// attestation there doesn't say which platform it describes: present, not
// read), and is unknown, never missing, when the index's evidence, or
// BuildKit's attestations in it, can't be read.
func TestIndexEvidenceForPlatformImages(t *testing.T) {
	var fail struct {
		sync.Mutex
		path string
	}
	reg := ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fail.Lock()
		p := fail.path
		fail.Unlock()
		if p != "" && req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, p) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		reg.ServeHTTP(w, req)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)
	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	d := descriptorOf(t, idx)
	attach(t, host+"/app", d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
	attach(t, host+"/app", d, bundleJSON(t, "https://cyclonedx.org/bom", d.Digest.String(), sbomPredicate("openssl"), ours))
	bx := pushBuildx(t, host+"/bx:1")
	bxd := descriptorOf(t, bx)
	attach(t, host+"/bx", bxd, bundleJSON(t, PredicateCosignSign, bxd.Digest.String(), map[string]any{}, ours))
	bim, _ := bx.IndexManifest()
	var attManifest string
	for _, m := range bim.Manifests {
		if m.Annotations[buildxReferenceType] == buildxAttestation {
			attManifest = m.Digest.String()
		}
	}

	build := func(refs ...string) map[string]report.Image {
		t.Helper()
		v := acmeVerifier()
		quick := []remote.Option{remote.WithRetryBackoff(remote.Backoff{Duration: time.Millisecond, Steps: 1})}
		r, err := Build(context.Background(), observe(t, host, refs...), Options{
			Name: "index", Version: "test", GeneratedAt: "2026-10-26T00:00:00Z", Verifier: v, Discoverer: &Discoverer{Options: quick}, RemoteOptions: quick,
			Policy: report.Policy{Required: []string{KindSignature, KindSBOM}, TrustedSigners: v.Signers},
		})
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

	a := build("app:1")["app"]
	if s := a.Evidence.SBOM; s.Status != "present" || s.Source != "cosign-attestation" || s.Platforms["linux/amd64"] != "present" || !strings.Contains(s.Detail, "image index") {
		t.Errorf("a signed SBOM on the index: %+v", s)
	}
	if a.Packages != nil || a.Verdict.Status != "unverified" {
		t.Errorf("an index SBOM was read: packages %v, verdict %+v", a.Packages, a.Verdict)
	}

	// The index's referrers can't be read: the platform images' SBOMs are
	// unknown, not missing.
	fail.Lock()
	fail.path = "/referrers/" + d.Digest.String()
	fail.Unlock()
	a = build("app:1")["app"]
	if s := a.Evidence.SBOM; s.Status != "unknown" || s.Platforms["linux/amd64"] != "unknown" {
		t.Errorf("the index's evidence unreadable: SBOM %+v", s)
	}

	// BuildKit's attestation manifest can't be read: unknown, not missing.
	fail.Lock()
	fail.path = "/manifests/" + attManifest
	fail.Unlock()
	b := build("bx:1")["bx"]
	if s := b.Evidence.SBOM; s.Status != "unknown" {
		t.Errorf("buildx attestations unreadable: SBOM %+v", s)
	}
	if s := b.Evidence.Provenance; s.Status != "unknown" {
		t.Errorf("buildx attestations unreadable: provenance %+v", s)
	}
	fail.Lock()
	fail.path = ""
	fail.Unlock()
}

// TestNotationSignerIsAClaim: the signer a Notation envelope names is read
// from its certificate's subject, and nothing else: a COSE envelope, a
// broken one, or one without a certificate names none.
func TestNotationSignerIsAClaim(t *testing.T) {
	good := notationJWS(t, v1.Descriptor{MediaType: types.OCIImageIndex, Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}})
	if s := notationSigner(good); s == nil || s.Identity != "x509.subject: "+notarySubject || s.Issuer != "" || s.Key != "" {
		t.Errorf("signer %+v", s)
	}
	sum := sha256.Sum256(good)
	for name, raw := range map[string][]byte{
		"not json":        []byte("\xd2\x84"), // a COSE_Sign1 tag
		"no x5c":          []byte(`{"header":{}}`),
		"x5c not base64":  []byte(`{"header":{"x5c":["!!"]}}`),
		"x5c not a cert":  []byte(`{"header":{"x5c":["` + base64.StdEncoding.EncodeToString(sum[:]) + `"]}}`),
		"x5c hex encoded": []byte(`{"header":{"x5c":["` + hex.EncodeToString(sum[:]) + `"]}}`),
	} {
		if s := notationSigner(raw); s != nil {
			t.Errorf("%s: signer %+v", name, s)
		}
	}
}
