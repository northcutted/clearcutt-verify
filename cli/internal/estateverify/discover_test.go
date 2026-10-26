package estateverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// noReferrersRegistry is a registry without the OCI Referrers API, like
// registry:2 or Docker Hub: attaching evidence writes the referrers tag
// (sha256-<hex>), which is where it has to be found. It counts requests to
// the Referrers API, and fail, when set, answers requests whose path ends
// with it with that status.
type noReferrersRegistry struct {
	next      http.Handler
	referrers atomic.Int64
	failPath  atomic.Value // string
	failCode  atomic.Int64
}

func (r *noReferrersRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if strings.Contains(req.URL.Path, "/referrers/") {
		r.referrers.Add(1)
	}
	if p, _ := r.failPath.Load().(string); p != "" && strings.HasSuffix(req.URL.Path, p) {
		w.WriteHeader(int(r.failCode.Load()))
		return
	}
	r.next.ServeHTTP(w, req)
}

// attachRawSBOM attaches an unsigned SPDX document as a referrer, the way
// oras attach or cosign attach sbom --registry-referrers-mode=oci-1-1 do.
func attachRawSBOM(t *testing.T, repo string, subject v1.Descriptor) string {
	t.Helper()
	img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), emptyMediaType)
	img, err := mutate.Append(img, mutate.Addendum{Layer: static.NewLayer([]byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`), "application/spdx+json")})
	if err != nil {
		t.Fatal(err)
	}
	withSubject := mutate.Subject(img, subject).(v1.Image)
	// The artifact type says what it holds, as the referrers index lists it.
	withType := &artifactTyped{Image: withSubject, artifactType: "application/spdx+json"}
	d, _ := withType.Digest()
	r, _ := name.ParseReference(repo + "@" + d.String())
	if err := remote.Write(r, withType); err != nil {
		t.Fatal(err)
	}
	return r.String()
}

// TestDiscoverReadsTheReferrersTag covers registries without the Referrers
// API (registry:2, Docker Hub, and others): their attachments are listed
// in the referrers tag, sha256-<subject hex>, which cosign and oras write
// there instead. Evidence found there is evidence like any other, verified
// the same way; a tag that can't be read leaves evidence unknown, never
// missing.
func TestDiscoverReadsTheReferrersTag(t *testing.T) {
	reg := &noReferrersRegistry{next: ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)))}
	srv := httptest.NewServer(reg)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	d := descriptorOf(t, idx)
	ours := fulcioCert(t, ourSigner, ghIssuer)
	attach(t, host+"/app", d, bundleJSON(t, PredicateCosignSign, d.Digest.String(), map[string]any{}, ours))
	attach(t, host+"/app", d, bundleJSON(t, "https://slsa.dev/provenance/v1", d.Digest.String(), provenancePredicate("https://github.com/acme/images", "abc123"), ours))
	im, _ := idx.IndexManifest()
	for _, p := range im.Manifests {
		attach(t, host+"/app", p, bundleJSON(t, "https://cyclonedx.org/bom", p.Digest.String(), sbomPredicate("openssl"), ours))
	}
	raw := attachRawSBOM(t, host+"/app", d)

	// The tag the attachments were written to exists, and holds them.
	tag, err := name.NewTag(host + "/app:" + strings.Replace(d.Digest.String(), ":", "-", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Head(tag); err != nil {
		t.Fatalf("the registry has no Referrers API, so attaching should write the referrers tag %s: %v", tag, err)
	}

	// Attaching asked whether the registry has the API; reading needn't.
	reg.referrers.Store(0)
	found, err := (&Discoverer{}).Discover(context.Background(), host+"/app", d.Digest.String())
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, f := range found {
		kinds[f.Kind+"/"+f.Format]++
		if f.Format == FormatRawReferrer && f.Ref != raw {
			t.Errorf("raw SBOM found at %s, attached at %s", f.Ref, raw)
		}
	}
	want := map[string]int{KindSignature + "/" + FormatBundle: 1, KindProvenance + "/" + FormatBundle: 1, KindSBOM + "/" + FormatRawReferrer: 1}
	for k, n := range want {
		if kinds[k] != n {
			t.Errorf("found %d %s through the referrers tag, want %d (found %v)", kinds[k], k, n, kinds)
		}
	}
	if n := reg.referrers.Load(); n != 0 {
		t.Errorf("asked the Referrers API %d times though the referrers tag exists", n)
	}

	// The whole run: evidence in the referrers tag verifies like evidence
	// the Referrers API lists.
	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "app:1"), Options{
		Name: "tag", Version: "test", GeneratedAt: "2026-10-26T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{Required: []string{"signature", "sbom", "provenance"}, TrustedSigners: verifier.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	e := r.Images[0].Evidence
	if e.Signature.Status != "verified" || e.SBOM.Status != "verified" || e.Provenance.Status != "verified" || r.Images[0].Verdict.Status != "verified" {
		t.Errorf("evidence in the referrers tag: signature %s, sbom %s, provenance %s, verdict %+v", e.Signature.Status, e.SBOM.Status, e.Provenance.Status, r.Images[0].Verdict)
	}

	// An image with nothing attached: no tag, and the Referrers API isn't
	// there either (404). That is missing evidence, not unknown.
	bare := pushIndex(t, host+"/bare:1", nil, built, nil)
	bd := descriptorOf(t, bare)
	if found, err := (&Discoverer{}).Discover(context.Background(), host+"/bare", bd.Digest.String()); err != nil || len(found) != 0 {
		t.Errorf("nothing attached: found %v, err %v", found, err)
	}

	// The referrers tag can't be read: whatever it lists is unknown.
	for _, tc := range []struct {
		name string
		code int
	}{
		{"rate limited", http.StatusTooManyRequests},
		{"server error", http.StatusInternalServerError},
		{"unauthorized", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg.failCode.Store(int64(tc.code))
			reg.failPath.Store("/manifests/" + tag.TagStr())
			defer reg.failPath.Store("")
			once := &Discoverer{Options: []remote.Option{remote.WithRetryBackoff(remote.Backoff{Duration: time.Millisecond, Steps: 1})}}
			_, err := once.Discover(context.Background(), host+"/app", d.Digest.String())
			if !errors.Is(err, ErrUnknown) {
				t.Errorf("an unreadable referrers tag (%d) gave %v, want ErrUnknown", tc.code, err)
			}
		})
	}
}

// TestReferrersTagThatIsNotAnIndex: a referrers tag holding an image (a
// mistake, or a tag pushed over it) lists nothing that can be read, so the
// evidence is unknown, not missing.
func TestReferrersTagThatIsNotAnIndex(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	d := descriptorOf(t, idx)
	tag, _ := name.NewTag(host + "/app:" + strings.Replace(d.Digest.String(), ":", "-", 1))
	img := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON)
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Discoverer{}).Discover(context.Background(), host+"/app", d.Digest.String()); !errors.Is(err, ErrUnknown) {
		t.Errorf("a referrers tag holding an image gave %v, want ErrUnknown", err)
	}
}

// artifactTyped sets an image manifest's artifactType.
type artifactTyped struct {
	v1.Image
	artifactType string
}

func (a *artifactTyped) RawManifest() ([]byte, error) {
	return withArtifactType(a.Image, a.artifactType)
}

func (a *artifactTyped) Digest() (v1.Hash, error) {
	raw, err := a.RawManifest()
	if err != nil {
		return v1.Hash{}, err
	}
	h, _, err := v1.SHA256(bytes.NewReader(raw))
	return h, err
}

func (a *artifactTyped) Size() (int64, error) {
	raw, err := a.RawManifest()
	return int64(len(raw)), err
}

func (a *artifactTyped) Manifest() (*v1.Manifest, error) {
	raw, err := a.RawManifest()
	if err != nil {
		return nil, err
	}
	return v1.ParseManifest(bytes.NewReader(raw))
}

func (a *artifactTyped) ArtifactType() (string, error) { return a.artifactType, nil }

// withArtifactType is img's manifest with artifactType set.
func withArtifactType(img v1.Image, artifactType string) ([]byte, error) {
	raw, err := img.RawManifest()
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m["artifactType"] = artifactType
	return json.Marshal(m)
}
