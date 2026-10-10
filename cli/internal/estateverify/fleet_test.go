package estateverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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

func imageRecipePredicate(baseRef, baseDigest string) map[string]any {
	return map[string]any{
		"factory":  map[string]string{"version": "v0.1.0"},
		"manifest": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata:\n  name: tools\nspec:\n  test:\n    command: [/usr/bin/jq, --version]\n",
		"lock":     "base:\n  ref: " + baseRef + "\n  digest: " + baseDigest + "\npackages:\n  platforms:\n    linux/amd64:\n      - {name: jq, version: '1.8'}\n",
	}
}

// pushCosignTags signs repo@digest the way cosign v2 did: a .sig tag whose
// layer carries the certificate, and an .att tag holding a DSSE envelope.
func pushCosignTags(t *testing.T, repo, digest, certB64, predicateType string, predicate any) {
	t.Helper()
	der, _ := base64.StdEncoding.DecodeString(certB64)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	tag := strings.Replace(digest, ":", "-", 1)
	push := func(suffix string, layer []byte, mt types.MediaType, ann map[string]string) {
		img, err := mutate.Append(mutate.MediaType(empty.Image, types.OCIManifestSchema1), mutate.Addendum{Layer: static.NewLayer(layer, mt), Annotations: ann})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := name.ParseReference(repo + ":" + tag + suffix)
		if err := remote.Write(r, img); err != nil {
			t.Fatal(err)
		}
	}
	push(".sig", []byte(`{"critical":{"image":{"docker-manifest-digest":"`+digest+`"}}}`), "application/vnd.dev.cosign.simplesigning.v1+json",
		map[string]string{"dev.cosignproject.cosign/signature": "c2ln", "dev.sigstore.cosign/certificate": certPEM})
	st, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": predicateType, "predicate": predicate,
		"subject": []any{map[string]any{"name": repo, "digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}}})
	env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(st), "signatures": []any{}})
	push(".att", env, "application/vnd.dsse.envelope.v1+json", map[string]string{"predicateType": predicateType, "dev.sigstore.cosign/certificate": certPEM})
}

type fakeReproducer map[string]string // ref → rebuilt digest ("" fails)

func (f fakeReproducer) Reproduce(_ context.Context, ref string, s report.Signer) (string, error) {
	if s.IdentityRegexp == "" {
		return "", errors.New("no trusted signer passed")
	}
	if d := f[ref]; d != "" {
		return d, nil
	}
	return "", errors.New("buildkit: base image unavailable")
}

// TestBuildFactoryFleet covers what clearcutt-factory fleets add: an image
// whose recipe pins a base that has since moved on, a rebased image, an
// image signed the cosign v2 way, and reproduction.
func TestBuildFactoryFleet(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)

	// tools was built on the base before it moved on by ten days.
	old := pushIndex(t, host+"/base:previous", nil, built.Add(-10*24*time.Hour), nil)
	oldDigest, _ := old.Digest()
	current := pushIndex(t, host+"/base:latest", nil, built, nil)
	tools := pushIndex(t, host+"/tools:1", old, built, nil)
	toolsDesc := descriptorOf(t, tools)
	attach(t, host+"/tools", toolsDesc, bundleJSON(t, PredicateCosignSign, toolsDesc.Digest.String(), map[string]any{}, ours))
	attach(t, host+"/tools", toolsDesc, bundleJSON(t, PredicateRecipe, toolsDesc.Digest.String(), imageRecipePredicate(host+"/base:latest", oldDigest.String()), ours))

	// rebased moved tools' layers onto the current base.
	rebased := pushIndex(t, host+"/rebased:1", current, built, nil)
	rebasedDesc := descriptorOf(t, rebased)
	attach(t, host+"/rebased", rebasedDesc, bundleJSON(t, PredicateCosignSign, rebasedDesc.Digest.String(), map[string]any{}, ours))
	attach(t, host+"/rebased", rebasedDesc, bundleJSON(t, legacyPredicateRebase, rebasedDesc.Digest.String(),
		map[string]any{"factory": map[string]string{"version": "v0.1.0"}, "image": host + "/tools@" + toolsDesc.Digest.String()}, ours))

	// svc is on an older runtime than the one observed: runtime is a root.
	oldRuntime := pushIndex(t, host+"/runtime:previous", nil, built.Add(-2*24*time.Hour), nil)
	oldRuntimeDigest, _ := oldRuntime.Digest()
	pushIndex(t, host+"/runtime:latest", nil, built, nil)
	svc := pushIndex(t, host+"/svc:1", oldRuntime, built, nil)
	svcDesc := descriptorOf(t, svc)
	attach(t, host+"/svc", svcDesc, bundleJSON(t, PredicateRecipe, svcDesc.Digest.String(), imageRecipePredicate(host+"/runtime:latest", oldRuntimeDigest.String()), ours))

	legacy := pushIndex(t, host+"/legacy:1", nil, built, nil)
	legacyDigest, _ := legacy.Digest()
	pushCosignTags(t, host+"/legacy", legacyDigest.String(), ours, "https://slsa.dev/provenance/v1", map[string]any{"buildDefinition": map[string]any{
		"externalParameters":   map[string]any{"workflow": map[string]string{"repository": "https://github.com/acme/images"}},
		"resolvedDependencies": []any{map[string]any{"uri": "git+https://github.com/acme/images@refs/heads/main", "digest": map[string]string{"gitCommit": "abc123"}}},
	}})

	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "base:latest", "tools:1", "rebased:1", "legacy:1", "runtime:latest", "svc:1"), Options{
		Name: "fleet", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: verifier, Platforms: []string{"linux/amd64"},
		Reproducer: fakeReproducer{host + "/tools@" + toolsDesc.Digest.String(): toolsDesc.Digest.String()},
		Policy:     report.Policy{Required: []string{"signature", "recipe"}, TrustedSigners: verifier.Signers, MaxDaysBehind: 30, Reproduce: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}

	tl := img["tools"]
	if b := tl.Base; b == nil || b.Strength != "proof" || b.Drift != "stale" || b.DaysBehind != 10 || b.Ref != host+"/base:latest" || b.CurrentDigest == "" || b.CurrentDigest == b.Digest {
		t.Errorf("tools base: %+v (unresolved %v, warnings %v)", tl.Base, tl.Unresolved, tl.Warnings)
	}
	// The claimed base was checked on one platform image, which its digest names.
	if b := tl.Base; b == nil || b.Platform != "linux/amd64" || b.ProvenOn != "linux/amd64" {
		t.Errorf("tools base platform: %+v", tl.Base)
	}
	if e := tl.Evidence.Tests; e.Status != "present" || e.Source != "recipe" || !strings.Contains(e.Detail, "/usr/bin/jq --version") {
		t.Errorf("tools tests from the recipe: %+v", e)
	}
	if len(tl.Platforms) != 1 || tl.Platforms[0].Platform != "linux/amd64" || tl.Platforms[0].Layers != 2 {
		t.Errorf("tools platforms: %+v", tl.Platforms)
	}
	if tl.Factory == nil || tl.Factory.Kind != "Image" || tl.Reproducibility.Status != "reproduced" || tl.Verdict.Status != "verified" {
		t.Errorf("tools: %+v %+v %+v", tl.Factory, tl.Reproducibility, tl.Verdict)
	}

	rb := img["rebased"]
	if rb.Evidence.Rebase.Status != "verified" || rb.Evidence.Recipe.Status != "not-applicable" || rb.Factory == nil || rb.Factory.RebasedFrom != host+"/tools@"+toolsDesc.Digest.String() {
		t.Errorf("rebased evidence: %+v %+v", rb.Evidence, rb.Factory)
	}
	if rb.Factory == nil || rb.Factory.Kind != "Image" || rb.Factory.Name != "tools" {
		t.Errorf("rebased factory (from the original recipe): %+v %v", rb.Factory, rb.Warnings)
	}
	if rb.Base != nil && (rb.Base.Platform != "" || rb.Base.ProvenOn != "linux/amd64") {
		t.Errorf("rebased base found by the graph names the index: %+v", rb.Base)
	}
	if rb.Builder.Basis != "clearcutt-factory rebase record" || rb.Base == nil || rb.Base.Drift != "current" {
		t.Errorf("rebased builder %+v base %+v", rb.Builder, rb.Base)
	}
	// Its rebase couldn't be repeated: undecided, not a mismatch.
	if rb.Reproducibility.Method != "rebase-repeat" || rb.Reproducibility.Status != "not-checked" || rb.Verdict.Status != "unverified" ||
		!strings.Contains(rb.Reproducibility.Detail, "couldn't finish") {
		t.Errorf("rebased reproducibility %+v verdict %+v", rb.Reproducibility, rb.Verdict)
	}

	lg := img["legacy"]
	if s := lg.Evidence.Signature; s.Status != "verified" || !strings.HasSuffix(s.Ref, ".sig") || s.Signer == nil || s.Signer.Identity != ourSigner {
		t.Errorf("legacy signature: %+v", s)
	}
	if lg.Evidence.Provenance.Status != "verified" || lg.Source == nil || lg.Source.URL != "https://github.com/acme/images" || lg.Source.Revision != "abc123" {
		t.Errorf("legacy provenance %+v source %+v", lg.Evidence.Provenance, lg.Source)
	}

	// A root found only through older versions has no drift to measure.
	if rt := img["runtime"]; rt.Root == "" || strings.Contains(strings.Join(rt.Verdict.Reasons, ";"), "couldn't be measured") {
		t.Errorf("runtime: root %q, verdict %+v", rt.Root, rt.Verdict)
	}
	if img["svc"].Base == nil || img["svc"].Base.DaysBehind != 2 {
		t.Errorf("svc base: %+v", img["svc"].Base)
	}
	if img["base"].Root == "" || len(r.Bases) != 2 || r.Bases[0].Consumers != 2 || r.Bases[0].StaleConsumers != 1 || r.Bases[0].Versions != 2 || r.Bases[1].Repository != host+"/runtime" {
		t.Errorf("bases %+v (base root %q)", r.Bases, img["base"].Root)
	}
	validateReport(t, r)
}

func TestReadPolicy(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "policy.yaml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p, err := ReadPolicy(write("apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [signature, sbom]\n" +
		"trustedSigners:\n  - identityRegexp: ^https://github\\.com/acme/\n    issuer: " + ghIssuer + "\nfailOn: critical\nonlyFixed: true\nmaxDaysBehind: 30\n"))
	if err != nil || len(p.Required) != 2 || p.FailOn != "critical" || !p.OnlyFixed || p.MaxDaysBehind != 30 || len(p.TrustedSigners) != 1 {
		t.Fatalf("policy %+v, %v", p, err)
	}
	for body, want := range map[string]string{
		"apiVersion: v1\nkind: Policy\n":                                                                     "expected apiVersion",
		"apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [rebase]\n":                       "required evidence",
		"apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nfailOn: severe\n":                           "failOn",
		"apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\ntrustedSigners: [{identityRegexp: '.*'}]\n": "wildcard",
		"apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequire: [signature]\n":                     "unknown field",
	} {
		if _, err := ReadPolicy(write(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", body, err, want)
		}
	}
	if _, err := ReadPolicy(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("read a missing policy")
	}
}

func TestFactoryReproducer(t *testing.T) {
	signer := report.Signer{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}
	digest := "sha256:" + strings.Repeat("d", 64)
	var args []string
	f := FactoryReproducer{Dir: t.TempDir(), Run: func(_ context.Context, _, bin string, a ...string) ([]byte, error) {
		args = append([]string{bin}, a...)
		return []byte("building...\nrebuilt " + digest + ", matching the published image\n"), nil
	}}
	got, err := f.Reproduce(context.Background(), "r@"+digest, signer)
	if err != nil || got != digest || strings.Join(args[:4], " ") != "clearcutt-factory verify --image r@"+digest {
		t.Fatalf("reproduce: %q %v (args %q)", got, err, args)
	}
	f.Run = func(context.Context, string, string, ...string) ([]byte, error) {
		return []byte("pulling base\nerror: base image unavailable\n"), errors.New("exit status 1")
	}
	if _, err := f.Reproduce(context.Background(), "r@"+digest, signer); err == nil || !strings.Contains(err.Error(), "base image unavailable") {
		t.Errorf("failed rebuild: %v", err)
	}
	f.Run = func(context.Context, string, string, ...string) ([]byte, error) { return []byte("done\n"), nil }
	if _, err := f.Reproduce(context.Background(), "r@"+digest, signer); err == nil || !strings.Contains(err.Error(), "gave no digest") {
		t.Errorf("no digest: %v", err)
	}
	if _, err := f.Reproduce(context.Background(), "r@"+digest, report.Signer{}); err == nil {
		t.Error("reproduced without a signer")
	}
}

// TestVerifierRunsCosign runs a stand-in cosign binary.
func TestVerifierRunsCosign(t *testing.T) {
	dir := t.TempDir()
	cosign := filepath.Join(dir, "cosign")
	script := "#!/bin/sh\ncase \"$*\" in *acme*) echo '[]';; *) echo 'Error: no matching signatures' >&2; exit 1;; esac\n"
	if err := os.WriteFile(cosign, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Cosign: cosign, Signers: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}}
	subj := Subject{Ref: "r@sha256:x", Kind: KindSignature}
	if _, err := v.Verify(context.Background(), subj); err != nil {
		t.Errorf("verify: %v", err)
	}
	v.Signers[0].IdentityRegexp = `^https://github\.com/other/`
	if _, err := v.Verify(context.Background(), subj); err == nil || !strings.Contains(err.Error(), "no matching signatures") {
		t.Errorf("untrusted: %v", err)
	}
}

func TestReproduceOutcomes(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	signer := &report.Signer{Identity: ourSigner, Issuer: ghIssuer}
	img := &report.Image{Repository: "r", Digest: digest, Evidence: report.Evidence{Recipe: report.EvidenceItem{Status: "verified"}, Rebase: report.EvidenceItem{Status: "not-applicable"}}}
	opts := Options{Policy: report.Policy{Reproduce: true, TrustedSigners: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}}}}
	data := imageData{recipeVerified: true, recipeSigner: signer}
	for rebuilt, want := range map[string]string{digest: "reproduced", "sha256:" + strings.Repeat("b", 64): "not-reproduced", "": "not-checked"} {
		opts.Reproducer = fakeReproducer{"r@" + digest: rebuilt}
		if got := reproduce(context.Background(), img, data, opts); got.Status != want || got.Method != "recipe-rebuild" {
			t.Errorf("rebuilt %q: %+v, want %s", rebuilt, got, want)
		}
	}
	// Unverified recipes aren't rebuilt.
	if got := reproduce(context.Background(), img, imageData{recipeSigner: signer}, opts); got.Status != "not-checked" || !strings.Contains(got.Detail, "Only verified") {
		t.Errorf("unverified recipe: %+v", got)
	}
}

// TestBuildStacks covers registry stacks: an app pinned to a signed stack
// version that the stack's tag has since moved on from.
func TestBuildStacks(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours := fulcioCert(t, ourSigner, ghIssuer)

	pushStack := func(content string) string {
		img, err := mutate.Append(mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), "application/vnd.clearcutt.factory.stack.v1+yaml"),
			mutate.Addendum{Layer: static.NewLayer([]byte(content), "application/vnd.clearcutt.factory.stack.v1+yaml")})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := name.ParseReference(host + "/stacks/go:1")
		if err := remote.Write(r, img); err != nil {
			t.Fatal(err)
		}
		d, _ := img.Digest()
		return d.String()
	}
	old := pushStack("kind: Stack\nmetadata: {name: go}\nbuild: golang:1.26\n")
	attach(t, host+"/stacks/go", v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: mustHash(t, old)}, bundleJSON(t, PredicateCosignSign, old, map[string]any{}, ours))
	current := pushStack("kind: Stack\nmetadata: {name: go}\nbuild: golang:1.27\n")

	app := pushIndex(t, host+"/apps/checkout:1", nil, built, nil)
	appDesc := descriptorOf(t, app)
	recipe := map[string]any{
		"factory":  map[string]string{"version": "v0.1.1"},
		"manifest": "apiVersion: factory.clearcutt.dev/v1alpha1\nkind: App\nmetadata:\n  name: checkout\nspec:\n  stack: " + host + "/stacks/go:1\n",
		"lock":     "app:\n  stack: go\n  stackDigest: sha256:" + strings.Repeat("d", 64) + "\n  stackArtifact: {ref: " + host + "/stacks/go:1, digest: " + old + "}\n  build: {ref: golang:1, digest: sha256:" + strings.Repeat("c", 64) + "}\n",
	}
	attach(t, host+"/apps/checkout", appDesc, bundleJSON(t, PredicateRecipe, appDesc.Digest.String(), recipe, ours))

	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "apps/checkout:1"), Options{
		Name: "stacks", Version: "test", GeneratedAt: "2026-10-10T00:00:00Z", Verifier: verifier,
		Policy: report.Policy{TrustedSigners: verifier.Signers, StackSigners: verifier.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := r.Images[0].Factory
	if f == nil || f.Stack != "go" || f.StackRef != host+"/stacks/go:1" || f.StackDigest != old {
		t.Fatalf("app factory: %+v", f)
	}
	if len(r.Stacks) != 1 {
		t.Fatalf("stacks: %+v", r.Stacks)
	}
	st := r.Stacks[0]
	if st.Repository != host+"/stacks/go" || st.CurrentDigest != current || st.Consumers != 1 || st.StaleConsumers != 1 {
		t.Errorf("stack: %+v", st)
	}
	if len(st.Versions) != 1 || st.Versions[0].Current || st.Versions[0].Signature.Status != "verified" || strings.Join(st.Versions[0].Images, ",") != "apps/checkout" {
		t.Errorf("stack versions: %+v", st.Versions)
	}
	validateReport(t, r)

	// Without stack signers the signature is present, not verified.
	r, _ = Build(context.Background(), observe(t, host, "apps/checkout:1"), Options{Name: "stacks", Version: "test", Verifier: verifier,
		Policy: report.Policy{TrustedSigners: verifier.Signers}})
	if s := r.Stacks[0].Versions[0].Signature; s.Status != "present" || !strings.Contains(s.Detail, "No stack signer") {
		t.Errorf("no stack signers: %+v", s)
	}
}

func mustHash(t *testing.T, digest string) v1.Hash {
	t.Helper()
	h, err := v1.NewHash(digest)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
