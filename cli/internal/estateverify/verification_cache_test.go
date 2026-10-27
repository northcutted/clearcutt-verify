package estateverify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

// snapshotAnswer is a test runner, not a cryptographic verifier. Real Cosign
// cold/warm parity is exercised by commands.TestRealCosign. Here only the exact
// bytes handed to the subprocess can supply its returned DSSE statements.
func snapshotAnswer(args []string) ([]byte, error) {
	if !contains(args, "--local-image") {
		return nil, errors.New("expected pinned local evidence")
	}
	dir := args[len(args)-1]
	typ := ""
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--type" {
			typ = args[i+1]
		}
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "blobs", "sha256", "*"))
	var out bytes.Buffer
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if bytes.Contains(raw, []byte("invalid-signature")) {
			return nil, errors.New("signature mismatch")
		}
		var bundle struct {
			DSSE json.RawMessage `json:"dsseEnvelope"`
		}
		if json.Unmarshal(raw, &bundle) != nil || len(bundle.DSSE) == 0 {
			continue
		}
		f, err := decodeBundle(raw)
		if err != nil {
			return nil, err
		}
		if f.PredicateType == typ {
			out.Write(bundle.DSSE)
			out.WriteByte('\n')
		}
	}
	return out.Bytes(), nil
}

type cacheFixture struct {
	repo, digest, cert string
	found              []Found
	v                  *Verifier
	cache              *VerificationCache
	subj               Subject
	flags              []string
	calls              atomic.Int32
}

func newCacheFixture(t *testing.T) *cacheFixture {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	f := &cacheFixture{repo: strings.TrimPrefix(srv.URL, "http://") + "/app", cert: fulcioCert(t, ourSigner, ghIssuer)}
	idx := pushIndex(t, f.repo+":1", nil, built, nil)
	desc := descriptorOf(t, idx)
	f.digest = desc.Digest.String()
	attach(t, f.repo, desc, bundleJSON(t, "https://cyclonedx.org/bom", f.digest, sbomPredicate("openssl"), f.cert))
	var err error
	f.found, err = (&Discoverer{}).Discover(context.Background(), f.repo, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "trusted-root.json")
	if err := os.WriteFile(root, []byte("root-A"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.cache = &VerificationCache{dir: t.TempDir(), namespace: "test-implementation"}
	f.v = &Verifier{TrustedRoot: root, Cache: f.cache, cacheFound: f.found,
		Signers: []report.Signer{{Identity: ourSigner, Issuer: ghIssuer}},
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			f.calls.Add(1)
			return snapshotAnswer(args)
		}}
	f.subj = Subject{Ref: f.repo + "@" + f.digest, Kind: KindSBOM, PredicateType: "https://cyclonedx.org/bom", Signer: f.found[0].Signer}
	f.flags, _ = exactFlags(*f.found[0].Signer)
	return f
}

func (f *cacheFixture) verify(t *testing.T) {
	t.Helper()
	statements, err := f.v.verifyWith(context.Background(), f.subj, f.flags)
	if err != nil || len(statements) != 1 || !bytes.Equal(statements[0], f.found[0].Statement) {
		t.Fatalf("cache verification: %v, %q", err, statements)
	}
}

func TestVerificationCacheReopensAndInvalidatesTrustAndVersions(t *testing.T) {
	f := newCacheFixture(t)
	f.verify(t)
	f.v.Cache = &VerificationCache{dir: f.cache.dir, namespace: f.cache.namespace}
	f.verify(t)
	if f.calls.Load() != 1 {
		t.Fatal("unchanged verification did not survive reopening the cache")
	}
	for _, change := range []func(){
		func() {
			if err := os.WriteFile(f.v.TrustedRoot, []byte("root-B"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		func() { f.v.Signers[0].SourceRef = "refs/heads/main" },
		func() { f.v.Cache.namespace = "new-verifier-or-cosign" },
	} {
		before := f.calls.Load()
		change()
		f.verify(t)
		if f.calls.Load() != before+1 {
			t.Fatal("trust/version change reused an old result")
		}
	}
	key := filepath.Join(t.TempDir(), "acme.pub")
	if err := os.WriteFile(key, []byte("key-A"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.flags = []string{"--key", key, "--insecure-ignore-tlog=true"}
	f.verify(t)
	before := f.calls.Load()
	if err := os.WriteFile(key, []byte("key-B"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.verify(t)
	if f.calls.Load() != before+1 {
		t.Fatal("key rotation at the same path did not invalidate")
	}
}

func TestVerificationCachePinsTrustAndEvidenceBeforeRunning(t *testing.T) {
	f := newCacheFixture(t)
	old := f.v.Run
	f.v.Run = func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		if !contains(args, "--local-image") {
			return old(ctx, bin, args...)
		}
		// An A -> B -> A source-file change cannot relabel B as A: Cosign
		// receives the captured A file, not the caller's mutable path.
		if err := os.WriteFile(f.v.TrustedRoot, []byte("root-B"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(f.v.TrustedRoot, []byte("root-A"), 0o600)
		got, _ := os.ReadFile(filepath.Join(args[len(args)-1], "trusted-root.json"))
		if string(got) != "root-A" {
			t.Fatalf("mutable trust file reached verifier: %s", got)
		}
		return old(ctx, bin, args...)
	}
	f.verify(t)
	f.verify(t)
	if f.calls.Load() != 1 {
		t.Fatal("pinned trust bytes were not reused")
	}
	// Same statement and certificate, different signature bytes/manifest.
	var bundle map[string]any
	_ = json.Unmarshal(bundleJSON(t, f.subj.PredicateType, f.digest, sbomPredicate("openssl"), f.cert), &bundle)
	bundle["dsseEnvelope"].(map[string]any)["signatures"] = []any{map[string]string{"sig": "invalid-signature"}}
	raw, _ := json.Marshal(bundle)
	idxRef, _ := name.NewDigest(f.subj.Ref)
	desc, err := remote.Get(idxRef)
	if err != nil {
		t.Fatal(err)
	}
	ref := attach(t, f.repo, desc.Descriptor, raw)
	newFound, err := (&Discoverer{}).Discover(context.Background(), f.repo, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, found := range newFound {
		if found.Ref == ref {
			f.v.cacheFound = []Found{found}
		}
	}
	before := f.calls.Load()
	if _, err := f.v.verifyWith(context.Background(), f.subj, f.flags); err == nil || f.calls.Load() <= before {
		t.Fatal("changed signature bytes reused a previous pass")
	}
	f.v.cacheFound = f.found
	f.verify(t) // original immutable evidence still has its own correct result
}

func TestVerificationCacheCorruptionUnknownAndUnavailableAreMisses(t *testing.T) {
	f := newCacheFixture(t)
	f.verify(t)
	entries, _ := filepath.Glob(filepath.Join(f.cache.dir, "*.json"))
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`{"key":"other","output":"e30=","checksum":"bad"}`), []byte(`not json`)} {
		if err := os.WriteFile(entries[0], raw, 0o600); err != nil {
			t.Fatal(err)
		}
		before := f.calls.Load()
		f.verify(t)
		if f.calls.Load() != before+1 {
			t.Fatal("corrupt cache counted as verified")
		}
	}
	if err := os.RemoveAll(f.cache.dir); err != nil {
		t.Fatal(err)
	}
	f.verify(t) // read/write errors cannot prevent live verification
	if err := os.MkdirAll(f.cache.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	good := f.v.Run
	f.v.Run = func(context.Context, string, ...string) ([]byte, error) {
		f.calls.Add(1)
		return nil, context.DeadlineExceeded
	}
	for range 2 {
		if _, err := f.v.verifyWith(context.Background(), f.subj, f.flags); !couldntCheck(err) {
			t.Fatalf("unknown result: %v", err)
		}
	}
	if entries, _ := os.ReadDir(f.cache.dir); len(entries) != 0 {
		t.Fatal("unknown result was cached")
	}
	f.v.Run = good
	f.verify(t)
}

func TestVerificationCacheUnsupportedPathsStayLive(t *testing.T) {
	for _, kind := range []string{"mixed", "message-signature", "remote-key", "target-override"} {
		t.Run(kind, func(t *testing.T) {
			f := newCacheFixture(t)
			switch kind {
			case "mixed":
				pushKeySignedAttestation(t, f.repo, f.digest, f.subj.PredicateType, sbomPredicate("openssl"))
				var err error
				f.v.cacheFound, err = (&Discoverer{}).Discover(context.Background(), f.repo, f.digest)
				if err != nil {
					t.Fatal(err)
				}
			case "message-signature":
				f.v.cacheFound = append([]Found{}, f.found...)
				f.v.cacheFound[0].Statement = nil
			case "remote-key":
				f.flags = []string{"--key", "https://keys.example.test/acme.pub", "--insecure-ignore-tlog=true"}
			case "target-override":
				t.Setenv("SIGSTORE_ROOT_FILE", f.v.TrustedRoot)
			}
			f.v.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if contains(args, "--local-image") {
					t.Error("unsupported configuration used the alternate local verifier")
				}
				return json.Marshal(map[string]any{"payload": base64.StdEncoding.EncodeToString(f.found[0].Statement)})
			}
			f.verify(t)
			if entries, _ := os.ReadDir(f.cache.dir); len(entries) != 0 {
				t.Fatal("unsupported live result was cached")
			}
		})
	}
}

func TestVerificationCacheRejectsPayloadsMasqueradingAsReferrers(t *testing.T) {
	f := newCacheFixture(t)
	var bundle map[string]any
	_ = json.Unmarshal(bundleJSON(t, f.subj.PredicateType, f.digest, sbomPredicate("openssl"), f.cert), &bundle)
	desc, err := remote.Get(mustDigest(t, f.subj.Ref))
	if err != nil {
		t.Fatal(err)
	}
	// Local Cosign scans all blobs as candidate manifests. This bundle blob
	// must not become an extra, unlisted referrer just by adding OCI fields.
	bundle["schemaVersion"], bundle["subject"] = 2, desc.Descriptor
	bundle["layers"] = []any{map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "digest": "sha256:" + strings.Repeat("f", 64), "size": 1}}
	raw, _ := json.Marshal(bundle)
	ref := attach(t, f.repo, desc.Descriptor, raw)
	found, err := (&Discoverer{}).Discover(context.Background(), f.repo, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range found {
		if entry.Ref == ref {
			f.v.cacheFound = []Found{entry}
		}
	}
	if _, err := captureVerification(context.Background(), f.subj, f.v.cacheFound, nil); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("payload became a local referrer manifest: %v", err)
	}
}

func TestVerificationCacheAtomicConcurrentPublication(t *testing.T) {
	c := &VerificationCache{dir: t.TempDir()}
	key := contentHash([]byte("same operation"))
	c.write(key, []byte("complete"))
	var wg sync.WaitGroup
	var incomplete atomic.Bool
	for range 12 {
		wg.Go(func() {
			for range 10 {
				c.write(key, []byte("complete"))
				if raw, ok := c.read(key); !ok || string(raw) != "complete" {
					incomplete.Store(true)
				}
			}
		})
	}
	wg.Wait()
	if incomplete.Load() {
		t.Fatal("reader observed an incomplete cache generation")
	}
}

func TestVerificationCacheNamespaceIncludesExecutableBytes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	bin := filepath.Join(t.TempDir(), "cosign")
	if err := os.WriteFile(bin, []byte("binary-A"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := NewVerificationCache(dir, "dev", "v3.1.4", bin, nil)
	second := NewVerificationCache(dir, "dev", "v3.1.4", bin, nil)
	if first.Disabled != "" || first.namespace == "" || first.namespace != second.namespace {
		t.Fatalf("cache namespace: %+v", first)
	}
	if err := os.WriteFile(bin, []byte("binary-B"), 0o755); err != nil {
		t.Fatal(err)
	}
	changed := NewVerificationCache(dir, "dev", "v3.1.4", bin, nil)
	if changed.namespace == first.namespace {
		t.Fatal("same-version executable replacement reused results")
	}
	if c := NewVerificationCache(dir, "dev", "v3.0.6", bin, nil); c.Disabled == "" {
		t.Fatal("unsupported local bundle verifier enabled")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if c := NewVerificationCache(dir, "dev", "v3.1.4", bin, nil); c.Disabled == "" {
		t.Fatal("shared-writable/readable cache was trusted")
	}
}

func TestLegacyCacheCannotRelabelAMutableTagSnapshot(t *testing.T) {
	f := newCacheFixture(t)
	ctx := context.Background()
	idx, err := remote.Index(mustDigest(t, f.subj.Ref))
	if err != nil {
		t.Fatal(err)
	}
	repo := f.repo + "-legacy"
	target, _ := name.NewTag(repo + ":1")
	if err := remote.WriteIndex(target, idx); err != nil {
		t.Fatal(err)
	}
	f.subj.Ref, f.subj.Signer = repo+"@"+f.digest, nil
	key := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(key, []byte("offline-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.flags = []string{"--key", key, "--insecure-ignore-tlog=true"}
	envelope, _ := json.Marshal(map[string]any{"payload": base64.StdEncoding.EncodeToString(f.found[0].Statement)})
	image := func(signature string) v1.Image {
		img, err := mutate.Append(empty.Image, mutate.Addendum{Layer: static.NewLayer(envelope, "application/vnd.dsse.envelope.v1+json"),
			Annotations: map[string]string{"dev.cosignproject.cosign/signature": signature}})
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	a, b := image("signature-A"), image("invalid-signature")
	tag, _ := name.NewTag(repo + ":" + strings.Replace(f.digest, ":", "-", 1) + ".att")
	if err := remote.Write(tag, a); err != nil {
		t.Fatal(err)
	}
	f.v.cacheFound, err = (&Discoverer{}).Discover(ctx, repo, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	original := f.v.cacheFound
	f.v.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		f.calls.Add(1)
		if !contains(args, "--local-image") {
			return nil, errors.New("invalid live signature")
		}
		// A changed to B during verification and back before any later read.
		if err := remote.Write(tag, b); err != nil {
			t.Fatal(err)
		}
		defer remote.Write(tag, a)
		dir := args[len(args)-1]
		raw, _ := os.ReadFile(filepath.Join(dir, "index.json"))
		var index v1.IndexManifest
		_ = json.Unmarshal(raw, &index)
		for _, descriptor := range index.Manifests {
			if descriptor.Annotations["kind"] != "dev.cosignproject.cosign/atts" {
				continue
			}
			raw, _ := os.ReadFile(filepath.Join(dir, "blobs", "sha256", descriptor.Digest.Hex))
			if bytes.Contains(raw, []byte("invalid-signature")) {
				return nil, errors.New("invalid local signature")
			}
			return envelope, nil
		}
		return nil, errors.New("no captured legacy attestation")
	}
	f.verify(t)
	if err := remote.Write(tag, b); err != nil {
		t.Fatal(err)
	}
	f.v.cacheFound, err = (&Discoverer{}).Discover(ctx, repo, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	before := f.calls.Load()
	if _, err := f.v.verifyWith(ctx, f.subj, f.flags); err == nil || f.calls.Load() <= before {
		t.Fatal("new legacy signature bytes reused the old snapshot")
	}
	f.v.cacheFound = original
	f.verify(t)
}

func TestCachedScanAgesAndRescansEveryRun(t *testing.T) {
	f := newCacheFixture(t)
	idx, err := remote.Index(mustDigest(t, f.subj.Ref))
	if err != nil {
		t.Fatal(err)
	}
	im, _ := idx.IndexManifest()
	attach(t, f.repo, descriptorOf(t, idx), bundleJSON(t, PredicateCosignSign, f.digest, map[string]any{}, f.cert))
	for _, platform := range im.Manifests {
		attach(t, f.repo, platform, bundleJSON(t, "https://cyclonedx.org/bom", platform.Digest.String(), sbomPredicate("openssl"), f.cert))
		attach(t, f.repo, platform, bundleJSON(t, PredicateVuln, platform.Digest.String(), vulnPredicateAt("2026-10-01T00:00:00Z"), f.cert))
	}
	observations := observe(t, strings.Split(f.repo, "/")[0], "app:1")
	scanner := &fakeScanner{result: recordedGrype(t)}
	opts := Options{Verifier: f.v, Scanner: scanner, GeneratedAt: "2026-10-01T00:05:00Z",
		Policy: report.Policy{Required: []string{KindSignature, KindSBOM, KindVulnerabilityScan}, TrustedSigners: f.v.Signers, MaxScanAgeDays: 1, Rescan: true}}
	first, err := Build(context.Background(), observations, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Images[0].Verdict.Status != "verified" {
		t.Fatalf("initial verdict: %+v", first.Images[0].Verdict)
	}
	before := f.calls.Load()
	opts.GeneratedAt = "2026-11-01T00:00:00Z"
	second, err := Build(context.Background(), observations, opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Images[0].Verdict.Status != "unverified" || !strings.Contains(strings.Join(second.Images[0].Verdict.Reasons, ";"), "days old") {
		t.Fatalf("cached scan stopped aging: %+v", second.Images[0].Verdict)
	}
	if f.calls.Load() != before || len(scanner.calls) != 4 {
		t.Fatalf("crypto rerun or rescan reused: crypto %d -> %d; scans %d", before, f.calls.Load(), len(scanner.calls))
	}
}

func mustDigest(t *testing.T, ref string) name.Digest {
	t.Helper()
	d, err := name.NewDigest(ref)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCachedOutputKeepsSubjectAndPredicateBound(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	st, _ := json.Marshal(map[string]any{"predicateType": PredicateCosignSign, "subject": []any{map[string]any{"digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}}})
	out, _ := json.Marshal(map[string]any{"payload": base64.StdEncoding.EncodeToString(st)})
	subj := Subject{Ref: "example.test/app@" + digest, Kind: KindSignature, PredicateType: PredicateCosignSign}
	if _, err := cachedOutput(out, subj, true); err != nil {
		t.Fatal(err)
	}
	var multiple map[string]any
	_ = json.Unmarshal(st, &multiple)
	multiple["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha512"] = strings.Repeat("c", 128)
	multiStatement, _ := json.Marshal(multiple)
	multiOutput, _ := json.Marshal(map[string]any{"payload": base64.StdEncoding.EncodeToString(multiStatement)})
	if _, err := cachedOutput(multiOutput, subj, true); err == nil {
		t.Fatal("unusual multi-algorithm signature bypassed live verification")
	}
	subj.Ref = "example.test/app@sha256:" + strings.Repeat("b", 64)
	if _, err := cachedOutput(out, subj, true); err == nil {
		t.Fatal("cached output crossed subjects")
	}
	subj.Ref, subj.Kind, subj.PredicateType = "example.test/app@"+digest, KindSBOM, "https://cyclonedx.org/bom"
	if _, err := cachedOutput(out, subj, true); err == nil {
		t.Fatal("cached output crossed predicates")
	}
}
