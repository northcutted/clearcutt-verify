package estateverify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// What cosign v3.0.6 printed in the showcase's CI when one of several
// concurrent verifications lost Sigstore's trusted root: a warning naming
// the TUF error, then the generic failure that read as a bad signature.
const lostTrustedRoot = "WARNING: Could not fetch trusted_root.json from the TUF repository. Continuing with individual targets. Error from TUF: error getting live trusted root: failed to create tuf updater: read snapshot.json: unexpected end of JSON input\n" +
	"Error: trusted root is required when using new bundle format\n" +
	"error during command execution: trusted root is required when using new bundle format"

func TestLostTrustedRootIsUnknownNotFailed(t *testing.T) {
	for _, msg := range []string{
		"error during command execution: trusted root is required when using new bundle format",
		"cosign verify-attestation: exit status 1: " + cosignStderr(lostTrustedRoot),
		"error getting live trusted root: failed to create tuf updater: Get \"https://tuf-repo-cdn.sigstore.dev/timestamp.json\": context deadline exceeded",
		"loading trusted root: open /tmp/x/trusted_root.json: no such file or directory",
	} {
		if !couldntCheck(classify(context.Background(), errors.New(msg))) {
			t.Errorf("%q decided something about the evidence", msg)
		}
		if status, detail := failure(classify(context.Background(), errors.New(msg)), "x"); status != "unknown" || !strings.Contains(detail, "cosign couldn't check it") {
			t.Errorf("%q: %s %q", msg, status, detail)
		}
	}
	// What cosign said about TUF is kept with the error, not just its last
	// line.
	if got := cosignStderr(lostTrustedRoot); !strings.Contains(got, "Error from TUF: error getting live trusted root") || !strings.HasSuffix(got, "trusted root is required when using new bundle format") {
		t.Errorf("stderr kept: %q", got)
	}
	if got := cosignStderr("some noise\nError: no matching signatures\n"); got != "Error: no matching signatures" {
		t.Errorf("plain stderr: %q", got)
	}
	// A verifier facing it reports unknown with the TUF message.
	cert := &report.Signer{Identity: ourSigner, Issuer: ghIssuer, SourceRepository: "https://github.com/acme/images"}
	v := &Verifier{Signers: []report.Signer{{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}},
		Run: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("cosign verify-attestation: exit status 1: " + cosignStderr(lostTrustedRoot))
		}}
	_, err := v.Verify(context.Background(), Subject{Ref: "r@sha256:" + strings.Repeat("a", 64), Kind: KindVulnerabilityScan, PredicateType: PredicateVuln, Signer: cert})
	if !couldntCheck(err) || !strings.Contains(err.Error(), "Error from TUF") {
		t.Errorf("verify: couldntCheck %v, %v", couldntCheck(err), err)
	}
}

// TestPrepareTrustedRoot: the trusted root is fetched once, only when a
// signer needs it (keyless, or a key whose evidence is in the transparency
// log) and nothing else supplies one, and every verification that needs it
// then reads it from the file.
func TestPrepareTrustedRoot(t *testing.T) {
	const rootJSON = `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`
	// put writes cache files (relative paths), each modified at its time.
	put := func(t *testing.T, cache string, files map[string]time.Time) {
		t.Helper()
		for rel, at := range files {
			file := filepath.Join(cache, rel)
			if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(rootJSON), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(file, at, at); err != nil {
				t.Fatal(err)
			}
		}
	}
	cache := t.TempDir()
	rootFile := filepath.Join(cache, "tuf-repo-cdn.sigstore.dev", "targets", "trusted_root.json")
	put(t, cache, map[string]time.Time{"tuf-repo-cdn.sigstore.dev/targets/trusted_root.json": built})
	t.Setenv("TUF_ROOT", cache)
	t.Setenv("TUF_MIRROR", "")
	for _, name := range sigstoreTargetVars {
		t.Setenv(name, "")
	}
	keyless := report.Signer{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}
	key := report.Signer{Key: "acme.pub"}
	off := false
	offlineKey := report.Signer{Key: "offline.pub", Tlog: &off}
	cert := &report.Signer{Identity: ourSigner, Issuer: ghIssuer, SourceRepository: "https://github.com/acme/images"}
	digest := "r@sha256:" + strings.Repeat("a", 64)
	newVerifier := func(signers ...report.Signer) (*Verifier, *[][]string) {
		var calls [][]string
		v := &Verifier{Signers: signers}
		v.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls = append(calls, args)
			if args[0] == "initialize" {
				return nil, nil
			}
			return nil, errors.New("no matching signatures")
		}
		return v, &calls
	}

	v, calls := newVerifier(keyless, key, offlineKey)
	root, warning, err := v.PrepareTrustedRoot(context.Background())
	if err != nil || root != rootFile || warning != "" || v.TrustedRoot != rootFile || len(*calls) != 1 || strings.Join((*calls)[0], " ") != "initialize" {
		t.Fatalf("root %q, warning %q, %v, calls %v", root, warning, err, *calls)
	}
	if root2, _, err := v.PrepareTrustedRoot(context.Background()); err != nil || root2 != rootFile || len(*calls) != 1 {
		t.Errorf("fetched again: %q %v %v", root2, err, *calls)
	}
	// Keyless verifications and key verifications that check the
	// transparency log read the file; a key that signs without the log
	// needs no root.
	_, _ = v.Verify(context.Background(), Subject{Ref: digest, Kind: KindSignature, Signer: cert})
	v.Signers = []report.Signer{key}
	_, _ = v.Verify(context.Background(), Subject{Ref: digest, Kind: KindSignature, Signer: &report.Signer{Key: "x"}})
	v.Signers = []report.Signer{offlineKey}
	_, _ = v.Verify(context.Background(), Subject{Ref: digest, Kind: KindSignature, Signer: &report.Signer{Key: "x"}})
	if len(*calls) != 4 {
		t.Fatalf("calls %v", *calls)
	}
	if kl := strings.Join((*calls)[1], " "); !strings.Contains(kl, "--trusted-root "+rootFile) || !strings.HasSuffix(kl, digest) {
		t.Errorf("keyless verification: %s", kl)
	}
	if ky := strings.Join((*calls)[2], " "); !strings.Contains(ky, "--key acme.pub") || !strings.Contains(ky, "--trusted-root "+rootFile) {
		t.Errorf("key verification with the transparency log: %s", ky)
	}
	if off := strings.Join((*calls)[3], " "); strings.Contains(off, "--trusted-root") || !strings.Contains(off, "--key offline.pub --insecure-ignore-tlog=true") {
		t.Errorf("key verification without the transparency log: %s", off)
	}

	// A key whose evidence is in the transparency log needs the root too.
	v, calls = newVerifier(key)
	if root, _, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != rootFile || len(*calls) != 1 {
		t.Errorf("key with the transparency log: %q %v %v", root, err, *calls)
	}
	// Only keys that sign without the log: nothing to fetch.
	v, calls = newVerifier(offlineKey)
	if root, _, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != "" || len(*calls) != 0 {
		t.Errorf("offline keys only: %q %v %v", root, err, *calls)
	}
	// A root given: used as is.
	v, calls = newVerifier(keyless)
	v.TrustedRoot = "/etc/sigstore/trusted_root.json"
	if root, _, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != v.TrustedRoot || len(*calls) != 0 {
		t.Errorf("given root: %q %v %v", root, err, *calls)
	}
	// Individual targets in the environment: left to cosign.
	t.Setenv("SIGSTORE_ROOT_FILE", "/etc/sigstore/root.pem")
	v, calls = newVerifier(keyless)
	if root, _, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != "" || len(*calls) != 0 {
		t.Errorf("individual targets: %q %v %v", root, err, *calls)
	}
	t.Setenv("SIGSTORE_ROOT_FILE", "")
	// The fetch failing is an operational error naming the fix.
	v, _ = newVerifier(keyless)
	v.Run = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New(`Get "https://tuf-repo-cdn.sigstore.dev/root.json": dial tcp: i/o timeout`)
	}
	if _, _, err := v.PrepareTrustedRoot(context.Background()); err == nil || !strings.Contains(err.Error(), "cosign initialize") || !strings.Contains(err.Error(), "--trusted-root") {
		t.Errorf("fetch failing: %v", err)
	}

	// Two mirrors cached: the root of the mirror cosign initialize used, the
	// one TUF_MIRROR names (passed on to it), else the one it recorded in
	// remote.json, else the default; not whichever is newer.
	cache = t.TempDir()
	t.Setenv("TUF_ROOT", cache)
	put(t, cache, map[string]time.Time{
		"tuf-repo-cdn.sigstore.dev/targets/trusted_root.json": built,
		"tuf.example-sigstore/targets/trusted_root.json":      built.Add(time.Hour),
	})
	t.Setenv("TUF_MIRROR", "https://tuf-repo-cdn.sigstore.dev")
	v, calls = newVerifier(keyless)
	if root, warning, err := v.PrepareTrustedRoot(context.Background()); err != nil || warning != "" || root != filepath.Join(cache, "tuf-repo-cdn.sigstore.dev", "targets", "trusted_root.json") ||
		strings.Join((*calls)[0], " ") != "initialize --mirror https://tuf-repo-cdn.sigstore.dev" {
		t.Errorf("TUF_MIRROR, the default: %q %q %v %v", root, warning, err, *calls)
	}
	t.Setenv("TUF_MIRROR", "https://TUF.example/sigstore")
	v, _ = newVerifier(keyless)
	if root, _, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != filepath.Join(cache, "tuf.example-sigstore", "targets", "trusted_root.json") {
		t.Errorf("TUF_MIRROR, another: %q %v", root, err)
	}
	t.Setenv("TUF_MIRROR", "")
	if err := os.WriteFile(filepath.Join(cache, "remote.json"), []byte(`{"mirror":"https://tuf.example/sigstore"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	v, _ = newVerifier(keyless)
	if root, _, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != filepath.Join(cache, "tuf.example-sigstore", "targets", "trusted_root.json") {
		t.Errorf("remote.json: %q %v", root, err)
	}
	if err := os.Remove(filepath.Join(cache, "remote.json")); err != nil {
		t.Fatal(err)
	}
	v, _ = newVerifier(keyless)
	if root, _, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != filepath.Join(cache, "tuf-repo-cdn.sigstore.dev", "targets", "trusted_root.json") {
		t.Errorf("the default mirror: %q %v", root, err)
	}

	// Another layout: the newest trusted_root.json in the cache, which is
	// what cosign initialize (which clears the cache) just wrote.
	cache = t.TempDir()
	t.Setenv("TUF_ROOT", cache)
	put(t, cache, map[string]time.Time{
		"v2/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json": built.Add(time.Hour),
		"v2/old/trusted_root.json":                               built,
	})
	v, _ = newVerifier(keyless)
	if root, warning, err := v.PrepareTrustedRoot(context.Background()); err != nil || warning != "" || root != filepath.Join(cache, "v2", "tuf-repo-cdn.sigstore.dev", "targets", "trusted_root.json") {
		t.Errorf("another layout: %q %q %v", root, warning, err)
	}

	// None found: verifications go on without the flag, as before, and the
	// caller gets a warning to show, naming the way out.
	t.Setenv("TUF_ROOT", t.TempDir())
	v, calls = newVerifier(keyless)
	root, warning, err = v.PrepareTrustedRoot(context.Background())
	if err != nil || root != "" || len(*calls) != 1 || !strings.Contains(warning, "isn't in the TUF cache") || !strings.Contains(warning, "--trusted-root FILE") {
		t.Errorf("no cached file: %q %q %v %v", root, warning, err, *calls)
	}
	_, _ = v.Verify(context.Background(), Subject{Ref: digest, Kind: KindSignature, Signer: cert})
	if kl := strings.Join((*calls)[1], " "); strings.Contains(kl, "--trusted-root") {
		t.Errorf("verified against a root that wasn't found: %s", kl)
	}
}

// What the legacy TUF client (individual targets) says about its cache is
// about the trust root, not the evidence: unknown.
func TestLegacyTUFErrorsAreUnknown(t *testing.T) {
	for _, msg := range []string{
		"cosign verify: exit status 1: Error: initializing tuf client: unable to initialize client, local cache may be corrupt: tuf: failed to decode root.json: unexpected end of JSON input",
		"cosign verify: exit status 1: Error: tuf: failed to decode snapshot.json: invalid character",
		"cosign verify: exit status 1: Error: getting Fulcio roots: initializing tuf: open /root/.sigstore/root/tuf.db: resource temporarily unavailable",
	} {
		if status, _ := failure(classify(context.Background(), errors.New(msg)), "x"); status != "unknown" {
			t.Errorf("%q: %s, want unknown", msg, status)
		}
	}
	// A signature that doesn't verify is still failed.
	if status, _ := failure(classify(context.Background(), errors.New("cosign verify: exit status 1: Error: no matching signatures: invalid signature when validating ASN.1 encoded signature")), "x"); status != "failed" {
		t.Errorf("a bad signature: %s", status)
	}
}
