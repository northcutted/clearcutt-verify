package estateverify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
// keyless signer is trusted and nothing else supplies one, and every keyless
// verification then reads it from the file.
func TestPrepareTrustedRoot(t *testing.T) {
	cache := t.TempDir()
	rootFile := filepath.Join(cache, "tuf-repo-cdn.sigstore.dev", "targets", "trusted_root.json")
	if err := os.MkdirAll(filepath.Dir(rootFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootFile, []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUF_ROOT", cache)
	t.Setenv("TUF_MIRROR", "")
	for _, name := range sigstoreTargetVars {
		t.Setenv(name, "")
	}
	keyless := report.Signer{IdentityRegexp: `^https://github\.com/acme/`, Issuer: ghIssuer}
	key := report.Signer{Key: "acme.pub"}
	cert := &report.Signer{Identity: ourSigner, Issuer: ghIssuer, SourceRepository: "https://github.com/acme/images"}
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

	v, calls := newVerifier(keyless, key)
	root, err := v.PrepareTrustedRoot(context.Background())
	if err != nil || root != rootFile || v.TrustedRoot != rootFile || len(*calls) != 1 || strings.Join((*calls)[0], " ") != "initialize" {
		t.Fatalf("root %q, %v, calls %v", root, err, *calls)
	}
	if root2, err := v.PrepareTrustedRoot(context.Background()); err != nil || root2 != rootFile || len(*calls) != 1 {
		t.Errorf("fetched again: %q %v %v", root2, err, *calls)
	}
	// Keyless verifications read the file; key verifications don't.
	_, _ = v.Verify(context.Background(), Subject{Ref: "r@sha256:" + strings.Repeat("a", 64), Kind: KindSignature, Signer: cert})
	_, _ = v.Verify(context.Background(), Subject{Ref: "r@sha256:" + strings.Repeat("a", 64), Kind: KindSignature, Signer: &report.Signer{Key: "x"}})
	if len(*calls) != 3 {
		t.Fatalf("calls %v", *calls)
	}
	if kl := strings.Join((*calls)[1], " "); !strings.Contains(kl, "--trusted-root "+rootFile) || !strings.HasSuffix(kl, "r@sha256:"+strings.Repeat("a", 64)) {
		t.Errorf("keyless verification: %s", kl)
	}
	if ky := strings.Join((*calls)[2], " "); strings.Contains(ky, "--trusted-root") || !strings.Contains(ky, "--key acme.pub") {
		t.Errorf("key verification: %s", ky)
	}

	// Only keys: nothing to fetch.
	v, calls = newVerifier(key)
	if root, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != "" || len(*calls) != 0 {
		t.Errorf("keys only: %q %v %v", root, err, *calls)
	}
	// A root given: used as is.
	v, calls = newVerifier(keyless)
	v.TrustedRoot = "/etc/sigstore/trusted_root.json"
	if root, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != v.TrustedRoot || len(*calls) != 0 {
		t.Errorf("given root: %q %v %v", root, err, *calls)
	}
	// Individual targets in the environment: left to cosign.
	t.Setenv("SIGSTORE_ROOT_FILE", "/etc/sigstore/root.pem")
	v, calls = newVerifier(keyless)
	if root, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != "" || len(*calls) != 0 {
		t.Errorf("individual targets: %q %v %v", root, err, *calls)
	}
	t.Setenv("SIGSTORE_ROOT_FILE", "")
	// A mirror in the environment is passed on.
	t.Setenv("TUF_MIRROR", "https://tuf.example")
	v, calls = newVerifier(keyless)
	if _, err := v.PrepareTrustedRoot(context.Background()); err != nil || strings.Join((*calls)[0], " ") != "initialize --mirror https://tuf.example" {
		t.Errorf("mirror: %v %v", err, *calls)
	}
	t.Setenv("TUF_MIRROR", "")
	// The fetch failing is an operational error naming the fix.
	v, _ = newVerifier(keyless)
	v.Run = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New(`Get "https://tuf-repo-cdn.sigstore.dev/root.json": dial tcp: i/o timeout`)
	}
	if _, err := v.PrepareTrustedRoot(context.Background()); err == nil || !strings.Contains(err.Error(), "cosign initialize") || !strings.Contains(err.Error(), "--trusted-root") {
		t.Errorf("fetch failing: %v", err)
	}
	// No cached file found: verifications go on without the flag (cosign's
	// cache is warm anyway).
	t.Setenv("TUF_ROOT", t.TempDir())
	v, calls = newVerifier(keyless)
	if root, err := v.PrepareTrustedRoot(context.Background()); err != nil || root != "" || len(*calls) != 1 {
		t.Errorf("no cached file: %q %v %v", root, err, *calls)
	}
}
