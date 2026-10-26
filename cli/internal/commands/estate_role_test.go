package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEstatePullAndHistoryUseTheEstateRole: a trust policy's signers with
// role estate are who may have signed what estate pull and estate history
// read, named with --trust-policy or through --policy's trustPolicy; the
// history index is verified like a bundle, and refused when nobody trusted
// signed it.
func TestEstatePullAndHistoryUseTheEstateRole(t *testing.T) {
	host := estateTestRegistry(t)
	offline := false
	withCosign(t, "", keyCosign(&offline))
	dir := t.TempDir()
	for _, f := range []string{"trusted.pub", "other.pub"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("key"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	trust := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trust, []byte(`apiVersion: clearcutt.dev/v1
kind: TrustPolicy
signers:
  - name: images
    identityRegexp: ^https://github\.com/acme/
    issuer: https://token.actions.githubusercontent.com
  - name: estate-job
    roles: [estate]
    key: trusted.pub
    tlog: false
`), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [signature]\ntrustPolicy: trust.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	imagesOnly := filepath.Join(dir, "images-only.yaml")
	if err := os.WriteFile(imagesOnly, []byte("apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - identityRegexp: ^https://github\\.com/acme/\n    issuer: https://token.actions.githubusercontent.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A bundle, signed by the estate job's key.
	ref := host + "/acme/estate:latest"
	digest := pushBundle(t, ref, "acme")
	signWithKey(t, host+"/acme/estate", digest)
	for _, flags := range [][]string{{"--trust-policy", trust}, {"--policy", policy}} {
		out := t.TempDir()
		stdout, err := runCLI(t, append([]string{"estate", "pull", ref, "--output", out, "--insecure"}, flags...)...)
		if err != nil || !strings.Contains(stdout, "signature verified: key") {
			t.Errorf("pull with %v: %v\n%s", flags, err, stdout)
		}
	}
	// A trust policy with no estate signer names nobody.
	if _, err := runCLI(t, "estate", "pull", ref, "--output", t.TempDir(), "--insecure", "--trust-policy", imagesOnly); err == nil || !strings.Contains(err.Error(), "role estate") {
		t.Errorf("no estate signer: %v", err)
	}
	// The policy flags and cosign's are exclusive.
	if _, err := runCLI(t, "estate", "pull", ref, "--output", t.TempDir(), "--insecure", "--trust-policy", trust, "--key", "trusted.pub"); err == nil || !strings.Contains(err.Error(), "exclusive") {
		t.Errorf("policy with cosign flags: %v", err)
	}

	// A history index: appended to by estate push, then signed.
	snap := t.TempDir()
	if err := os.WriteFile(filepath.Join(snap, "graph.json"), []byte(`{"summary":{"observedImages":3,"resolvedConsumers":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	historyRef := host + "/acme/estate:history"
	stdout, err := runCLI(t, "estate", "push", host+"/acme/estate:day-1", "--dir", snap, "--generated-at", "2026-10-26T00:00:00Z", "--history", historyRef, "--insecure")
	if err != nil {
		t.Fatalf("push: %v\n%s", err, stdout)
	}
	historyDigest := ""
	for _, line := range strings.Split(stdout, "\n") {
		if _, rest, ok := strings.Cut(line, "appended to history "); ok {
			historyDigest = strings.TrimSuffix(strings.TrimSpace(rest[strings.LastIndex(rest, "(")+1:]), ")")
		}
	}
	if !strings.HasPrefix(historyDigest, "sha256:") {
		t.Fatalf("no history digest in:\n%s", stdout)
	}
	// Unsigned: refused, unless allowed.
	if _, err := runCLI(t, "estate", "history", historyRef, "--insecure", "--trust-policy", trust); err == nil || !strings.Contains(err.Error(), "refusing the history index") {
		t.Errorf("unsigned history: %v", err)
	}
	if stdout, err := runCLI(t, "estate", "history", historyRef, "--insecure", "--trust-policy", trust, "--allow-unverified"); err != nil || !strings.Contains(stdout, "NOT verified") {
		t.Errorf("unsigned history, allowed: %v\n%s", err, stdout)
	}
	signWithKey(t, host+"/acme/estate", historyDigest)
	stdout, err = runCLI(t, "estate", "history", historyRef, "--insecure", "--trust-policy", trust)
	if err != nil || !strings.Contains(stdout, "history index signature verified: key") || !strings.Contains(stdout, "one snapshot so far") {
		t.Errorf("signed history: %v\n%s", err, stdout)
	}
	// Signed by the wrong key, or a cosign that couldn't check: refused.
	if _, err := runCLI(t, "estate", "history", historyRef, "--insecure", "--key", filepath.Join(dir, "other.pub"), "--insecure-ignore-tlog"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("wrong key: %v", err)
	}
	offline = true
	if _, err := runCLI(t, "estate", "history", historyRef, "--insecure", "--trust-policy", trust); err == nil || errors.Is(err, ErrCheckFailed) || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("cosign offline: %v", err)
	}
}
