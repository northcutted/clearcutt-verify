package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// pushBundle stores a report bundle named name with estate push and returns
// its digest (bundles with the same name have the same digest).
func pushBundle(t *testing.T, ref, name string) string {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "estate-report.json"), []byte(`{"kind":"EstateReport","metadata":{"name":"`+name+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t, "estate", "push", ref, "--dir", src, "--file", "estate-report.json", "--insecure")
	if err != nil {
		t.Fatalf("estate push: %v\n%s", err, stdout)
	}
	for _, line := range strings.Split(stdout, "\n") {
		if d, ok := strings.CutPrefix(line, "[estate] digest "); ok {
			return strings.TrimSpace(d)
		}
	}
	t.Fatalf("no digest in:\n%s", stdout)
	return ""
}

// signWithKey attaches a cosign v2 signature tag (no certificate: a key
// signed it) to repo@digest.
func signWithKey(t *testing.T, repo, digest string) {
	t.Helper()
	payload := `{"critical":{"identity":{"docker-reference":"` + repo + `"},"image":{"docker-manifest-digest":"` + digest + `"},"type":"cosign container image signature"},"optional":null}`
	img, err := mutate.Append(mutate.MediaType(empty.Image, types.OCIManifestSchema1), mutate.Addendum{
		Layer: static.NewLayer([]byte(payload), "application/vnd.dev.cosign.simplesigning.v1+json"), Annotations: map[string]string{"dev.cosignproject.cosign/signature": "c2ln"}})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := name.ParseReference(repo + ":" + strings.Replace(digest, ":", "-", 1) + ".sig")
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
}

// keyCosign verifies, as cosign verify --key does, signatures the key
// ending in trusted.pub made; it is offline when told so.
func keyCosign(offline *bool) func(args []string) ([]byte, error) {
	return func(args []string) ([]byte, error) {
		if *offline {
			return nil, errors.New(`error during command execution: Get "https://registry/v2/": dial tcp: lookup registry: no such host`)
		}
		ref := args[len(args)-1]
		_, digest, _ := strings.Cut(ref, "@")
		for i, a := range args {
			if a == "--key" && strings.HasSuffix(args[i+1], "trusted.pub") && args[0] == "verify" {
				return []byte(`[{"critical":{"image":{"docker-manifest-digest":"` + digest + `"},"type":"cosign container image signature"}}]`), nil
			}
		}
		return nil, errors.New("error during command execution: no matching signatures: invalid signature when validating ASN.1 encoded signature")
	}
}

// TestEstatePullVerifiesTheSignature: estate pull writes a bundle only once
// cosign verified its signature against the signer named on the command
// line. Before, it checked only the artifact's media type, so anyone who
// could push to the repository could feed the next run a forged history.
func TestEstatePullVerifiesTheSignature(t *testing.T) {
	offline := false
	withCosign(t, "", keyCosign(&offline))
	host := estateTestRegistry(t)
	signed, unsigned := host+"/acme/estate:latest", host+"/acme/estate:unsigned"
	digest := pushBundle(t, signed, "signed")
	signWithKey(t, host+"/acme/estate", digest)
	pushBundle(t, unsigned, "unsigned")
	t.Setenv("GITHUB_ACTIONS", "")

	pull := func(ref string, args ...string) (string, string, error) {
		t.Helper()
		dir := t.TempDir()
		stdout, err := runCLI(t, append([]string{"estate", "pull", ref, "--output", dir, "--insecure"}, args...)...)
		return stdout, dir, err
	}
	wrote := func(dir string) bool {
		_, err := os.Stat(filepath.Join(dir, "estate-report.json"))
		return err == nil
	}

	stdout, dir, err := pull(signed, "--key", "keys/trusted.pub")
	if err != nil || !wrote(dir) || !strings.Contains(stdout, "signature verified: key keys/trusted.pub") {
		t.Errorf("signed by the named key: %v\n%s", err, stdout)
	}

	for _, tc := range []struct {
		name, ref, want string
		args            []string
	}{
		{"no signer named", signed, "--certificate-identity", nil},
		{"another key", signed, "its signature is failed", []string{"--key", "keys/other.pub"}},
		{"unsigned", unsigned, "its signature is missing", []string{"--key", "keys/trusted.pub"}},
	} {
		stdout, dir, err := pull(tc.ref, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) || wrote(dir) {
			t.Errorf("%s: got %v (wrote %v), want a refusal saying %q\n%s", tc.name, err, wrote(dir), tc.want, stdout)
		}
	}

	offline = true
	if stdout, dir, err := pull(signed, "--key", "keys/trusted.pub"); err == nil || !strings.Contains(err.Error(), "unknown") || !strings.Contains(err.Error(), "cosign couldn't check it") || wrote(dir) {
		t.Errorf("cosign offline: %v\n%s", err, stdout)
	}
	offline = false

	// The opt-out writes it, and says so where it can't be missed.
	t.Setenv("GITHUB_ACTIONS", "true")
	for _, args := range [][]string{{"--allow-unverified"}, {"--key", "keys/other.pub", "--allow-unverified"}} {
		stdout, dir, err := pull(signed, args...)
		if err != nil || !wrote(dir) || !strings.Contains(stdout, "WARNING") || !strings.Contains(stdout, "NOT verified") || !strings.Contains(stdout, "::warning") {
			t.Errorf("%v: %v\n%s", args, err, stdout)
		}
	}
}

// TestEstatePullSignerFlags: the signer is named the way cosign verify
// takes it, and the same identities are refused as in a trust policy.
func TestEstatePullSignerFlags(t *testing.T) {
	withCosign(t, "", nil)
	host := estateTestRegistry(t)
	const issuer = "https://token.actions.githubusercontent.com"
	const identity = "https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--key", "k.pub", "--certificate-identity", identity}, "not both"},
		{[]string{"--certificate-identity", identity}, "needs --certificate-identity"},
		{[]string{"--certificate-oidc-issuer", issuer}, "needs --certificate-identity"},
		{[]string{"--certificate-identity", identity, "--certificate-identity-regexp", "^https://github\\.com/acme/", "--certificate-oidc-issuer", issuer}, "exclusive"},
		{[]string{"--certificate-identity-regexp", ".*", "--certificate-oidc-issuer", issuer}, "wildcard"},
		{[]string{"--certificate-identity-regexp", "https://github\\.com/acme/", "--certificate-oidc-issuer", issuer}, "unanchored"},
		{[]string{"--insecure-ignore-tlog"}, "applies to --key"},
		{[]string{"--certificate-identity", identity, "--certificate-oidc-issuer", issuer, "--insecure-ignore-tlog"}, "applies to --key"},
		{[]string{"--certificate-identity", identity, "--certificate-oidc-issuer", "https://accounts.example", "--certificate-github-workflow-repository", "acme/estate"}, "GitHub Actions issuer"},
	} {
		if stdout, err := runCLI(t, append([]string{"estate", "pull", host + "/acme/estate:latest", "--output", t.TempDir(), "--insecure"}, tc.args...)...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: got %v, want %q\n%s", tc.args, err, tc.want, stdout)
		}
	}
	// No cosign: refused before anything is pulled.
	if _, err := runCLI(t, "estate", "pull", host+"/acme/estate:latest", "--output", t.TempDir(), "--insecure", "--key", "k.pub", "--cosign-path", filepath.Join(t.TempDir(), "cosign")); err == nil {
		t.Error("pulled with no cosign to check the signature")
	}
	withCosign(t, "v2.4.0", nil)
	if _, err := runCLI(t, "estate", "pull", host+"/acme/estate:latest", "--output", t.TempDir(), "--insecure", "--key", "k.pub"); err == nil || !strings.Contains(err.Error(), "too old") {
		t.Errorf("cosign v2: %v", err)
	}
}
