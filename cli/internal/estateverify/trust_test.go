package estateverify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

const trustYAML = `apiVersion: clearcutt.dev/v1
kind: TrustPolicy
signers:
  - name: factory-builds
    identityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v
    issuer: https://token.actions.githubusercontent.com
    sourceRepositoryOwner: https://github.com/acme
    sourceMatchesImage: true
  - name: platform-stacks
    roles: [stack]
    identity: https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main
    issuer: https://token.actions.githubusercontent.com
`

func TestReadTrustPolicy(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tp, err := ReadTrustPolicy(write("trust.yaml", trustYAML))
	if err != nil {
		t.Fatal(err)
	}
	images, stacks := tp.For("image"), tp.For("stack")
	if len(images) != 1 || !images[0].SourceMatchesImage || len(stacks) != 1 || stacks[0].Identity == "" {
		t.Errorf("roles: images %+v stacks %+v", images, stacks)
	}

	// A verification policy can name it; its image signers join the policy's.
	p, err := ReadPolicy(write("policy.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [signature]\ntrustPolicy: trust.yaml\n"))
	if err != nil || len(p.TrustedSigners) != 1 || p.TrustedSigners[0].SourceRepositoryOwner != "https://github.com/acme" {
		t.Errorf("policy with a trust policy: %+v %v", p.TrustedSigners, err)
	}

	for body, want := range map[string]string{
		"apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\n":                                               "expected apiVersion",
		"apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{roles: [admin], identity: x, issuer: y}]\n": "role \"admin\"",
		"apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{identityRegexp: '.*', issuer: y}]\n":        "wildcard",
		"apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners: [{identity: x, issuer: y, color: red}]\n":     "unknown field",
	} {
		if _, err := ReadTrustPolicy(write("bad.yaml", body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", body, err, want)
		}
	}
	if _, err := ReadPolicy(write("p2.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\ntrustPolicy: missing.yaml\n")); err == nil {
		t.Error("read a policy naming a missing trust policy")
	}
}

// The rebuild is bound to the repository the evidence was verified against.
func TestReproduceBindsTheRepository(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	var got report.Signer
	rep := reproducerFunc(func(_ context.Context, _ string, s report.Signer) (string, error) {
		got = s
		return digest, nil
	})
	img := &report.Image{Repository: "ghcr.io/acme/apps/checkout", Digest: digest, Evidence: report.Evidence{Recipe: report.EvidenceItem{Status: "verified"}, Rebase: report.EvidenceItem{Status: "not-applicable"}}}
	trusted := report.Signer{IdentityRegexp: `^https://github\.com/northcutted/clearcutt-factory/`, Issuer: ghIssuer, SourceRepositoryOwner: "https://github.com/acme", SourceMatchesImage: true}
	cert := &report.Signer{Identity: "https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v0.1.1", Issuer: ghIssuer, SourceRepository: "https://github.com/acme/checkout"}
	opts := Options{Reproducer: rep, Policy: report.Policy{Reproduce: true, TrustedSigners: []report.Signer{trusted}}}
	r := reproduce(context.Background(), img, imageData{recipeVerified: true, recipeSigner: cert, claimedSource: "https://github.com/acme/checkout"}, opts)
	if r.Status != "reproduced" || got.SourceRepository != "https://github.com/acme/checkout" || got.SourceMatchesImage || got.SourceRepositoryOwner != "" {
		t.Errorf("reproduced %+v with signer %+v", r, got)
	}

	var args []string
	f := FactoryReproducer{Dir: t.TempDir(), Run: func(_ context.Context, _, _ string, a ...string) ([]byte, error) {
		args = a
		return []byte("rebuilt " + digest), nil
	}}
	if _, err := f.Reproduce(context.Background(), "r@"+digest, got); err != nil || !strings.Contains(strings.Join(args, " "), "--certificate-github-workflow-repository acme/checkout") {
		t.Errorf("factory args %q, %v", args, err)
	}
}

type reproducerFunc func(context.Context, string, report.Signer) (string, error)

func (f reproducerFunc) Reproduce(ctx context.Context, ref string, s report.Signer) (string, error) {
	return f(ctx, ref, s)
}
