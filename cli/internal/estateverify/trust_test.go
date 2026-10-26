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
	r := reproduce(context.Background(), img, imageData{recipeVerified: true, recipeSigner: cert}, opts)
	// Bound to exactly the signer that verified the recipe the report shows,
	// not to a policy regexp another identity could also match.
	if r.Status != "reproduced" || got.Identity != cert.Identity || got.IdentityRegexp != "" || got.Issuer != ghIssuer ||
		got.SourceRepository != "https://github.com/acme/checkout" || got.SourceMatchesImage || got.SourceRepositoryOwner != "" {
		t.Errorf("reproduced %+v with signer %+v", r, got)
	}

	var args []string
	f := FactoryReproducer{Dir: t.TempDir(), Run: func(_ context.Context, _, _ string, a ...string) ([]byte, []byte, error) {
		args = a
		return []byte("reproducible: rebuilt " + digest + " matches\n"), nil, nil
	}}
	if _, err := f.Reproduce(context.Background(), "r@"+digest, got); err != nil || !strings.Contains(strings.Join(args, " "), "--certificate-github-workflow-repository acme/checkout") {
		t.Errorf("factory args %q, %v", args, err)
	}
}

type reproducerFunc func(context.Context, string, report.Signer) (string, error)

func (f reproducerFunc) Reproduce(ctx context.Context, ref string, s report.Signer) (string, error) {
	return f(ctx, ref, s)
}

// sourceRepositoryOwner must be exactly https://github.com/OWNER (a trailing
// slash allowed): anything else matched no certificate, silently, so every
// signature came out failed. It is refused when the policy is read, naming
// the form, wherever the signer comes from.
func TestSourceRepositoryOwnerIsValidated(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	signer := func(owner string) string {
		return "  - identityRegexp: ^https://github\\.com/acme/\n    issuer: " + ghIssuer + "\n    sourceRepositoryOwner: '" + owner + "'\n"
	}
	policies := map[string]func(owner string) string{
		"trustedSigners": func(owner string) string {
			return write("policy.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\ntrustedSigners:\n"+signer(owner))
		},
		"stackSigners": func(owner string) string {
			return write("policy.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nstackSigners:\n"+signer(owner))
		},
		"trust policy": func(owner string) string {
			write("trust.yaml", "apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n"+signer(owner))
			return write("policy.yaml", "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\ntrustPolicy: trust.yaml\n")
		},
	}
	for where, policy := range policies {
		for _, owner := range []string{"https://github.com/acme", "https://github.com/acme/"} {
			if _, err := ReadPolicy(policy(owner)); err != nil {
				t.Errorf("%s: %q refused: %v", where, owner, err)
			}
		}
		for _, owner := range []string{
			"https://github.com/acme/repo", // a repository, not an owner
			"github.com/acme",              // no scheme
			"http://github.com/acme",
			"https://github.com/", // no owner
			"https://gitlab.com/acme",
			"acme",
		} {
			_, err := ReadPolicy(policy(owner))
			if err == nil || !strings.Contains(err.Error(), "sourceRepositoryOwner \""+owner+"\" must be https://github.com/OWNER") {
				t.Errorf("%s: %q: got %v, want it refused naming https://github.com/OWNER", where, owner, err)
			}
		}
	}
}
