package estateverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// Verifier checks evidence with cosign against trusted signers. cosign does
// the cryptography (certificate chain, transparency log, signature), as it
// does everywhere else in ClearCutt, so trust roots stay cosign's.
type Verifier struct {
	Signers []report.Signer
	// Cosign is the cosign binary (default "cosign").
	Cosign string
	// Run executes cosign and returns stdout; tests replace it.
	Run func(ctx context.Context, bin string, args ...string) ([]byte, error)
}

// ErrNoSigner means no trusted signer was configured, so evidence can only
// be present, never verified.
var ErrNoSigner = errors.New("no trusted signer configured")

// Subject is the evidence to verify and what is known about its image.
type Subject struct {
	// Ref is repository@digest.
	Ref string
	// Kind is the evidence kind, PredicateType its predicate (attestations).
	Kind, PredicateType string
	// ImageSource is the repository the image names as its source
	// (org.opencontainers.image.source), for signers with
	// sourceMatchesImage.
	ImageSource string
	// Signer is who signed the evidence found, as its certificate says.
	Signer *report.Signer
}

// Verify checks the evidence with cosign and returns the trusted signer
// that verified it.
func (v *Verifier) Verify(ctx context.Context, subj Subject) (report.Signer, error) {
	if len(v.Signers) == 0 {
		return report.Signer{}, ErrNoSigner
	}
	var errs []string
	for _, s := range v.Signers {
		flags, err := signerFlags(s)
		if err != nil {
			return report.Signer{}, err
		}
		caller, err := callerFlags(s, subj)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		args := []string{"verify-attestation", "--type", subj.PredicateType}
		if subj.Kind == KindSignature {
			args = []string{"verify"}
		}
		args = append(append(append(append(args, "--output", "json"), flags...), caller...), subj.Ref)
		if _, err := v.run(ctx, args...); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return s, nil
	}
	return report.Signer{}, fmt.Errorf("not signed by a trusted signer: %s", strings.Join(errs, "; "))
}

// callerFlags turns a signer's constraints on the run that signed into
// cosign flags. cosign checks one exact repository, so an owner or the
// image's source is first resolved to the repository it must be: the
// image's source, or the repository on the certificate found, when it is
// one of the owner's.
func callerFlags(s report.Signer, subj Subject) ([]string, error) {
	repo, err := resolveRepository(s, subj)
	if err != nil {
		return nil, err
	}
	var flags []string
	if repo != "" {
		flags = append(flags, "--certificate-github-workflow-repository", strings.TrimPrefix(repo, "https://github.com/"))
	}
	if s.SourceRef != "" {
		flags = append(flags, "--certificate-github-workflow-ref", s.SourceRef)
	}
	return flags, nil
}

// resolveRepository returns the one repository (https://github.com/OWNER/REPO)
// whose workflow runs the signer accepts for this evidence, or "" when the
// signer doesn't constrain the caller.
func resolveRepository(s report.Signer, subj Subject) (string, error) {
	repo := s.SourceRepository
	if s.SourceMatchesImage {
		src := strings.TrimSuffix(strings.TrimSuffix(subj.ImageSource, "/"), ".git")
		switch {
		case src == "":
			return "", errors.New("the image names no source repository (org.opencontainers.image.source), and the signer requires the run to be in it")
		case repo != "" && repo != src:
			return "", fmt.Errorf("the image names %s as its source, not %s", src, repo)
		}
		repo = src
	}
	if s.SourceRepositoryOwner != "" {
		if repo == "" && subj.Signer != nil {
			repo = subj.Signer.SourceRepository
		}
		if !strings.HasPrefix(repo, strings.TrimSuffix(s.SourceRepositoryOwner, "/")+"/") {
			return "", fmt.Errorf("signed in %q, not a repository of %s", repo, s.SourceRepositoryOwner)
		}
	}
	if repo != "" {
		name, ok := strings.CutPrefix(repo, "https://github.com/")
		if !ok || strings.Count(name, "/") != 1 {
			return "", fmt.Errorf("source repository %q is not https://github.com/OWNER/REPO", repo)
		}
	}
	return repo, nil
}

// constrainsCaller reports whether the signer says which runs may sign.
func constrainsCaller(s report.Signer) bool {
	return s.SourceRepository != "" || s.SourceRepositoryOwner != "" || s.SourceMatchesImage
}

// calledFromElsewhere reports whether the certificate's run was in another
// repository than the workflow that signed: a reusable workflow, which any
// repository can call. It returns that repository.
func calledFromElsewhere(cert *report.Signer) (string, bool) {
	if cert == nil || cert.SourceRepository == "" {
		return "", false
	}
	return cert.SourceRepository, !strings.HasPrefix(cert.Identity, cert.SourceRepository+"/")
}

func (v *Verifier) run(ctx context.Context, args ...string) ([]byte, error) {
	bin := v.Cosign
	if bin == "" {
		bin = "cosign"
	}
	if v.Run != nil {
		return v.Run(ctx, bin, args...)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cosign %s: %v: %s", args[0], err, lastLine(stderr.String()))
	}
	return out, nil
}

// signerFlags turns a trusted signer into cosign flags. Like the rest of
// ClearCutt, it refuses identities that would let anyone verify.
func signerFlags(s report.Signer) ([]string, error) {
	if s.Key != "" {
		return []string{"--key", s.Key}, nil
	}
	id := strings.TrimSpace(s.IdentityRegexp)
	if id == "" {
		id = strings.TrimSpace(s.Identity)
	}
	switch id {
	case "", ".*", ".+", "^.*$", "https://github.com/.*", "^https://github.com/.*":
		return nil, fmt.Errorf("refusing a trusted signer with an empty or wildcard identity (%q): name the workflow or organization", id)
	}
	if strings.TrimSpace(s.Issuer) == "" {
		return nil, fmt.Errorf("trusted signer %q has no OIDC issuer (e.g. https://token.actions.githubusercontent.com)", id)
	}
	if (constrainsCaller(s) || s.SourceRef != "") && s.Issuer != githubIssuer {
		return nil, fmt.Errorf("trusted signer %q: source constraints need the GitHub Actions issuer (%s)", id, githubIssuer)
	}
	if s.IdentityRegexp != "" {
		return []string{"--certificate-identity-regexp", s.IdentityRegexp, "--certificate-oidc-issuer", s.Issuer}, nil
	}
	return []string{"--certificate-identity", s.Identity, "--certificate-oidc-issuer", s.Issuer}, nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
