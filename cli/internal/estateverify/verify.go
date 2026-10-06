package estateverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/northcutted/clearcutt/internal/report"
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

// Verify checks the evidence of kind (with predicateType, for
// attestations) on ref (repository@digest). It returns the trusted signer
// that verified it.
func (v *Verifier) Verify(ctx context.Context, ref, kind, predicateType string) (report.Signer, error) {
	if len(v.Signers) == 0 {
		return report.Signer{}, ErrNoSigner
	}
	var errs []string
	for _, s := range v.Signers {
		flags, err := signerFlags(s)
		if err != nil {
			return report.Signer{}, err
		}
		args := []string{"verify-attestation", "--type", predicateType}
		if kind == KindSignature {
			args = []string{"verify"}
		}
		args = append(append(append(args, "--output", "json"), flags...), ref)
		if _, err := v.run(ctx, args...); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return s, nil
	}
	return report.Signer{}, fmt.Errorf("not signed by a trusted signer: %s", strings.Join(errs, "; "))
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
	if s.IdentityRegexp != "" {
		return []string{"--certificate-identity-regexp", s.IdentityRegexp, "--certificate-oidc-issuer", s.Issuer}, nil
	}
	return []string{"--certificate-identity", s.Identity, "--certificate-oidc-issuer", s.Issuer}, nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
