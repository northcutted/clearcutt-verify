package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"

	"github.com/northcutted/clearcutt-verify/internal/registryauth"
)

// verify_release_evidence.go ports the since-removed
// core/scripts/verify-release-evidence.mjs into the CLI. It verifies one published image ref against the registry: resolved
// digest, Sigstore keyless signature, SBOM + test-results attestations, SLSA
// provenance, and GitHub-native provenance. Identity is matched EXACTLY
// (--certificate-identity, not -regexp) — this is a security gate, so it does not
// reuse the regexp-based sign.Cosign verify helpers.

type releaseEvidenceFlags struct {
	ref              string
	digest           string
	repo             string
	workflowIdentity string
	oidcIssuer       string
	sourceRef        string
	sourceBranch     string
	outPath          string
}

var releaseEvidenceOpts releaseEvidenceFlags

var releaseEvidenceResolveDigest = func(ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	desc, err := remote.Head(r, remote.WithAuthFromKeychain(registryauth.Keychain))
	if err != nil {
		return "", err
	}
	digest := desc.Digest.String()
	if strings.TrimSpace(digest) == "" {
		return "", fmt.Errorf("registry returned an empty digest for %s", ref)
	}
	return digest, nil
}

// VerifyEvidenceResponse is the structured payload for --format json|yaml,
// a checklist of each verification.
type VerifyEvidenceResponse struct {
	Status string              `json:"status"` // pass or fail
	Ref    string              `json:"ref"`
	Digest string              `json:"digest,omitempty"`
	Checks []VerifyCheckResult `json:"checks"`
}

func NewVerifyReleaseEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release-evidence",
		Short: "Verify a published image ref carries complete Sigstore + SLSA release evidence",
		Long: `Verifies one published ClearCutt image reference directly against the registry:
the Go-resolved registry digest (optionally matched against --digest), the Sigstore
keyless signature, the SPDX SBOM and test-results attestations, the SLSA
provenance (slsa-verifier), and the GitHub-native provenance attestation. The
signer is matched exactly against --workflow-identity. By default it uses
cosign, slsa-verifier, and gh from PATH. Pass --core-dir to run those verifier
tools from the scaffolded ClearCutt Nix dev shell instead.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerifyReleaseEvidence()
		},
	}
	f := cmd.Flags()
	f.StringVar(&releaseEvidenceOpts.ref, "ref", "", "Image reference to verify (required)")
	f.StringVar(&releaseEvidenceOpts.digest, "digest", "", "Expected image digest (sha256:...), matched against the resolved digest")
	f.StringVar(&releaseEvidenceOpts.repo, "repo", "", "owner/repo the image was built from (required)")
	f.StringVar(&releaseEvidenceOpts.workflowIdentity, "workflow-identity", "", "Exact Sigstore certificate identity of the release workflow (required)")
	f.StringVar(&releaseEvidenceOpts.oidcIssuer, "oidc-issuer", "https://token.actions.githubusercontent.com", "Sigstore certificate OIDC issuer")
	f.StringVar(&releaseEvidenceOpts.sourceRef, "source-ref", "refs/heads/main", "Source ref for GitHub-native provenance verification")
	f.StringVar(&releaseEvidenceOpts.sourceBranch, "source-branch", "", "Source branch for slsa-verifier (defaults to --source-ref without refs/heads/)")
	f.StringVar(&releaseEvidenceOpts.outPath, "out", "", "Write the machine-readable verification checklist to this JSON file")
	_ = cmd.MarkFlagRequired("ref")
	_ = cmd.MarkFlagRequired("repo")
	_ = cmd.MarkFlagRequired("workflow-identity")
	return cmd
}

// evidenceImageRepository strips any @digest and tag, mirroring imageRepository().
func evidenceImageRepository(ref string) string {
	withoutDigest := strings.SplitN(ref, "@", 2)[0]
	lastColon := strings.LastIndex(withoutDigest, ":")
	lastSlash := strings.LastIndex(withoutDigest, "/")
	if lastColon > lastSlash {
		return withoutDigest[:lastColon]
	}
	return withoutDigest
}

// evidenceRun mirrors the .mjs run(): non-captured stdout is streamed to
// io.Discard (cosign verify-attestation prints multi-MB DSSE payloads even on
// success), prints failure detail on stderr, and returns captured stdout.
func evidenceRun(label, name string, args []string, captureStdout bool) (string, error) {
	cmdName, cmdArgs := name, args
	cmd := exec.Command(cmdName, cmdArgs...)
	var stdoutBuf, stderrBuf bytes.Buffer
	if captureStdout {
		cmd.Stdout = &stdoutBuf
	} else {
		cmd.Stdout = io.Discard
	}
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(errOut, "[evidence] failed: %s\n", label)
		detail := strings.TrimSpace(strings.Join([]string{stdoutBuf.String(), stderrBuf.String()}, "\n"))
		if detail != "" {
			fmt.Fprintln(errOut, detail)
		}
		// A verifier that ran and rejected the evidence is a policy gate
		// failure (exit 2); a verifier that could not run at all (e.g. cosign
		// missing from PATH) is an operational error (exit 1).
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("release evidence check failed: %s: %w", label, ErrCheckFailed)
		}
		return "", fmt.Errorf("release evidence tool %q could not run (%s): %w", cmdName, label, err)
	}
	return stdoutBuf.String(), nil
}

func runVerifyReleaseEvidence() error {
	o := releaseEvidenceOpts
	sourceBranch := o.sourceBranch
	if sourceBranch == "" {
		sourceBranch = strings.TrimPrefix(o.sourceRef, "refs/heads/")
	}

	checks := []VerifyCheckResult{}
	resolvedDigest := ""
	addCheck := func(id, status, message string) {
		checks = append(checks, VerifyCheckResult{ID: id, Status: status, Message: message})
		if status == "pass" && !structuredFormat() {
			fmt.Fprintf(out, "[evidence] ok: %s\n", message)
		}
	}
	// finish emits the structured payload (when requested) before surfacing the
	// verification verdict, so json/yaml consumers always get a complete
	// check-list even on the first failed gate.
	finish := func(failErr error) error {
		response := VerifyEvidenceResponse{
			Status: "pass",
			Ref:    o.ref,
			Digest: resolvedDigest,
			Checks: checks,
		}
		if failErr != nil {
			response.Status = "fail"
		}
		if o.outPath != "" {
			if err := writeVerifyEvidenceResponse(o.outPath, response); err != nil {
				return err
			}
		}
		if structuredFormat() {
			if err := printStructured(response); err != nil {
				return err
			}
		}
		return failErr
	}
	step := func(id, label, name string, args []string, captureStdout bool) (string, error) {
		stdout, err := evidenceRun(label, name, args, captureStdout)
		if err != nil {
			addCheck(id, "fail", label)
			return "", err
		}
		addCheck(id, "pass", label)
		return stdout, nil
	}

	resolved, err := releaseEvidenceResolveDigest(o.ref)
	if err != nil {
		addCheck("digest.resolve", "fail", "resolve image digest")
		return finish(fmt.Errorf("release evidence digest resolution failed for %s: %w", o.ref, err))
	}
	resolvedDigest = strings.TrimSpace(resolved)
	addCheck("digest.resolve", "pass", "resolve image digest")
	if o.digest != "" && resolvedDigest != o.digest {
		fmt.Fprintf(errOut, "[evidence] digest mismatch for %s: got %s, expected %s\n", o.ref, resolvedDigest, o.digest)
		checks = append(checks, VerifyCheckResult{
			ID:      "digest.match",
			Status:  "fail",
			Message: fmt.Sprintf("digest mismatch for %s: got %s, expected %s", o.ref, resolvedDigest, o.digest),
		})
		return finish(ErrCheckFailed)
	}

	digestToUse := resolvedDigest
	if o.digest != "" {
		digestToUse = o.digest
		addCheck("digest.match", "pass", fmt.Sprintf("%s resolves to expected digest %s", o.ref, o.digest))
	}
	immutableRef := evidenceImageRepository(o.ref) + "@" + digestToUse

	if _, err := step("signature.keyless", "Sigstore keyless signature", "cosign", []string{
		"verify", immutableRef,
		"--certificate-identity", o.workflowIdentity,
		"--certificate-oidc-issuer", o.oidcIssuer,
		"--output", "json",
	}, false); err != nil {
		return finish(err)
	}

	if _, err := step("attestation.sbom", "SPDX SBOM attestation", "cosign", []string{
		"verify-attestation", immutableRef,
		"--type", "spdxjson",
		"--certificate-identity", o.workflowIdentity,
		"--certificate-oidc-issuer", o.oidcIssuer,
	}, false); err != nil {
		return finish(err)
	}

	if _, err := step("attestation.tests", "test-results attestation", "cosign", []string{
		"verify-attestation", immutableRef,
		"--type", "custom",
		"--certificate-identity", o.workflowIdentity,
		"--certificate-oidc-issuer", o.oidcIssuer,
	}, false); err != nil {
		return finish(err)
	}

	if _, err := step("provenance.slsa", "slsa-verifier provenance check", "slsa-verifier", []string{
		"verify-image", immutableRef,
		"--source-uri", "github.com/" + o.repo,
		"--source-branch", sourceBranch,
	}, false); err != nil {
		return finish(err)
	}

	if _, err := step("provenance.github", "GitHub-native provenance attestation", "gh", []string{
		"attestation", "verify", "oci://" + immutableRef,
		"--repo", o.repo,
		"--cert-identity", o.workflowIdentity,
		"--source-ref", o.sourceRef,
	}, false); err != nil {
		return finish(err)
	}

	if !structuredFormat() {
		fmt.Fprintf(out, "[evidence] complete: %s\n", immutableRef)
	}
	return finish(nil)
}

func writeVerifyEvidenceResponse(path string, response VerifyEvidenceResponse) error {
	raw, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
