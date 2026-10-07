package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/spf13/cobra"
)

type mirrorFlags struct {
	tag                  string
	source               string
	target               string
	output               string
	verifySource         string
	verifyTarget         string
	verifyIdentity       string
	verifyIssuer         string
	preserveAttestations bool
}

var mirrorOpts mirrorFlags

const (
	// defaultReleaseIdentityRegex is the Sigstore signing identity of ClearCutt's
	// own release workflow. mirror verify pins to it by default so a mirrored
	// signature must trace back to a genuine ClearCutt release, not just any valid
	// Sigstore certificate. Override with --identity when mirroring a fork.
	defaultReleaseIdentityRegex = "https://github.com/northcutted/clearcutt(-verify)?/.github/workflows/release.yml@.*"
	// defaultOIDCIssuer is the GitHub Actions OIDC issuer used for keyless signing.
	defaultOIDCIssuer = "https://token.actions.githubusercontent.com"
)

func NewMirrorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mirror <image-id> --target <destination-registry>",
		Short: "Formulate trust-preserving OCI registry mirroring workflows",
		Long:  `Generates precise skopeo and cosign instructions to mirror multi-arch image layers alongside OIDC signatures and SBOM attestations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return runMirror(args[0])
		},
	}

	cmd.Flags().StringVar(&mirrorOpts.tag, "tag", "", "Target release tag version (defaults to latest)")
	cmd.Flags().StringVar(&mirrorOpts.source, "source", "ghcr.io/northcutted/clearcutt", "Optional source registry override")
	cmd.Flags().StringVar(&mirrorOpts.target, "target", "", "Required enterprise destination registry destination")
	cmd.Flags().StringVar(&mirrorOpts.output, "output", "", "Output shell script file path destination")
	cmd.Flags().BoolVar(&mirrorOpts.preserveAttestations, "preserve-attestations", true, "Preserve all SBOM and SLSA attestations during replication")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Generate a script to verify a mirror preserved signatures and referrers",
		Long: `Generates a cosign/oras verification script that checks the target mirror
preserved the source image's digest, Sigstore signature, and attestation
referrers (SBOM, SLSA provenance). The script requires network access to both
registries; this command itself performs no network calls.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMirrorVerify()
		},
	}

	verifyCmd.Flags().StringVar(&mirrorOpts.verifySource, "source", "", "Source OCI image reference tag")
	verifyCmd.Flags().StringVar(&mirrorOpts.verifyTarget, "target", "", "Target mirrored OCI image reference tag")
	verifyCmd.Flags().StringVar(&mirrorOpts.verifyIdentity, "identity", defaultReleaseIdentityRegex, "Cosign certificate-identity regexp the mirrored signature must match")
	verifyCmd.Flags().StringVar(&mirrorOpts.verifyIssuer, "issuer", defaultOIDCIssuer, "Cosign OIDC issuer the mirrored signature must match")
	verifyCmd.Flags().StringVar(&mirrorOpts.output, "output", "", "Output shell script file path destination")
	verifyCmd.MarkFlagRequired("source")
	verifyCmd.MarkFlagRequired("target")

	cmd.AddCommand(verifyCmd)

	return cmd
}

func runMirrorVerify() error {
	src := strings.TrimSpace(mirrorOpts.verifySource)
	tgt := strings.TrimSpace(mirrorOpts.verifyTarget)
	identity := strings.TrimSpace(mirrorOpts.verifyIdentity)
	issuer := strings.TrimSpace(mirrorOpts.verifyIssuer)

	script := fmt.Sprintf(`#!/usr/bin/env bash
# ClearCutt Mirror Trust Verification
# Confirms the target mirror preserved the digest, signature, and attestation
# referrers of the source image. Requires: cosign, oras, crane, jq, and network
# access to both registries.
#
# Source: %s
# Target: %s

set -euo pipefail

SRC="%s"
TGT="%s"
# Signer the mirrored signature must trace back to. Defaults to ClearCutt's
# release workflow; override with --identity / --issuer when mirroring a fork.
IDENTITY="%s"
ISSUER="%s"

log()  { echo "[clearcutt-verify mirror verify] $1"; }
fail() { echo "[clearcutt-verify mirror verify] FAIL: $1" >&2; exit 1; }

# 1. Both references must resolve to the same image digest.
log "Resolving manifest digests..."
src_digest="$(crane digest "$SRC")"
tgt_digest="$(crane digest "$TGT")"
[ "$src_digest" = "$tgt_digest" ] || fail "digest mismatch: source=$src_digest target=$tgt_digest"
log "Digest match: $tgt_digest"

# 2. Referrer counts (signatures, SBOMs, provenance) must be preserved.
log "Comparing OCI referrers..."
src_refs="$(oras discover --format json "$SRC" | jq '.manifests | length')"
tgt_refs="$(oras discover --format json "$TGT" | jq '.manifests | length')"
[ "$tgt_refs" -ge "$src_refs" ] || fail "target is missing referrers: source=$src_refs target=$tgt_refs"
log "Referrers preserved: target=$tgt_refs source=$src_refs"

# 3. The mirrored signature must still verify against the expected signer
#    identity and issuer (a wildcard would accept any Sigstore certificate).
log "Verifying target signature against $IDENTITY..."
cosign verify "$TGT" \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" >/dev/null || fail "target signature did not verify"

log "Mirror trust verification PASSED for $TGT"
`, src, tgt, src, tgt, identity, issuer)

	if mirrorOpts.output != "" {
		if err := os.WriteFile(mirrorOpts.output, []byte(script), 0755); err != nil {
			return fmt.Errorf("failed to write verification script: %w", err)
		}
		if !GlobalOpts.Quiet {
			fmt.Fprintf(out, "Successfully generated mirror verification script: %s\n", mirrorOpts.output)
		}
		return nil
	}

	out.Write([]byte(script))
	return nil
}

func runMirror(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Resolve the target release
	release, err := latestOrTaggedRelease(record.Releases, mirrorOpts.tag)
	if err != nil {
		return fmt.Errorf("%w for image %q", err, imageID)
	}

	sourceRegistry := strings.TrimRight(mirrorOpts.source, "/")
	targetRegistry := strings.TrimRight(mirrorOpts.target, "/")

	sourceImageRef := fmt.Sprintf("%s/%s:%s-%s", sourceRegistry, record.ImageName, release.Tag, record.Tier.ID)
	targetImageRef := fmt.Sprintf("%s/%s:%s-%s", targetRegistry, record.ImageName, release.Tag, record.Tier.ID)

	scriptTemplate := fmt.Sprintf(`#!/usr/bin/env bash
# ClearCutt Trust-Preserving Base Image Mirroring Script
# Mapped Target: %s (%s)
# Release Tag:   %s

set -euo pipefail

log_info() {
  echo "[clearcutt-verify mirror] $1"
}

log_info "1. Copying multi-architecture layers securely using skopeo..."
skopeo copy \
  --all \
  --src-tls-verify=true \
  --dest-tls-verify=true \
  docker://%s \
  docker://%s

log_info "2. Copying Sigstore cryptographic signatures and SBOM attestations using cosign..."
cosign copy \
  %s \
  %s

log_info "Mirror completed successfully for %s -> %s!"
`, record.ID, record.Tier.Name, release.Tag, sourceImageRef, targetImageRef, sourceImageRef, targetImageRef, record.ID, targetRegistry)

	if mirrorOpts.output != "" {
		if err := os.WriteFile(mirrorOpts.output, []byte(scriptTemplate), 0755); err != nil {
			return fmt.Errorf("failed to write mirroring script: %w", err)
		}
		if !GlobalOpts.Quiet {
			fmt.Fprintf(out, "Successfully generated mirroring execution script: %s\n", mirrorOpts.output)
		}
	} else {
		out.Write([]byte(scriptTemplate))
	}

	return nil
}
