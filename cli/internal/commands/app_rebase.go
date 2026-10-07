package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/attest"
	"github.com/northcutted/clearcutt-verify/internal/oci"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/northcutted/clearcutt-verify/internal/sign"
	"github.com/spf13/cobra"
)

const defaultRebaseOIDCIssuer = "https://token.actions.githubusercontent.com"

type appRebaseFlags struct {
	image                string
	candidateBase        string
	candidateBaseID      string
	candidateBaseVersion string
	oldBase              string
	tag                  string
	sign                 bool
	attest               bool
	requireDevSignature  bool
	devIdentity          string
	devIssuer            string
	compatPolicy         string
	cosignPath           string
}

var appRebaseOpts appRebaseFlags

// AppRebaseResult is the structured output of `app rebase`.
type AppRebaseResult struct {
	SourceImage        string   `json:"sourceImage"`
	SourceDigest       string   `json:"sourceDigest"`
	RebasedRef         string   `json:"rebasedRef"`
	RebasedDigest      string   `json:"rebasedDigest"`
	OldBaseDigest      string   `json:"oldBaseDigest"`
	NewBaseDigest      string   `json:"newBaseDigest"`
	CurrentBaseID      string   `json:"currentBaseId"`
	CandidateBaseID    string   `json:"candidateBaseId"`
	Compatible         bool     `json:"compatible"`
	CompatReason       string   `json:"compatReason"`
	PreservedAppLayers []string `json:"preservedAppLayers"`
	DevSignatureVerify bool     `json:"developerSignatureVerified"`
	Signed             bool     `json:"signed"`
	Attested           bool     `json:"attested"`
}

func newAppRebaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rebase",
		Short: "Swap the base under an app image, preserving app layers, then sign and attest",
		Long: `Rebases an application image onto a new ClearCutt base without recompiling it: the
base layers are swapped while every application layer is preserved byte-for-byte
(go-containerregistry independently re-verifies, by diff_id, that the app layers sit
exactly on top of the recorded base). Multi-arch indexes are rebased per platform.

Trust model (dual-control): before a rebase is allowed, the original developer's
keyless signature over the source image is verified (--dev-identity). The resulting
rebase attestation records that verification so a downstream admission gate (e.g.
Kyverno) can require both the rebase engine's signature and signed evidence that the
developer leg was checked. A runtime-incompatible candidate base (major/minor change)
is refused.

Example:
  clearcutt-verify app rebase \
    --image ghcr.io/acme/payments-api:1.0.0 \
    --candidate-base ghcr.io/northcutted/clearcutt/clearcutt-java25:v0.17.0-distroless \
    --candidate-base-id java25-distroless \
    --tag ghcr.io/acme/payments-api:1.0.0-rebased \
    --dev-identity 'https://github.com/acme/.+/.github/workflows/release.yml@refs/heads/main' \
    --sign --attest`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAppRebase()
		},
	}

	f := cmd.Flags()
	f.StringVar(&appRebaseOpts.image, "image", "", "Application image reference to rebase")
	f.StringVar(&appRebaseOpts.candidateBase, "candidate-base", "", "Replacement base: catalog id or registry reference")
	f.StringVar(&appRebaseOpts.candidateBaseID, "candidate-base-id", "", "Candidate base catalog id (when --candidate-base is a raw reference)")
	f.StringVar(&appRebaseOpts.candidateBaseVersion, "candidate-base-version", "", "Candidate base version stamped into the rebased labels")
	f.StringVar(&appRebaseOpts.oldBase, "old-base", "", "Override the old base reference (defaults to the app's recorded base ref)")
	f.StringVar(&appRebaseOpts.tag, "tag", "", "Target reference to push the rebased image to")
	f.BoolVar(&appRebaseOpts.sign, "sign", false, "Sign the rebased image with cosign (keyless)")
	f.BoolVar(&appRebaseOpts.attest, "attest", false, "Attach the rebase attestation as an OCI referrer (cosign attest)")
	f.BoolVar(&appRebaseOpts.requireDevSignature, "require-dev-signature", true, "Verify the developer signature over the source image before rebasing (dual-control)")
	f.StringVar(&appRebaseOpts.devIdentity, "dev-identity", "", "Pinned developer signer identity (certificate-identity-regexp) verified over the source image")
	f.StringVar(&appRebaseOpts.devIssuer, "dev-issuer", defaultRebaseOIDCIssuer, "OIDC issuer of the developer signature")
	f.StringVar(&appRebaseOpts.compatPolicy, "compat-policy", "", "Compatibility policy identifier recorded in the attestation (default derived from the base)")
	f.StringVar(&appRebaseOpts.cosignPath, "cosign-path", "cosign", "Path to the cosign binary")

	_ = cmd.MarkFlagRequired("image")
	_ = cmd.MarkFlagRequired("candidate-base")
	_ = cmd.MarkFlagRequired("tag")

	return cmd
}

func runAppRebase() error {
	client := newOCIClient()

	meta, err := client.ReadAppMeta(appRebaseOpts.image)
	if err != nil {
		return fmt.Errorf("read app image: %w", err)
	}
	if !meta.Rebasable {
		return fmt.Errorf("image %q is not marked rebasable; rebuild it with `clearcutt-verify app build`", appRebaseOpts.image)
	}
	currentBaseID := meta.BaseID

	// Resolve the candidate base reference and its catalog id.
	candRef, candID, candVer, err := resolveBaseReference(appRebaseOpts.candidateBase, appRebaseOpts.candidateBaseVersion)
	if err != nil {
		return err
	}
	if appRebaseOpts.candidateBaseID != "" {
		candID = appRebaseOpts.candidateBaseID
	}
	if candID == "" {
		return fmt.Errorf("candidate base id unknown; pass --candidate-base-id so the compatibility gate can run")
	}

	result := AppRebaseResult{
		SourceImage:     appRebaseOpts.image,
		SourceDigest:    digestFromRef(meta.SourceRef),
		CurrentBaseID:   currentBaseID,
		CandidateBaseID: candID,
	}

	// ABI compatibility gate — fail-closed. We never rebase across a runtime line.
	compatOK, compatReason := runtimeCompat(currentBaseID, candID)
	result.Compatible = compatOK
	result.CompatReason = compatReason
	if !compatOK {
		fmt.Fprintf(errOut, "rebase blocked: %s\n", compatReason)
		return ErrCheckFailed
	}

	// Dual-control: verify the developer signature over the exact source before rebasing.
	if appRebaseOpts.requireDevSignature && strings.TrimSpace(appRebaseOpts.devIdentity) == "" {
		return fmt.Errorf("--dev-identity is required for dual-control verification (or pass --require-dev-signature=false to opt out)")
	}
	var cs *sign.Cosign
	needCosign := appRebaseOpts.requireDevSignature || appRebaseOpts.sign || appRebaseOpts.attest
	if needCosign {
		cs = sign.New(appRebaseOpts.cosignPath, appRebaseOpts.devIdentity, appRebaseOpts.devIssuer, out, errOut)
		if err := cs.Available(); err != nil {
			return err
		}
	}
	if appRebaseOpts.requireDevSignature {
		if meta.SourceRef == "" {
			return fmt.Errorf("could not determine a digest-pinned source reference to verify")
		}
		fmt.Fprintf(out, "Verifying developer signature over %s ...\n", meta.SourceRef)
		if err := cs.VerifyImage(meta.SourceRef); err != nil {
			return fmt.Errorf("dual-control: developer signature verification failed: %w", err)
		}
		result.DevSignatureVerify = true
	}

	// Mechanical rebase + push.
	rr, err := client.Rebase(oci.RebaseOptions{
		AppRef:         appRebaseOpts.image,
		NewBaseRef:     candRef,
		OldBaseRef:     appRebaseOpts.oldBase,
		NewBaseID:      candID,
		NewBaseVersion: candVer,
		TargetRef:      appRebaseOpts.tag,
	})
	if err != nil {
		return fmt.Errorf("rebase failed: %w", err)
	}
	result.RebasedRef = rr.NewRef
	result.RebasedDigest = rr.NewDigest
	result.OldBaseDigest = rr.OldBaseDigest
	result.NewBaseDigest = rr.NewBaseDigest
	result.PreservedAppLayers = rr.PreservedAppLayers

	// Sign the rebased image (engine identity, keyless).
	if appRebaseOpts.sign {
		fmt.Fprintf(out, "Signing %s ...\n", rr.NewRef)
		if err := cs.Sign(rr.NewRef); err != nil {
			return fmt.Errorf("sign rebased image: %w", err)
		}
		result.Signed = true
	}

	// Build, validate, and attach the rebase attestation.
	if appRebaseOpts.attest {
		if err := attestRebase(cs, rr, &result, candID); err != nil {
			return err
		}
		result.Attested = true
	}

	return emitAppRebaseResult(result)
}

// attestRebase assembles the rebase predicate, enforces the dual-control invariant,
// writes the predicate to a temp file, and attaches it with cosign.
func attestRebase(cs *sign.Cosign, rr *oci.RebaseResult, result *AppRebaseResult, candID string) error {
	compatPolicy := appRebaseOpts.compatPolicy
	if compatPolicy == "" {
		compatPolicy = "clearcutt-" + candID + "-v1"
	}
	pred := attest.Predicate{
		SourceImage:                appRebaseOpts.image,
		SourceDigest:               rr.SourceDigest,
		OldBaseDigest:              rr.OldBaseDigest,
		NewBaseDigest:              rr.NewBaseDigest,
		PreservedAppLayers:         rr.PreservedAppLayers,
		RemovedBaseLayers:          rr.RemovedBaseLayers,
		AddedBaseLayers:            rr.AddedBaseLayers,
		CompatibilityPolicy:        compatPolicy,
		RebaseDecision:             attest.DecisionAllowed,
		DeveloperIdentity:          appRebaseOpts.devIdentity,
		DeveloperIssuer:            appRebaseOpts.devIssuer,
		DeveloperSignatureVerified: result.DevSignatureVerify,
	}
	if err := pred.Validate(); err != nil {
		return fmt.Errorf("refusing to emit an invalid rebase attestation: %w", err)
	}

	data, err := pred.Marshal()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "clearcutt-rebase-predicate-*.json")
	if err != nil {
		return fmt.Errorf("create predicate temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	fmt.Fprintf(out, "Attaching rebase attestation to %s ...\n", rr.NewRef)
	if err := cs.Attest(rr.NewRef, tmp.Name(), attest.PredicateType); err != nil {
		return fmt.Errorf("attest rebased image: %w", err)
	}
	return nil
}

func emitAppRebaseResult(r AppRebaseResult) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, r)
	case "yaml", "yml":
		return output.PrintYAML(out, r)
	default:
		fmt.Fprintf(out, "\nRebase complete\n")
		fmt.Fprintf(out, "  source         : %s (%s)\n", r.SourceImage, truncateDigest(r.SourceDigest))
		fmt.Fprintf(out, "  rebased        : %s\n", r.RebasedRef)
		fmt.Fprintf(out, "  base swap      : %s -> %s\n", truncateDigest(r.OldBaseDigest), truncateDigest(r.NewBaseDigest))
		fmt.Fprintf(out, "  compatibility  : %s\n", r.CompatReason)
		fmt.Fprintf(out, "  app layers     : %d preserved byte-for-byte\n", len(r.PreservedAppLayers))
		fmt.Fprintf(out, "  dev signature  : %s\n", verifiedLabel(r.DevSignatureVerify))
		fmt.Fprintf(out, "  signed         : %t\n", r.Signed)
		fmt.Fprintf(out, "  attested       : %t\n", r.Attested)
		return nil
	}
}

func verifiedLabel(v bool) string {
	if v {
		return "verified (dual-control)"
	}
	return "not verified"
}

func digestFromRef(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}
