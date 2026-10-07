package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/spf13/cobra"
)

type policyFlags struct {
	tag               string
	engine            string
	output            string
	environment       string
	requireDigest     bool
	requireSignature  bool
	requireProvenance bool
	denyDevTier       bool
	denyPreview       bool
	namespace         string
}

var policyOpts policyFlags

func NewPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy <image-id>",
		Short: "Generate Kubernetes admission control policy examples",
		Long: `Extracts OIDC signature metadata from the base image catalog to emit
Kyverno verification policies and Gatekeeper scaffolds for teams with their own
verifying admission integrations. Kyverno is the stronger generated path today;
Gatekeeper output is not a standalone cryptographic verifier.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicy(args[0])
		},
	}

	cmd.Flags().StringVar(&policyOpts.tag, "tag", "", "Target release tag version (defaults to latest)")
	cmd.Flags().StringVar(&policyOpts.engine, "engine", "kyverno", "Admission engine: kyverno or gatekeeper")
	cmd.Flags().StringVar(&policyOpts.output, "output", "", "Output manifest file path destination")
	cmd.Flags().StringVar(&policyOpts.environment, "environment", "production", "Policy environment profile: development, production, or strict")
	cmd.Flags().BoolVar(&policyOpts.requireDigest, "require-digest", false, "Require digest pinning on container images")
	cmd.Flags().BoolVar(&policyOpts.requireSignature, "require-signature", false, "Require Cosign keyless signatures")
	cmd.Flags().BoolVar(&policyOpts.requireProvenance, "require-provenance", false, "Require SLSA build provenance attestations")
	cmd.Flags().BoolVar(&policyOpts.denyDevTier, "deny-dev-tier", false, "Deny images from the 'dev' tooling tier")
	cmd.Flags().BoolVar(&policyOpts.denyPreview, "deny-preview", false, "Deny images marked as preview lifecycle stage")
	cmd.Flags().StringVar(&policyOpts.namespace, "namespace", "default", "Kubernetes namespace context target")

	return cmd
}

func runPolicy(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Resolve the target release
	release, err := latestOrTaggedRelease(record.Releases, policyOpts.tag)
	if err != nil {
		return fmt.Errorf("%w for image %q", err, imageID)
	}

	// Resolve OIDC subject and issuer. Admission policy generation is a trust
	// surface, so missing or mismatched signer metadata must fail closed rather
	// than falling back to the upstream ClearCutt identity.
	subject := ""
	issuer := "https://token.actions.githubusercontent.com"

	if release.Signature != nil && release.Signature.Certificate != nil {
		if release.Signature.Certificate.Subject != nil {
			subject = *release.Signature.Certificate.Subject
		}
		if release.Signature.Certificate.Issuer != nil {
			issuer = *release.Signature.Certificate.Issuer
		}
	}
	if strings.TrimSpace(subject) == "" {
		return fmt.Errorf("catalog release %s for image %q is missing signature certificate subject; cannot generate admission policy", release.Tag, imageID)
	}
	if !signerSubjectMatchesImageRepo(subject, record.FullName) {
		return fmt.Errorf("catalog release %s for image %q signs %q with unrelated workflow identity %q", release.Tag, imageID, record.FullName, subject)
	}

	// Resolve defaults by environment profile
	env := strings.ToLower(policyOpts.environment)
	reqDigest := policyOpts.requireDigest
	reqSig := policyOpts.requireSignature
	reqProv := policyOpts.requireProvenance
	denyDev := policyOpts.denyDevTier
	denyPrev := policyOpts.denyPreview
	requireNonRoot := false

	switch env {
	case "development":
		reqSig = true
	case "production":
		reqDigest, reqSig, reqProv, denyDev, denyPrev = true, true, true, true, true
	case "strict":
		// Everything production enforces, plus a hard non-root workload guarantee.
		reqDigest, reqSig, reqProv, denyDev, denyPrev = true, true, true, true, true
		requireNonRoot = true
	}

	var outputPolicy string

	switch strings.ToLower(policyOpts.engine) {
	case "gatekeeper", "opa":
		outputPolicy = fmt.Sprintf(`apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8scosignsignatureverify
spec:
  crd:
    spec:
      names:
        kind: K8sCosignSignatureVerify
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8scosignsignatureverify

        violation[{"msg": msg}] {
          input.review.object.kind == "Pod"
          image := input.review.object.spec.containers[_].image
          startswith(image, "%s")
          msg := sprintf("Security Violation: Image %%q must be verified using Cosign keyless signatures", [image])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sCosignSignatureVerify
metadata:
  name: verify-signature-%s
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["%s"]
  parameters:
    imagePattern: "%s:*"
    requireDigest: %t
    requireSignature: %t
    requireProvenance: %t
    denyDevTier: %t
    denyPreview: %t
    requireNonRoot: %t
    subject: "%s"
    issuer: "%s"
`, record.FullName, record.ID, policyOpts.namespace, record.FullName, reqDigest, reqSig, reqProv, denyDev, denyPrev, requireNonRoot, subject, issuer)

	default: // Kyverno
		var rulesBlock strings.Builder

		// Main signature and digest rule
		rulesBlock.WriteString(fmt.Sprintf(`    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["%s"]
      verifyImages:
        - imageReferences: ["%s:*"]
          mutateDigest: %t
          verifyDigest: %t
          required: %t
`, policyOpts.namespace, record.FullName, reqDigest, reqDigest, reqSig))

		if reqSig {
			rulesBlock.WriteString(fmt.Sprintf(`          attestors:
            - entries:
                - keyless:
                    subject: "%s"
                    issuer: "%s"
`, subject, issuer))
		}

		if reqProv {
			rulesBlock.WriteString(fmt.Sprintf(`          attestations:
            - predicateType: https://slsa.dev/provenance/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "%s"
                        issuer: "%s"
`, subject, issuer))
		}

		if denyDev {
			rulesBlock.WriteString(fmt.Sprintf(`    - name: deny-dev-images
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["%s"]
      validate:
        message: "Security Violation: Dev tier images are forbidden in this environment"
        pattern:
          spec:
            containers:
              - =(image): "!*:*-dev"
`, policyOpts.namespace))
		}

		if denyPrev && strings.EqualFold(release.Lifecycle.Status, "preview") {
			rulesBlock.WriteString(fmt.Sprintf(`    - name: deny-preview-images
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["%s"]
      validate:
        message: "Security Violation: Preview lifecycle images are forbidden in this environment"
        pattern:
          spec:
            containers:
              - =(image): "!%s:*"
`, policyOpts.namespace, record.FullName))
		}

		if requireNonRoot {
			rulesBlock.WriteString(fmt.Sprintf(`    - name: require-run-as-non-root
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["%s"]
      validate:
        message: "Security Violation: strict profile requires spec.securityContext.runAsNonRoot=true"
        pattern:
          spec:
            securityContext:
              runAsNonRoot: true
`, policyOpts.namespace))
		}

		outputPolicy = fmt.Sprintf(`apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-signature-%s
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
%s`, record.ID, rulesBlock.String())
	}

	if policyOpts.output != "" {
		if err := os.WriteFile(policyOpts.output, []byte(outputPolicy), 0644); err != nil {
			return fmt.Errorf("failed to write policy manifest file: %w", err)
		}
		if !GlobalOpts.Quiet {
			fmt.Fprintf(out, "Successfully generated policy manifest file: %s\n", policyOpts.output)
		}
	} else {
		out.Write([]byte(outputPolicy))
	}

	return nil
}

func signerSubjectMatchesImageRepo(subject, fullName string) bool {
	const ghcrPrefix = "ghcr.io/"
	if !strings.HasPrefix(fullName, ghcrPrefix) {
		return true
	}
	parts := strings.Split(fullName[len(ghcrPrefix):], "/")
	if len(parts) < 3 {
		return true
	}
	repoPath := parts[0] + "/" + parts[1]
	return strings.Contains(subject, "github.com/"+repoPath+"/")
}
