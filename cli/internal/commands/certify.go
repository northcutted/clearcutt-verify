package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/certify"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

type certifyFlags struct {
	base             string
	imageRef         string
	requireSignature bool
	requireSbom      bool
	requireProv      bool
	policyFile       string
}

var certifyOpts certifyFlags

type CertificationPolicyDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Base struct {
			AllowedImages       []string `json:"allowedImages"`
			RequireDigestPinned bool     `json:"requireDigestPinned"`
			RequireKnownBase    bool     `json:"requireKnownBase"`
		} `json:"base"`
		SupplyChain struct {
			RequireSignature  bool `json:"requireSignature"`
			RequireProvenance bool `json:"requireProvenance"`
			RequireSbom       bool `json:"requireSbom"`
			MinimumSlsaLevel  int  `json:"minimumSlsaLevel"`
		} `json:"supplyChain"`
		Runtime struct {
			RequireNonRoot        bool `json:"requireNonRoot"`
			ForbidShell           bool `json:"forbidShell"`
			ForbidPackageManagers bool `json:"forbidPackageManagers"`
			ForbidDevTier         bool `json:"forbidDevTier"`
		} `json:"runtime"`
		Lifecycle struct {
			AllowPreview      bool `json:"allowPreview"`
			AllowDeprecated   bool `json:"allowDeprecated"`
			AllowExperimental bool `json:"allowExperimental"`
		} `json:"lifecycle"`
		Vulnerabilities struct {
			MaxCritical     int    `json:"maxCritical"`
			MaxHigh         int    `json:"maxHigh"`
			AllowExceptions bool   `json:"allowExceptions"`
			ExceptionFile   string `json:"exceptionFile"`
		} `json:"vulnerabilities"`
	} `json:"spec"`
}

type CertifyCheckResult struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // pass, fail, or skip
	Message string `json:"message"`
}

type CertifyResponse struct {
	Status string               `json:"status"` // pass or fail
	Image  string               `json:"image"`
	Checks []CertifyCheckResult `json:"checks"`
}

func NewCertifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certify <tarball-path>",
		Short: "Certify an application image against its security contract",
		Long: `Unpacks and parses local OCI/Docker image tarballs completely offline to verify
non-root users, shell-free distroless tiers, and required OCI labels. Supports both
legacy 'docker save' archives and OCI-layout archives. Supply-chain attestations
(signature, SBOM, provenance) live as registry referrers and cannot be verified
from an offline tarball; those checks are reported as skipped with guidance.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertify(args[0])
		},
	}

	cmd.Flags().StringVar(&certifyOpts.base, "base", "", "Optional ClearCutt base image ID the app claims to derive from (e.g. java21-distroless)")
	cmd.Flags().StringVar(&certifyOpts.imageRef, "image-ref", "", "Original image reference used to produce the tarball (enables digest-pinning checks when docker-save metadata drops @sha256 refs)")
	cmd.Flags().BoolVar(&certifyOpts.requireSignature, "require-signature", false, "Require signed attestations to exist for downstream image layers")
	cmd.Flags().BoolVar(&certifyOpts.requireSbom, "require-sbom", false, "Require SPDX SBOM attachments to exist for downstream image layers")
	cmd.Flags().BoolVar(&certifyOpts.requireProv, "require-provenance", false, "Require SLSA Level-3 build provenance attestations")
	cmd.Flags().StringVar(&certifyOpts.policyFile, "policy", "", "Path to local declarative certification-policy.yaml file")

	return cmd
}

func runCertify(tarPath string) error {
	checks := []CertifyCheckResult{}
	hasFailures := false
	skipped := 0

	addCheck := func(id, status, message string) {
		checks = append(checks, CertifyCheckResult{ID: id, Status: status, Message: message})
		switch status {
		case "fail":
			hasFailures = true
		case "skip":
			skipped++
		}
	}

	var policy *CertificationPolicyDoc
	reqSig := certifyOpts.requireSignature
	reqSbom := certifyOpts.requireSbom
	reqProv := certifyOpts.requireProv
	baseID := certifyOpts.base

	if certifyOpts.policyFile != "" {
		data, err := os.ReadFile(certifyOpts.policyFile)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}
		var p CertificationPolicyDoc
		if err := yaml.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("failed to parse policy YAML: %w", err)
		}
		if p.APIVersion != "clearcutt.dev/v1" {
			return fmt.Errorf("invalid certification policy apiVersion: %q (expected clearcutt.dev/v1)", p.APIVersion)
		}
		if p.Kind != "CertificationPolicy" {
			return fmt.Errorf("invalid certification policy kind: %q (expected CertificationPolicy)", p.Kind)
		}
		policy = &p
		reqSig = policy.Spec.SupplyChain.RequireSignature
		reqSbom = policy.Spec.SupplyChain.RequireSbom
		reqProv = policy.Spec.SupplyChain.RequireProvenance
	}

	tempDir, err := os.MkdirTemp("", "clearcutt-certify-*")
	if err != nil {
		return fmt.Errorf("failed to create temp workspace: %w", err)
	}
	defer os.RemoveAll(tempDir)

	img, err := certify.LoadImageArchive(tarPath, tempDir)
	if err != nil {
		return err
	}
	if strings.TrimSpace(certifyOpts.imageRef) != "" {
		img.RepoTags = append(img.RepoTags, strings.TrimSpace(certifyOpts.imageRef))
	}

	switch img.Format {
	case "docker":
		addCheck("manifest.parsed", "pass", "Parsed legacy docker-save image manifest")
	case "oci":
		addCheck("manifest.parsed", "pass", "Parsed OCI-layout image index and manifest")
	default:
		addCheck("manifest.parsed", "fail", "Unrecognized image archive: expected a docker-save manifest.json or an OCI-layout index.json")
	}

	if len(img.ConfigRaw) > 0 {
		var config certify.OCIImageConfig
		if err := json.Unmarshal(img.ConfigRaw, &config); err != nil {
			addCheck("config.parsed", "fail", fmt.Sprintf("Failed to parse OCI config JSON structure: %v", err))
		} else {
			addCheck("config.parsed", "pass", "Successfully parsed OCI image configuration specs")

			// Check 1: Rootless execution (Config.User)
			user := strings.TrimSpace(config.Config.User)
			switch {
			case user == "":
				addCheck("config.user.nonroot", "fail", "Security Violation: Config.User is not specified (defaults to root/UID 0)")
			case user == "0" || user == "root" || strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:"):
				addCheck("config.user.nonroot", "fail", fmt.Sprintf("Security Violation: Config.User executes under root privilege -> %s", user))
			default:
				addCheck("config.user.nonroot", "pass", fmt.Sprintf("Unprivileged non-root operator boundaries verified: User %s", user))
			}

			// Check 2: OCI standard labels
			hasCompliantLabel := false
			for k := range config.Config.Labels {
				if strings.HasPrefix(k, "org.opencontainers.image.") || strings.HasPrefix(k, "org.clearcutt.") {
					hasCompliantLabel = true
					break
				}
			}
			if hasCompliantLabel {
				addCheck("config.labels.compliance", "pass", "Corporate engineering compliance metadata labels are present")
			} else {
				addCheck("config.labels.compliance", "fail", "Compliance Notice: Image lacks required org.opencontainers.image compliance labels")
			}
		}
	} else if img.Format != "" {
		addCheck("config.parsed", "fail", "OCI image configuration blob was not found in the tarball archive")
	}

	// Check 3: Shell & package-manager audits, only when the claimed base is distroless.
	isDistroless := false
	if baseID != "" {
		if strings.Contains(baseID, "distroless") {
			isDistroless = true
		} else if record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, baseID); err == nil && record.Tier.ID == "distroless" {
			isDistroless = true
		}
	}

	if isDistroless {
		shellsFound := []string{}
		packageManagersFound := []string{}
		scanErrors := 0

		for _, layerPath := range img.LayerPaths {
			shells, pkgs, err := certify.ScanLayerForRuntimeTools(layerPath)
			if err != nil {
				scanErrors++
				continue
			}
			shellsFound = append(shellsFound, shells...)
			packageManagersFound = append(packageManagersFound, pkgs...)
		}

		// If we couldn't read any layer, don't claim a clean result we didn't verify.
		if scanErrors > 0 && scanErrors == len(img.LayerPaths) {
			addCheck("contract.shell.absence", "skip", "Could not read any image layers (unsupported layer encoding); shell audit not performed")
			addCheck("contract.package_manager.absence", "skip", "Could not read any image layers (unsupported layer encoding); package-manager audit not performed")
		} else {
			if len(shellsFound) > 0 {
				addCheck("contract.shell.absence", "fail", fmt.Sprintf("Security Violation: Distroless contract broken. Shell binaries found: %s", strings.Join(shellsFound, ", ")))
			} else {
				addCheck("contract.shell.absence", "pass", "Verified absence of interactive shell tools inside distroless closure")
			}
			if len(packageManagersFound) > 0 {
				addCheck("contract.package_manager.absence", "fail", fmt.Sprintf("Security Violation: Package manager tools found: %s", strings.Join(packageManagersFound, ", ")))
			} else {
				addCheck("contract.package_manager.absence", "pass", "Verified absence of package manager tools inside runtime boundary")
			}
		}
	} else if baseID != "" {
		addCheck("contract.shell.absence", "skip", "Base image tier is not distroless; shell audit not applicable")
		addCheck("contract.package_manager.absence", "skip", "Base image tier is not distroless; package-manager audit not applicable")
	}

	// Supply-chain attestations are OCI referrers in a registry, not contents of an
	// offline tarball. We cannot verify them here, so when required we mark them
	// skipped with guidance rather than asserting a result we did not check.
	const attestationGuidance = "verify against the registry with `cosign verify` / `cosign verify-attestation`"
	if reqSig {
		addCheck("evidence.signature.verified", "skip", "Signature is a registry referrer and cannot be verified from an offline tarball; "+attestationGuidance)
	}
	if reqSbom {
		addCheck("evidence.sbom.present", "skip", "SBOM attestation is a registry referrer and cannot be verified from an offline tarball; "+attestationGuidance)
	}
	if reqProv {
		addCheck("evidence.provenance.present", "skip", "SLSA provenance is a registry referrer and cannot be verified from an offline tarball; "+attestationGuidance)
	}

	// Declarative certification policy enforcement.
	if policy != nil {
		// 1. Allowed base images.
		if len(policy.Spec.Base.AllowedImages) > 0 {
			allowed := false
			for _, candidate := range policy.Spec.Base.AllowedImages {
				if candidate == baseID {
					allowed = true
					break
				}
			}
			if allowed {
				addCheck("policy.base.allowed", "pass", fmt.Sprintf("Base image %q is in approved allowedImages list", baseID))
			} else {
				addCheck("policy.base.allowed", "fail", fmt.Sprintf("Security Violation: Base image %q is not allowed by this policy", baseID))
			}
		}

		// 2. Digest pinning, evaluated against the image's own references.
		if policy.Spec.Base.RequireDigestPinned {
			isDigestPinned := strings.Contains(baseID, "@sha256:")
			for _, ref := range img.RepoTags {
				if strings.Contains(ref, "@sha256:") {
					isDigestPinned = true
					break
				}
			}
			if isDigestPinned {
				addCheck("policy.base.digestPinned", "pass", "Container image reference is digest-pinned")
			} else {
				addCheck("policy.base.digestPinned", "fail", "Security Violation: Image reference must be digest-pinned for production deployment")
			}
		}

		// 3. Minimum SLSA level cannot be determined from an offline tarball.
		if policy.Spec.SupplyChain.MinimumSlsaLevel > 0 {
			addCheck("policy.supplychain.slsaLevel", "skip", fmt.Sprintf("SLSA level requires the provenance attestation from the registry; cannot confirm >= %d offline", policy.Spec.SupplyChain.MinimumSlsaLevel))
		}

		// 4. Vulnerability gating against the declared base image's catalog record.
		if policy.Spec.Vulnerabilities.MaxCritical >= 0 || policy.Spec.Vulnerabilities.MaxHigh >= 0 {
			certifyVulnGate(policy, baseID, addCheck)
		}
	}

	overallStatus := "pass"
	if hasFailures {
		overallStatus = "fail"
	}

	response := CertifyResponse{
		Status: overallStatus,
		Image:  filepath.Base(tarPath),
		Checks: checks,
	}

	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		if err := output.PrintJSON(out, response); err != nil {
			return err
		}
	case "yaml", "yml":
		if err := output.PrintYAML(out, response); err != nil {
			return err
		}
	default:
		fmt.Fprintf(out, "Downstream Security Certification Report for %s\n", filepath.Base(tarPath))
		fmt.Fprintln(out, "-----------------------------------------------------------------")
		for _, check := range checks {
			statusSymbol := "✔ PASS"
			switch check.Status {
			case "fail":
				statusSymbol = "✘ FAIL"
			case "skip":
				statusSymbol = "↷ SKIP"
			}
			fmt.Fprintf(out, "[%-6s] %-32s : %s\n", statusSymbol, check.ID, check.Message)
		}
		fmt.Fprintln(out, "-----------------------------------------------------------------")
		switch {
		case hasFailures:
			fmt.Fprintln(out, "Certification Result: FAIL")
		case skipped > 0:
			fmt.Fprintf(out, "Certification Result: PASS (%d check(s) skipped — see guidance above)\n", skipped)
		default:
			fmt.Fprintln(out, "Certification Result: PASS")
		}
	}

	if hasFailures {
		return ErrCheckFailed
	}

	return nil
}

// certifyVulnGate enforces the policy's critical/high thresholds against the
// declared base image's catalog record, honoring active vulnerability exceptions.
func certifyVulnGate(policy *CertificationPolicyDoc, baseID string, addCheck func(id, status, message string)) {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, baseID)
	if err != nil {
		return
	}
	release, err := latestOrTaggedRelease(record.Releases, "")
	if err != nil {
		return
	}

	var exceptionsDoc *ExceptionsDoc
	if policy.Spec.Vulnerabilities.AllowExceptions && policy.Spec.Vulnerabilities.ExceptionFile != "" {
		if doc, err := LoadExceptionsFile(policy.Spec.Vulnerabilities.ExceptionFile); err == nil {
			exceptionsDoc = doc
		}
	}

	now := time.Now().UTC()
	maxCritFound, maxHighFound := 0, 0
	critExceeded, highExceeded := false, false

	for _, arch := range release.Architectures {
		if arch.Vulnerabilities == nil {
			continue
		}
		criticalCount, highCount := 0, 0
		for _, finding := range arch.Vulnerabilities.Findings {
			if entry, expired := exceptionsDoc.Match(finding.ID, finding.PackageName, baseID, release.Tag, now); entry != nil && !expired {
				continue
			}
			switch strings.ToLower(finding.Severity) {
			case "critical":
				criticalCount++
			case "high":
				highCount++
			}
		}
		if len(arch.Vulnerabilities.Findings) == 0 {
			criticalCount = arch.Vulnerabilities.CountsBySeverity.Critical
			highCount = arch.Vulnerabilities.CountsBySeverity.High
		}
		if criticalCount > maxCritFound {
			maxCritFound = criticalCount
		}
		if highCount > maxHighFound {
			maxHighFound = highCount
		}
		if policy.Spec.Vulnerabilities.MaxCritical >= 0 && criticalCount > policy.Spec.Vulnerabilities.MaxCritical {
			critExceeded = true
		}
		if policy.Spec.Vulnerabilities.MaxHigh >= 0 && highCount > policy.Spec.Vulnerabilities.MaxHigh {
			highExceeded = true
		}
	}

	if policy.Spec.Vulnerabilities.MaxCritical >= 0 {
		if critExceeded {
			addCheck("policy.vulnerabilities.critical", "fail", fmt.Sprintf("Critical vulnerabilities count %d exceeds policy limit %d", maxCritFound, policy.Spec.Vulnerabilities.MaxCritical))
		} else {
			addCheck("policy.vulnerabilities.critical", "pass", fmt.Sprintf("Critical vulnerabilities count %d is within policy limit %d", maxCritFound, policy.Spec.Vulnerabilities.MaxCritical))
		}
	}
	if policy.Spec.Vulnerabilities.MaxHigh >= 0 {
		if highExceeded {
			addCheck("policy.vulnerabilities.high", "fail", fmt.Sprintf("High vulnerabilities count %d exceeds policy limit %d", maxHighFound, policy.Spec.Vulnerabilities.MaxHigh))
		} else {
			addCheck("policy.vulnerabilities.high", "pass", fmt.Sprintf("High vulnerabilities count %d is within policy limit %d", maxHighFound, policy.Spec.Vulnerabilities.MaxHigh))
		}
	}
}
