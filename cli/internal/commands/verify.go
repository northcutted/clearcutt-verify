package commands

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt/internal/catalog"
	"github.com/northcutted/clearcutt/internal/config"
	"github.com/northcutted/clearcutt/internal/output"
	"github.com/spf13/cobra"
)

type verifyFlags struct {
	tag                     string
	requireProduction       bool
	allowPreview            bool
	allowDeprecated         bool
	requireSignature        bool
	requireSBOM             bool
	requireProvenance       bool
	requireTests            bool
	requireVulnScan         bool
	maxCritical             int
	maxHigh                 int
	exceptionsFile          string
	allowExceptions         bool
	failOnExpiredExceptions bool
	requireVulnPolicy       bool
	policyJSON              string
	vexOutput               string
}

var verifyOpts verifyFlags

// VerifyCheckResult represents a single assertion check result.
type VerifyCheckResult struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // pass or fail
	Message string `json:"message"`
}

// VerifyResponse represents the complete JSON response payload.
type VerifyResponse struct {
	Status string              `json:"status"` // pass or fail
	Image  string              `json:"image"`
	Tag    string              `json:"tag"`
	Checks []VerifyCheckResult `json:"checks"`
}

// NewVerifyCmd is the parent of the verification subcommands. Each is usable
// standalone: gate a published image against policy (image), check the generated
// catalog is complete and consistent (catalog), or verify a published ref's
// Sigstore + SLSA release evidence (release-evidence).
func NewVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify images, catalog data, and release evidence",
		Long: `Verification subcommands:
  image            gate a specific catalog image against policy contract gates
  catalog          check the generated catalog publishes complete, consistent trust data
  closure-purity   gate an image's /nix/store closure against shells, package managers, setuid/setgid
  runtime-cve      gate the shipped closure: no stock (below-floor) build of a CVE-remediated dep
  boundaries       run all image-security boundary gates (closure-purity + runtime-cve) at once
  rebuild          verify rebuild digest and runtime/grafted closure equivalence predicates
  release-evidence verify a published image ref's Sigstore signature + SLSA provenance
  estate           verify every image in an estate and write the estate report (contract/)`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(args[0])
		},
	}
	// Preserve the original `verify <image-id>` automation path while keeping
	// `verify image <image-id>` as the documented command.
	addVerifyImageFlags(cmd, true)
	cmd.AddCommand(newVerifyImageCmd())
	cmd.AddCommand(NewVerifyCatalogCmd())
	cmd.AddCommand(NewVerifyRebuildCmd())
	cmd.AddCommand(NewVerifyReleaseEvidenceCmd())
	cmd.AddCommand(newVerifyClosurePurityCmd())
	cmd.AddCommand(newVerifyBoundariesCmd())
	cmd.AddCommand(newVerifyEstateCmd())
	return cmd
}

// newVerifyImageCmd gates a specific catalog image against policy contracts.
func newVerifyImageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image <image-id>",
		Short: "Gate a specific ClearCutt catalog image against policy contract checks",
		Long: `Evaluates catalog-record evidence flags, smoke test status, vulnerability
limits, and lifecycle constraints for a specific image. This is a catalog policy
gate; use verify release-evidence for registry-side Cosign and SLSA verification.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(args[0])
		},
	}

	addVerifyImageFlags(cmd, false)

	return cmd
}

func addVerifyImageFlags(cmd *cobra.Command, hidden bool) {
	cmd.Flags().StringVar(&verifyOpts.tag, "tag", "", "Enforce policies against a specific versioned tag (defaults to latest)")
	cmd.Flags().BoolVar(&verifyOpts.requireProduction, "require-production", false, "Require that the image is approved for production deployment")
	cmd.Flags().BoolVar(&verifyOpts.allowPreview, "allow-preview", false, "Allow images currently marked in the 'preview' lifecycle status")
	cmd.Flags().BoolVar(&verifyOpts.allowDeprecated, "allow-deprecated", false, "Allow images currently marked in the 'deprecated' lifecycle status")
	cmd.Flags().BoolVar(&verifyOpts.requireSignature, "require-signature", false, "Require the catalog release record to report Sigstore signature evidence")
	cmd.Flags().BoolVar(&verifyOpts.requireSBOM, "require-sbom", false, "Require the catalog release record to report SPDX SBOM evidence for all architectures")
	cmd.Flags().BoolVar(&verifyOpts.requireProvenance, "require-provenance", false, "Require the catalog release record to report SLSA provenance evidence")
	cmd.Flags().BoolVar(&verifyOpts.requireTests, "require-tests", false, "Enforce that smoke and conformance tests exist and have passed")
	cmd.Flags().BoolVar(&verifyOpts.requireVulnScan, "require-vuln-scan", false, "Enforce presence of complete vulnerability scan results")
	cmd.Flags().IntVar(&verifyOpts.maxCritical, "max-critical", -1, "Maximum tolerated critical severity vulnerabilities (-1 to disable threshold)")
	cmd.Flags().IntVar(&verifyOpts.maxHigh, "max-high", -1, "Maximum tolerated high severity vulnerabilities (-1 to disable threshold)")
	cmd.Flags().StringVar(&verifyOpts.exceptionsFile, "exceptions", "", "Path to local exceptions YAML triage governance file (active exceptions are honoured automatically when set)")
	cmd.Flags().BoolVar(&verifyOpts.allowExceptions, "allow-exceptions", false, "Deprecated/no-op: exceptions are honoured automatically whenever --exceptions is provided")
	cmd.Flags().BoolVar(&verifyOpts.failOnExpiredExceptions, "fail-on-expired-exceptions", true, "Fail verification if any matched exception is expired")
	cmd.Flags().BoolVar(&verifyOpts.requireVulnPolicy, "require-vuln-policy", false, "Gate on the risk policy: block reachable, materially-risky findings (must_fix, and unfixable must_acknowledge) unless covered by an active exception")
	cmd.Flags().StringVar(&verifyOpts.policyJSON, "policy-json", os.Getenv("REMEDIATION_POLICY_JSON"), "Effective remediation policy JSON from clearcutt.fleet.yaml (used by --require-vuln-policy / --vex-output)")
	cmd.Flags().StringVar(&verifyOpts.vexOutput, "vex-output", "", "Write the policy-accepted finding set as expiring OpenVEX records to this path")

	if !hidden {
		return
	}
	for _, name := range []string{
		"tag",
		"require-production",
		"allow-preview",
		"allow-deprecated",
		"require-signature",
		"require-sbom",
		"require-provenance",
		"require-tests",
		"require-vuln-scan",
		"max-critical",
		"max-high",
		"exceptions",
		"allow-exceptions",
		"fail-on-expired-exceptions",
		"require-vuln-policy",
		"policy-json",
		"vex-output",
	} {
		_ = cmd.Flags().MarkHidden(name)
	}
}

func runVerify(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Resolve the target release
	release, err := latestOrTaggedRelease(record.Releases, verifyOpts.tag)
	if err != nil {
		return fmt.Errorf("%w for image %q", err, imageID)
	}

	// Parse exceptions whenever a file is provided. Supplying --exceptions is the
	// intent to honour them; we don't require a separate --allow-exceptions toggle,
	// which previously made the file a silent no-op when omitted.
	var exceptionsDoc *ExceptionsDoc
	if verifyOpts.exceptionsFile != "" {
		doc, err := LoadExceptionsFile(verifyOpts.exceptionsFile)
		if err != nil {
			return fmt.Errorf("failed to load exceptions file: %w", err)
		}
		exceptionsDoc = doc
	}

	checks := []VerifyCheckResult{}
	hasFailures := false

	addCheck := func(id, status, message string) {
		checks = append(checks, VerifyCheckResult{
			ID:      id,
			Status:  status,
			Message: message,
		})
		if status == "fail" {
			hasFailures = true
		}
	}

	// 1. Check Digest & Architectures
	if release.ManifestDigest != nil && *release.ManifestDigest != "" {
		addCheck("digest.present", "pass", fmt.Sprintf("manifest digest present: %s", *release.ManifestDigest))
	} else {
		addCheck("digest.present", "fail", "manifest digest is missing from release")
	}

	if len(release.Architectures) > 0 {
		var archList []string
		for _, arch := range release.Architectures {
			archList = append(archList, arch.Arch)
		}
		addCheck("architectures.present", "pass", fmt.Sprintf("architectures present: %s", strings.Join(archList, ", ")))
	} else {
		addCheck("architectures.present", "fail", "no architecture payloads found in release record")
	}

	// 2. Check Signature
	hasSig := catalog.EvidenceSummarySatisfies(release.Evidence, "signature")
	if release.Evidence == nil && release.Signature != nil {
		hasSig = release.Signature.CosignBundlePresent
	}
	if verifyOpts.requireSignature {
		if hasSig {
			addCheck("signature.present", "pass", "catalog release record reports Sigstore signature evidence")
		} else {
			addCheck("signature.present", "fail", "catalog release record is missing Sigstore signature evidence")
		}
	} else if hasSig {
		addCheck("signature.present", "pass", "catalog release record reports Sigstore signature evidence (not explicitly required)")
	}

	// 3. Check SBOM
	hasSBOM := catalog.EvidenceSummarySatisfies(release.Evidence, "sbom")
	if verifyOpts.requireSBOM {
		if hasSBOM {
			addCheck("sbom.present", "pass", "catalog release record reports SPDX SBOM evidence for all platforms")
		} else {
			missingCount := 0
			if release.Evidence != nil {
				missingCount = release.Evidence.ArchCount - release.Evidence.SBOMArchCount
			}
			addCheck("sbom.present", "fail", fmt.Sprintf("catalog release record is missing or has incomplete SPDX SBOM evidence (%d platforms missing)", missingCount))
		}
	} else if hasSBOM {
		addCheck("sbom.present", "pass", "catalog release record reports SPDX SBOM evidence for all platforms (not explicitly required)")
	}

	// 4. Check SLSA Provenance
	hasProv := catalog.EvidenceSummarySatisfies(release.Evidence, "provenance")
	if release.Evidence == nil && release.Provenance != nil {
		hasProv = true
	}
	if verifyOpts.requireProvenance {
		if hasProv {
			addCheck("provenance.present", "pass", "catalog release record reports SLSA provenance evidence")
		} else {
			addCheck("provenance.present", "fail", "catalog release record is missing SLSA provenance evidence")
		}
	} else if hasProv {
		addCheck("provenance.present", "pass", "catalog release record reports SLSA provenance evidence (not explicitly required)")
	}

	// 5. Check Conformance Tests
	hasTests := catalog.EvidenceSummarySatisfies(release.Evidence, "tests")
	if verifyOpts.requireTests {
		if hasTests {
			addCheck("tests.passed", "pass", "conformance and smoke tests passed on all platforms")
		} else {
			failedCount := 0
			if release.Evidence != nil {
				failedCount = release.Evidence.ArchCount - release.Evidence.PassedTestArchCount
			}
			addCheck("tests.passed", "fail", fmt.Sprintf("smoke tests failed or missing (%d platforms failed/incomplete)", failedCount))
		}
	} else if hasTests {
		addCheck("tests.passed", "pass", "conformance tests passed on all platforms (not explicitly required)")
	}

	// 6. Check Vulnerability Scanning
	hasScan := catalog.EvidenceSummarySatisfies(release.Evidence, "vulnerabilities")
	if verifyOpts.requireVulnScan {
		if hasScan {
			addCheck("vulnerabilities.scanned", "pass", "vulnerability scan results present for all platforms")
		} else {
			missingCount := 0
			if release.Evidence != nil {
				missingCount = release.Evidence.ArchCount - release.Evidence.VulnerabilityArchCount
			}
			addCheck("vulnerabilities.scanned", "fail", fmt.Sprintf("vulnerability scan coverage incomplete (%d platforms missing)", missingCount))
		}
	} else if hasScan {
		addCheck("vulnerabilities.scanned", "pass", "vulnerability scans present (not explicitly required)")
	}

	// 7. Check Production Gating
	if verifyOpts.requireProduction {
		if release.Lifecycle.ProductionAllowed {
			addCheck("lifecycle.productionAllowed", "pass", "image is approved for production deployment")
		} else {
			addCheck("lifecycle.productionAllowed", "fail", "production allowed check failed: this image is not approved for production use")
		}
	}

	// 8. Check Lifecycle Status
	lifecycleStatus := strings.ToLower(release.Lifecycle.Status)
	if lifecycleStatus == "preview" && !verifyOpts.allowPreview {
		addCheck("lifecycle.status", "fail", "lifecycle check failed: image is in 'preview' status (use --allow-preview to override)")
	} else if lifecycleStatus == "deprecated" && !verifyOpts.allowDeprecated {
		addCheck("lifecycle.status", "fail", "lifecycle check failed: image is in 'deprecated' status (use --allow-deprecated to override)")
	} else if lifecycleStatus == "eol" {
		addCheck("lifecycle.status", "fail", "lifecycle check failed: image is marked End-of-Life ('eol')")
	} else if lifecycleStatus == "blocked" {
		addCheck("lifecycle.status", "fail", "lifecycle check failed: image is 'blocked' due to security or platform concerns")
	} else {
		addCheck("lifecycle.status", "pass", fmt.Sprintf("lifecycle status verified: %s", lifecycleStatus))
	}

	// 9. Gating Vulnerability Thresholds
	if verifyOpts.maxCritical >= 0 || verifyOpts.maxHigh >= 0 {
		critExceeded := false
		highExceeded := false
		maxCritFound := 0
		maxHighFound := 0
		expiredExceptions := map[string]bool{}

		now := time.Now().UTC()

		for _, arch := range release.Architectures {
			if arch.Vulnerabilities == nil {
				continue
			}
			criticalCount := 0
			highCount := 0

			for _, finding := range arch.Vulnerabilities.Findings {
				// An active exception exempts a finding; an expired one never does,
				// but is recorded so --fail-on-expired-exceptions can surface it.
				if entry, expired := exceptionsDoc.Match(finding.ID, finding.PackageName, imageID, release.Tag, now); entry != nil {
					if expired {
						expiredExceptions[entry.ID] = true
					} else {
						continue
					}
				}

				sev := strings.ToLower(finding.Severity)
				if sev == "critical" {
					criticalCount++
				} else if sev == "high" {
					highCount++
				}
			}

			// If we don't have findings but have pre-aggregated counts, use them as fallback
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

			if verifyOpts.maxCritical >= 0 && criticalCount > verifyOpts.maxCritical {
				critExceeded = true
			}
			if verifyOpts.maxHigh >= 0 && highCount > verifyOpts.maxHigh {
				highExceeded = true
			}
		}

		if verifyOpts.failOnExpiredExceptions && len(expiredExceptions) > 0 {
			ids := make([]string, 0, len(expiredExceptions))
			for id := range expiredExceptions {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			addCheck("exceptions.expired", "fail", fmt.Sprintf("matched exception(s) expired and were not honored: %s", strings.Join(ids, ", ")))
		}

		if verifyOpts.maxCritical >= 0 {
			if critExceeded {
				addCheck("vulnerabilities.threshold.critical", "fail", fmt.Sprintf("critical vulnerability count %d exceeds maximum allowed %d", maxCritFound, verifyOpts.maxCritical))
			} else {
				addCheck("vulnerabilities.threshold.critical", "pass", fmt.Sprintf("critical vulnerabilities verified within limits (%d found, max allowed %d)", maxCritFound, verifyOpts.maxCritical))
			}
		}

		if verifyOpts.maxHigh >= 0 {
			if highExceeded {
				addCheck("vulnerabilities.threshold.high", "fail", fmt.Sprintf("high vulnerability count %d exceeds maximum allowed %d", maxHighFound, verifyOpts.maxHigh))
			} else {
				addCheck("vulnerabilities.threshold.high", "pass", fmt.Sprintf("high vulnerabilities verified within limits (%d found, max allowed %d)", maxHighFound, verifyOpts.maxHigh))
			}
		}
	}

	// 10. Risk-policy vulnerability gate (opt-in). The same config.Materiality the
	// remediation planner and the crypto floor use decides scope, so verify
	// blocks exactly the findings the rest of the platform treats as material:
	// reachable + production + (KEV | EPSS | severity). must_fix and unfixable
	// must_acknowledge block (the latter unless covered by an active exception —
	// an explicit, owned acknowledgement); everything else is policy-accepted and
	// emitted as an expiring OpenVEX record. This runs only when opted in, so the
	// legacy --max-critical/--max-high path is unchanged.
	if verifyOpts.requireVulnPolicy || verifyOpts.vexOutput != "" {
		policy := remediationPolicyFromJSON(verifyOpts.policyJSON)
		// Production-eligibility is fail-closed: gate the finding if EITHER the
		// image's own declared contract says production OR the policy lists its
		// tier. This closes the service-tier trap where a tier absent from
		// policy.ProductionTiers (e.g. a productionAllowed service image) would
		// otherwise make Materiality silently auto-accept every finding.
		prodTier := release.RuntimeContract.ProductionTier || productionTier(policy, record.Tier.ID)
		now := time.Now().UTC()

		mustFix := map[string]catalog.FindingInfo{}
		mustAck := map[string]catalog.FindingInfo{}
		accepted := map[string]policyAcceptance{}
		expiredExceptions := map[string]bool{}

		for _, arch := range release.Architectures {
			if arch.Vulnerabilities == nil {
				continue
			}
			for _, finding := range arch.Vulnerabilities.Findings {
				if finding.ID == "" {
					continue
				}
				key := finding.ID + "\x00" + finding.PackageName
				// An active exception is an explicit, owned acknowledgement: it
				// exempts the finding (and satisfies the must_acknowledge gate). An
				// expired one does not exempt — it re-blocks via its disposition AND
				// is surfaced below, so a lapsed acknowledgement is never silent.
				if entry, expired := exceptionsDoc.Match(finding.ID, finding.PackageName, imageID, release.Tag, now); entry != nil {
					if !expired {
						continue
					}
					expiredExceptions[entry.ID] = true
				}
				decision := findingMateriality(finding, prodTier, policy)
				switch decision.Disposition {
				case config.DispositionMustFix:
					mustFix[key] = finding
				case config.DispositionMustAcknowledge:
					mustAck[key] = finding
				case config.DispositionAutoAccept:
					accepted[key] = policyAcceptance{Finding: finding, Reason: decision.Reason}
				}
			}
		}

		if verifyOpts.requireVulnPolicy {
			if verifyOpts.failOnExpiredExceptions && len(expiredExceptions) > 0 {
				ids := make([]string, 0, len(expiredExceptions))
				for id := range expiredExceptions {
					ids = append(ids, id)
				}
				sort.Strings(ids)
				addCheck("vulnerabilities.policy.expiredExceptions", "fail", fmt.Sprintf("matched exception(s) expired and were not honored: %s", strings.Join(ids, ", ")))
			}
			if len(mustFix) > 0 {
				addCheck("vulnerabilities.policy.fixable", "fail", fmt.Sprintf("%d reachable, materially-risky, fixable finding(s) in a production tier: %s", len(mustFix), summarizeFindingKeys(mustFix)))
			} else {
				addCheck("vulnerabilities.policy.fixable", "pass", "no reachable, materially-risky, fixable findings outstanding")
			}
			if len(mustAck) > 0 {
				addCheck("vulnerabilities.policy.acknowledge", "fail", fmt.Sprintf("%d reachable, materially-risky, UNFIXABLE finding(s) require an explicit acknowledgement (add an exception): %s", len(mustAck), summarizeFindingKeys(mustAck)))
			} else {
				addCheck("vulnerabilities.policy.acknowledge", "pass", "no unacknowledged, materially-risky, unfixable findings")
			}
		}

		if verifyOpts.vexOutput != "" {
			if err := writePolicyVEX(verifyOpts.vexOutput, imageID, release.Tag, accepted, policy.AcceptedExpiryDays, now); err != nil {
				return fmt.Errorf("failed to write policy VEX records: %w", err)
			}
			// Human diagnostic only — never pollute the structured (json/yaml)
			// payload machine consumers read from stdout.
			format := strings.ToLower(GlobalOpts.Format)
			if !GlobalOpts.Quiet && format != "json" && format != "yaml" && format != "yml" && errOut != nil {
				fmt.Fprintf(errOut, "[verify] wrote %d policy-accepted VEX record(s) to %s\n", len(accepted), verifyOpts.vexOutput)
			}
		}
	}

	overallStatus := "pass"
	if hasFailures {
		overallStatus = "fail"
	}

	response := VerifyResponse{
		Status: overallStatus,
		Image:  imageID,
		Tag:    release.Tag,
		Checks: checks,
	}

	// Format output
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
		// Print human readable
		fmt.Fprintf(out, "Policy Gating Report for %s:%s\n", imageID, release.Tag)
		fmt.Fprintln(out, "-----------------------------------------------------------------")
		for _, check := range checks {
			statusSymbol := "✔ PASS"
			if check.Status == "fail" {
				statusSymbol = "✘ FAIL"
			}
			fmt.Fprintf(out, "[%-6s] %-32s : %s\n", statusSymbol, check.ID, check.Message)
		}
		fmt.Fprintln(out, "-----------------------------------------------------------------")
		if hasFailures {
			fmt.Fprintln(out, "Verification Result: FAIL")
		} else {
			fmt.Fprintln(out, "Verification Result: PASS")
		}
	}

	if hasFailures {
		return ErrCheckFailed
	}

	return nil
}
