package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/config"
)

// policyAcceptance is one finding the risk policy auto-accepted, carrying the
// reason so the emitted VEX record explains why (and re-derives each scan).
type policyAcceptance struct {
	Finding catalog.FindingInfo
	Reason  string
}

// findingMateriality classifies one catalog finding under the risk policy. The
// release gate (verify) and the evidence emitter (vex) share it so a finding can
// never be blocked by one consumer and waved through by the other — the single
// config.Materiality decision the remediation planner and the crypto floor also
// run.
func findingMateriality(finding catalog.FindingInfo, productionTier bool, policy config.RemediationPolicy) config.RiskDecision {
	return config.Materiality(config.MaterialityInput{
		Severity:       finding.Severity,
		EPSSPercentile: finding.EpssPercentile,
		KEV:            finding.KEV != nil && finding.KEV.KnownExploited,
		Layer:          finding.Layer,
		HasFix:         findingHasFix(finding.FixedIn), // same predicate the planner uses
		ProductionTier: productionTier,
	}, policy)
}

// ClearCuttVEXExtension is a namespaced OpenVEX extension recording that a
// finding was accepted by the risk policy (not a human waiver) and when that
// acceptance expires. It is isolated under one "clearcutt" key with omitempty so
// standard OpenVEX statements never carry non-standard fields, and the acceptance
// is never silent — it is visible and time-boxed, re-evaluated each scan.
type ClearCuttVEXExtension struct {
	Acceptance string `json:"acceptance"`          // policy_auto_accept
	Reason     string `json:"reason"`              // below_risk_threshold | not_reachable_base_layer | non_production
	ExpiresAt  string `json:"expiresAt,omitempty"` // YYYY-MM-DD, now + AcceptedExpiryDays
}

// policyAcceptanceStatement builds the OpenVEX statement for a policy-accepted
// finding. The status is "affected" (the vuln IS present; we accept the risk by
// policy) — the same mapping vex.go uses for a human accepted_risk exception, not
// a not_affected claim. The expiry makes the acceptance time-boxed.
func policyAcceptanceStatement(finding catalog.FindingInfo, product OpenVEXProduct, reason string, now time.Time, expiryDays int) OpenVEXStatement {
	expires := ""
	if expiryDays > 0 {
		expires = now.AddDate(0, 0, expiryDays).Format("2006-01-02")
	}
	return OpenVEXStatement{
		Vulnerability:   OpenVEXVulnerability{Name: finding.ID},
		Products:        []OpenVEXProduct{product},
		Status:          vexAffected,
		ImpactStatement: policyAcceptanceImpact(reason),
		Timestamp:       now.Format(time.RFC3339),
		ClearCutt: &ClearCuttVEXExtension{
			Acceptance: "policy_auto_accept",
			Reason:     reason,
			ExpiresAt:  expires,
		},
	}
}

func policyAcceptanceImpact(reason string) string {
	switch reason {
	case "not_reachable_base_layer":
		return "Present in the base image layer, not the shipped runtime closure; accepted by risk policy and re-evaluated each scan."
	case "non_production":
		return "Image tier is not production-eligible; accepted by risk policy and re-evaluated each scan."
	case "no_fix_unrequired":
		return "Reachable and materially risky but with no upstream fix; accepted by policy (requireFixedVersion=false) and re-evaluated each scan."
	default: // below_risk_threshold
		return "Below the materiality bar (KEV / EPSS percentile / severity); accepted by risk policy and re-evaluated each scan."
	}
}

// summarizeFindingKeys renders a short, deterministic "CVE (package)" list for a
// gate message, capped so a flood of findings doesn't bury the failure line.
func summarizeFindingKeys(findings map[string]catalog.FindingInfo) string {
	items := make([]string, 0, len(findings))
	for _, f := range findings {
		items = append(items, fmt.Sprintf("%s (%s)", f.ID, f.PackageName))
	}
	sort.Strings(items)
	const cap = 8
	if len(items) > cap {
		extra := len(items) - cap
		items = items[:cap]
		items = append(items, fmt.Sprintf("+%d more", extra))
	}
	return strings.Join(items, ", ")
}

// writePolicyVEX serializes the policy-accepted set as an OpenVEX document with
// expiring acceptance records. Output is deterministic (statements sorted by
// CVE+package) so re-runs produce a stable diff.
func writePolicyVEX(path, imageID, tag string, accepted map[string]policyAcceptance, expiryDays int, now time.Time) error {
	product := OpenVEXProduct{ID: fmt.Sprintf("pkg:nix/%s@%s", imageID, tag)}
	keys := make([]string, 0, len(accepted))
	for k := range accepted {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	doc := OpenVEXDocument{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("https://clearcutt.internal/vex/%s/%s/policy-accepted", imageID, tag),
		Author:     "ClearCutt Security Platform Gating Engine",
		Role:       "Document Creator",
		Timestamp:  now.Format(time.RFC3339),
		Version:    1,
		Statements: []OpenVEXStatement{},
	}
	for _, k := range keys {
		acc := accepted[k]
		doc.Statements = append(doc.Statements, policyAcceptanceStatement(acc.Finding, product, acc.Reason, now, expiryDays))
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode OpenVEX document: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create VEX output directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("failed to write OpenVEX document to %s: %w", path, err)
	}
	return nil
}
