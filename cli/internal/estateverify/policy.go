package estateverify

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	"github.com/northcutted/clearcutt/internal/report"
)

// PolicyFile is a verification policy on disk:
//
//	apiVersion: clearcutt.dev/v1
//	kind: VerificationPolicy
//	required: [signature, sbom, vulnerabilityScan, provenance]
//	trustedSigners:
//	  - identityRegexp: ^https://github\.com/acme/
//	    issuer: https://token.actions.githubusercontent.com
//	    sourceRepositoryOwner: https://github.com/acme
//	failOn: critical
//	onlyFixed: true
//	maxDaysBehind: 30
type PolicyFile struct {
	APIVersion    string          `json:"apiVersion"`
	Kind          string          `json:"kind"`
	Required      []string        `json:"required"`
	TrustedSigner []report.Signer `json:"trustedSigners"`
	FailOn        string          `json:"failOn"`
	OnlyFixed     bool            `json:"onlyFixed"`
	MaxDaysBehind int             `json:"maxDaysBehind"`
}

// ReadPolicy reads a VerificationPolicy file.
func ReadPolicy(path string) (report.Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return report.Policy{}, err
	}
	var f PolicyFile
	if err := yaml.UnmarshalStrict(raw, &f); err != nil {
		return report.Policy{}, fmt.Errorf("%s: %w", path, err)
	}
	if f.APIVersion != report.APIVersion || f.Kind != "VerificationPolicy" {
		return report.Policy{}, fmt.Errorf("%s: expected apiVersion %s and kind VerificationPolicy", path, report.APIVersion)
	}
	p := report.Policy{Required: f.Required, TrustedSigners: f.TrustedSigner, FailOn: f.FailOn, OnlyFixed: f.OnlyFixed, MaxDaysBehind: f.MaxDaysBehind}
	return p, ValidatePolicy(p)
}

// ValidatePolicy checks the policy's requirements and signers.
func ValidatePolicy(p report.Policy) error {
	for _, k := range p.Required {
		if k == KindRebase || !contains(Kinds, k) {
			return fmt.Errorf("required evidence %q must be one of signature, sbom, vulnerabilityScan, provenance, recipe, tests", k)
		}
	}
	if p.FailOn != "" && severityRank(p.FailOn) == 0 {
		return fmt.Errorf("failOn %q must be negligible, low, medium, high, or critical", p.FailOn)
	}
	for _, s := range p.TrustedSigners {
		if _, err := signerFlags(s); err != nil {
			return err
		}
		if s.Key != "" && (constrainsCaller(s) || s.SourceRef != "") {
			return fmt.Errorf("trusted signer %s: source constraints apply to keyless (GitHub Actions) signers, not keys", s.Key)
		}
	}
	return nil
}

// verdict decides whether an image meets the policy. A requirement that
// can't be decided makes the image unverified, never verified.
func verdict(img report.Image, p report.Policy) report.Verdict {
	var failed, unverified []string
	for _, k := range p.Required {
		item := evidenceItem(img.Evidence, k)
		switch item.Status {
		case "verified", "not-applicable":
		case "present":
			unverified = append(unverified, k+" is present but not verified")
		case "unknown":
			unverified = append(unverified, k+" is unknown (couldn't be read)")
		case "failed":
			failed = append(failed, k+" failed verification")
		default:
			failed = append(failed, k+" is missing")
		}
	}
	if p.FailOn != "" {
		if img.Vulnerabilities == nil {
			unverified = append(unverified, "vulnerabilities are unknown (no scan)")
		} else if n := countAtOrAbove(img.Vulnerabilities, p.FailOn, p.OnlyFixed); n > 0 {
			fixable := ""
			if p.OnlyFixed {
				fixable = " fixable"
			}
			failed = append(failed, fmt.Sprintf("%d%s vulnerabilities at %s or above", n, fixable, p.FailOn))
		}
	}
	if p.MaxDaysBehind > 0 {
		switch b := img.Base; {
		case b != nil && b.DaysBehind > p.MaxDaysBehind:
			failed = append(failed, fmt.Sprintf("base is %d days behind its newest version (limit %d)", b.DaysBehind, p.MaxDaysBehind))
		case b != nil && b.Drift == "unknown", b == nil && img.Root == "":
			// A root has no base to fall behind; anything else might.
			unverified = append(unverified, "how far its base is behind couldn't be measured")
		}
	}
	if p.Reproduce {
		switch r := img.Reproducibility; {
		case r.Status == "not-reproduced":
			failed = append(failed, "rebuilding gave a different digest")
		case r.Status == "not-checked" && r.Method != "":
			unverified = append(unverified, "reproducibility couldn't be checked")
		}
	}
	switch {
	case len(failed) > 0:
		return report.Verdict{Status: "failed", Reasons: append(failed, unverified...)}
	case len(unverified) > 0:
		return report.Verdict{Status: "unverified", Reasons: unverified}
	}
	return report.Verdict{Status: "verified", Reasons: []string{}}
}

func countAtOrAbove(v *report.Vulnerabilities, sev string, onlyFixed bool) int {
	n := 0
	for _, f := range v.Findings {
		if f.Suppressed || severityRank(f.Severity) < severityRank(sev) || (onlyFixed && len(f.FixedIn) == 0) {
			continue
		}
		n++
	}
	return n
}

func evidenceItem(e report.Evidence, kind string) report.EvidenceItem {
	switch kind {
	case KindSignature:
		return e.Signature
	case KindSBOM:
		return e.SBOM
	case KindVulnerabilityScan:
		return e.VulnerabilityScan
	case KindProvenance:
		return e.Provenance
	case KindRecipe:
		return e.Recipe
	case KindRebase:
		return e.Rebase
	case KindTests:
		return e.Tests
	}
	return report.EvidenceItem{Status: "unknown"}
}

// summarize computes the report's headline counts.
func summarize(r *report.Report) report.Summary {
	s := report.Summary{Images: len(r.Images), Evidence: map[string]report.StatusCounts{}}
	for _, k := range Kinds {
		s.Evidence[k] = report.StatusCounts{}
	}
	for _, img := range r.Images {
		switch img.Verdict.Status {
		case "verified":
			s.Verdicts.Verified++
		case "failed":
			s.Verdicts.Failed++
		default:
			s.Verdicts.Unverified++
		}
		for _, k := range Kinds {
			c := s.Evidence[k]
			switch evidenceItem(img.Evidence, k).Status {
			case "verified":
				c.Verified++
			case "present":
				c.Present++
			case "failed":
				c.Failed++
			case "missing":
				c.Missing++
			case "not-applicable":
				c.NotApplicable++
			default:
				c.Unknown++
			}
			s.Evidence[k] = c
		}
		switch {
		case img.Base != nil && img.Base.Strength == "proof":
			s.Bases.Proven++
		case img.Base != nil:
			s.Bases.Claimed++
		case img.Root != "":
			s.Bases.Roots++
		default:
			s.Bases.Unresolved++
		}
		if img.Base != nil {
			switch img.Base.Drift {
			case "current":
				s.Bases.Current++
			case "stale":
				s.Bases.Stale++
			}
		}
		if v := img.Vulnerabilities; v != nil {
			s.Vulnerabilities.Scanned++
			addCounts(&s.Vulnerabilities.Counts, v.Counts)
			addCounts(&s.Vulnerabilities.Fixable, v.Fixable)
		} else {
			s.Vulnerabilities.NotScanned++
		}
		if img.Packages != nil {
			s.Packages.Known++
		} else {
			s.Packages.Unknown++
		}
		switch img.Reproducibility.Status {
		case "reproduced":
			s.Reproducibility.Reproduced++
		case "not-reproduced":
			s.Reproducibility.NotReproduced++
		case "not-checked":
			s.Reproducibility.NotChecked++
		default:
			s.Reproducibility.NoRecipe++
		}
	}
	return s
}

func addCounts(a *report.SeverityCounts, b report.SeverityCounts) {
	a.Critical += b.Critical
	a.High += b.High
	a.Medium += b.Medium
	a.Low += b.Low
	a.Negligible += b.Negligible
	a.Unknown += b.Unknown
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
