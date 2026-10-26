package estateverify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/northcutted/clearcutt-verify/internal/report"
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
	// MaxScanAgeDays leaves images whose vulnerability scan is older
	// unverified.
	MaxScanAgeDays int `json:"maxScanAgeDays"`
	// StackSigners may sign clearcutt-factory stacks (a trust policy's
	// stack signers join them).
	StackSigners []report.Signer `json:"stackSigners"`
	// TrustPolicy names a TrustPolicy file (relative to this one) whose
	// image signers are trusted too, the same file clearcutt-factory reads.
	TrustPolicy string `json:"trustPolicy"`
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
	// Key files are relative to the file that names them, as clearcutt-factory
	// reads them: cosign (and, for --reproduce, clearcutt-factory) runs
	// elsewhere.
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return report.Policy{}, err
	}
	for _, signers := range [][]report.Signer{f.TrustedSigner, f.StackSigners} {
		for i := range signers {
			signers[i].Key = keyPath(dir, signers[i].Key)
		}
	}
	p := report.Policy{Required: f.Required, TrustedSigners: f.TrustedSigner, FailOn: f.FailOn, OnlyFixed: f.OnlyFixed, MaxDaysBehind: f.MaxDaysBehind, MaxScanAgeDays: f.MaxScanAgeDays, StackSigners: f.StackSigners}
	if f.TrustPolicy != "" {
		tp := f.TrustPolicy
		if !filepath.IsAbs(tp) {
			tp = filepath.Join(filepath.Dir(path), tp)
		}
		t, err := ReadTrustPolicy(tp)
		if err != nil {
			return report.Policy{}, err
		}
		p.TrustedSigners = append(p.TrustedSigners, t.For("image")...)
		p.StackSigners = append(p.StackSigners, t.For("stack")...)
	}
	return p, ValidatePolicy(p)
}

// ReadTrustPolicy reads a TrustPolicy file (YAML or JSON).
func ReadTrustPolicy(path string) (report.TrustPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return report.TrustPolicy{}, err
	}
	var t report.TrustPolicy
	if err := yaml.UnmarshalStrict(raw, &t); err != nil {
		return report.TrustPolicy{}, fmt.Errorf("%s: %w", path, err)
	}
	if t.APIVersion != report.APIVersion || t.Kind != report.KindTrustPolicy {
		return report.TrustPolicy{}, fmt.Errorf("%s: expected apiVersion %s and kind %s", path, report.APIVersion, report.KindTrustPolicy)
	}
	// A key file is relative to the trust policy (as clearcutt-factory reads
	// it), so cosign finds it wherever it runs and the report names it.
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return report.TrustPolicy{}, err
	}
	for i := range t.Signers {
		t.Signers[i].Key = keyPath(dir, t.Signers[i].Key)
	}
	for i, s := range t.Signers {
		for _, r := range s.Roles {
			if r != "image" && r != "stack" {
				return report.TrustPolicy{}, fmt.Errorf("%s: signers[%d]: role %q must be image or stack", path, i, r)
			}
		}
		if _, err := signerFlags(s.Signer()); err != nil {
			return report.TrustPolicy{}, fmt.Errorf("%s: signers[%d] %s: %w", path, i, s.Name, err)
		}
	}
	return t, nil
}

// keyPath resolves a key file relative to dir, the directory of the file
// that names it. cosign KMS and other URIs (with "://", or pkcs11:) are used
// as they are.
func keyPath(dir, k string) string {
	if k == "" || strings.Contains(k, "://") || strings.HasPrefix(k, "pkcs11:") || filepath.IsAbs(k) {
		return k
	}
	return filepath.Join(dir, k)
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
	for _, s := range append(append([]report.Signer{}, p.TrustedSigners...), p.StackSigners...) {
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
	return verdictAt(img, p, time.Now())
}

// verdictAt decides the verdict as of now (the report's time), which
// scan ages are measured against.
func verdictAt(img report.Image, p report.Policy, now time.Time) report.Verdict {
	var failed, unverified []string
	switch {
	case len(p.TrustedSigners) == 0:
		// Nothing about an image can be verified without someone to trust.
		unverified = append(unverified, "no trusted signer is configured, so nothing about it can be verified")
	case !anyVerified(img.Evidence):
		// A verdict rests on something a trusted signer vouched for; checks
		// that read no evidence (base drift, scan age) can't stand alone.
		unverified = append(unverified, "none of its evidence is verified, so a trusted signer vouched for nothing about it")
	}
	// Only verified evidence meets a requirement. The one exception is a
	// recipe that doesn't apply because the image was rebased, and that holds
	// only when its rebase record is verified: anything a trusted signer
	// didn't vouch for (present, failed, unknown, missing) never stands in.
	rebase := img.Evidence.Rebase.Status
	for _, k := range p.Required {
		item := evidenceItem(img.Evidence, k)
		switch st := item.Status; {
		case st == "verified":
		case st == "not-applicable" && k == KindRecipe && rebase == "verified":
		case st == "not-applicable":
			unverified = append(unverified, k+" is not applicable, and no verified evidence stands in for it")
		case st == "present":
			unverified = append(unverified, k+" is present but not verified")
		case st == "unknown":
			unverified = append(unverified, k+" is unknown (couldn't be read or checked)")
		case st == "failed":
			failed = append(failed, k+" failed verification")
		case k == KindRecipe && (rebase == "present" || rebase == "unknown"):
			// A rebased image has no recipe of its own; whether this one was
			// rebased rests on a record nobody could vouch for.
			unverified = append(unverified, "recipe is missing, and the rebase record that would stand in for it is "+rebase+", not verified")
		case st == "missing" || st == "":
			failed = append(failed, k+" is missing")
		default:
			unverified = append(unverified, fmt.Sprintf("%s has status %q, which isn't verified", k, st))
		}
	}
	if p.FailOn != "" {
		// Findings come only from verified scans; a scan that isn't verified
		// on every platform leaves the rest unknown, never clean.
		scan := img.Evidence.VulnerabilityScan.Status
		if v := img.Vulnerabilities; v != nil {
			if n := countAtOrAbove(v, p.FailOn, p.OnlyFixed); n > 0 {
				fixable := ""
				if p.OnlyFixed {
					fixable = " fixable"
				}
				failed = append(failed, fmt.Sprintf("%d%s vulnerabilities at %s or above", n, fixable, p.FailOn))
			}
		}
		switch {
		case img.Vulnerabilities == nil && (scan == "missing" || scan == ""):
			unverified = append(unverified, "vulnerabilities are unknown (no scan)")
		case scan != "verified":
			unverified = append(unverified, "vulnerabilities are unknown (the vulnerability scan is "+scan+", not verified)")
		case img.Vulnerabilities == nil:
			unverified = append(unverified, "vulnerabilities are unknown (the verified scan couldn't be read)")
		}
	}
	if p.MaxScanAgeDays > 0 {
		// The age is measured on verified scans of every platform; with none
		// to measure, how old its findings are is unknown.
		var scanned time.Time
		var err error
		if img.Vulnerabilities != nil {
			scanned, err = time.Parse(time.RFC3339, img.Vulnerabilities.ScannedAt)
		}
		switch {
		case img.Vulnerabilities == nil || img.Evidence.VulnerabilityScan.Status != "verified":
			unverified = append(unverified, "the vulnerability scan's age is unknown (no verified scan of every platform)")
		case err != nil:
			unverified = append(unverified, "the vulnerability scan's age is unknown (no scan time)")
		case now.Sub(scanned) > time.Duration(p.MaxScanAgeDays)*24*time.Hour:
			unverified = append(unverified, fmt.Sprintf("the vulnerability scan is %d days old (limit %d); what was found since is unknown",
				int(now.Sub(scanned).Hours()/24), p.MaxScanAgeDays))
		}
	}
	if p.MaxDaysBehind > 0 {
		// Only drift from a base proven by layer digests can fail an image:
		// drift from a base its author claims is as good as the claim, so at
		// worst it leaves the image unverified.
		switch b := img.Base; {
		case b != nil && b.Strength == "proof" && b.DaysBehind > p.MaxDaysBehind:
			failed = append(failed, fmt.Sprintf("base is %d days behind its newest version (limit %d)", b.DaysBehind, p.MaxDaysBehind))
		case b != nil && b.DaysBehind > p.MaxDaysBehind:
			unverified = append(unverified, fmt.Sprintf("its base is %d days behind its newest version (limit %d) by what the image claims (%s, %s), which isn't proven by layer digests", b.DaysBehind, p.MaxDaysBehind, b.Strength, b.Method))
		case b != nil && b.Drift == "stale" && b.DaysBehindUnknown:
			unverified = append(unverified, "its base is behind its newest version, by how many days couldn't be measured")
		case b != nil && b.Drift == "unknown", b == nil && img.Root == "":
			// A root has no base to fall behind; anything else might.
			unverified = append(unverified, "how far its base is behind couldn't be measured")
		}
	}
	if p.Reproduce {
		switch r := img.Reproducibility; {
		case r.Status == "not-reproduced":
			failed = append(failed, "rebuilding gave a different digest")
		case r.Status == "not-checked":
			// Including an image whose recipe or rebase record couldn't be
			// read: whether there is anything to rebuild is unknown.
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

// anyVerified reports whether any of the image's evidence verified against a
// trusted signer.
func anyVerified(e report.Evidence) bool {
	for _, k := range Kinds {
		if evidenceItem(e, k).Status == "verified" {
			return true
		}
	}
	return false
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
