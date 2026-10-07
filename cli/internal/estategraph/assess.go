package estategraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

type AssessOptions struct {
	GeneratedAt string
	CatalogPath string
}

func Assess(inventory ImagesFile, observations Observations, opts AssessOptions) (Assessment, error) {
	generatedAt := opts.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	obsByID := map[string]Observation{}
	for _, obs := range observations.Images {
		normalizeObservation(&obs)
		if obs.ID != "" {
			obsByID[obs.ID] = obs
		}
	}
	cataloged := map[string]bool{}
	if opts.CatalogPath != "" {
		idx, err := catalog.LoadCatalogIndex(opts.CatalogPath)
		if err != nil {
			return Assessment{}, fmt.Errorf("load assessment catalog: %w", err)
		}
		for _, image := range idx.Images {
			cataloged[image.ID] = true
		}
	}
	result := Assessment{
		GeneratedAt: generatedAt,
		Summary: AssessmentSummary{
			MissingEvidenceByChannel:  map[string]int{},
			ObservedEvidenceByChannel: map[string]int{},
			VerifiedEvidenceByChannel: map[string]int{},
			RuntimeContractGapsByType: map[string]int{},
			PolicyPostureByStatus:     map[string]int{},
			ImagesByRuntime:           map[string]int{},
			ImagesByTier:              map[string]int{},
		},
		Images: []ImageAssessment{},
	}
	specs := append([]ImageSpec(nil), inventory.Images...)
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].ID < specs[j].ID })
	for _, spec := range specs {
		obs := obsByID[spec.ID]
		item := assessImage(spec, obs)
		if cataloged[spec.ID] {
			result.Summary.CatalogedImages++
		}
		result.Summary.ImportedImages++
		result.Summary.ImagesByRuntime[spec.Language.ID]++
		result.Summary.ImagesByTier[spec.Tier]++
		if item.DigestRef != "" {
			result.Summary.ResolvedDigestRefs++
		}
		if item.MutableRef {
			result.Summary.MutableOrUnresolvedRefs++
		}
		if item.ClassificationConfidence == "low" || item.ClassificationConfidence == "" {
			result.Summary.LowConfidenceClassifications++
		}
		for _, ch := range item.MissingEvidence {
			result.Summary.MissingEvidenceByChannel[ch]++
		}
		for _, ch := range item.ObservedEvidence {
			result.Summary.ObservedEvidenceByChannel[ch]++
		}
		for _, ch := range item.VerifiedEvidence {
			result.Summary.VerifiedEvidenceByChannel[ch]++
		}
		for _, gap := range item.RuntimeContractGaps {
			result.Summary.RuntimeContractGapsByType[gap]++
		}
		result.Summary.PolicyPostureByStatus[item.PolicyPosture]++
		result.Images = append(result.Images, item)
	}
	return result, nil
}

func assessImage(spec ImageSpec, obs Observation) ImageAssessment {
	confidence := ""
	if spec.Governance != nil {
		confidence = spec.Governance.ClassificationConfidence
	}
	item := ImageAssessment{
		ID:                       spec.ID,
		Image:                    spec.Image,
		Language:                 spec.Language.ID,
		Tier:                     spec.Tier,
		DigestRef:                obs.DigestRef,
		MutableRef:               obs.DigestRef == "" || !strings.Contains(spec.Image, "@sha256:"),
		ClassificationConfidence: firstNonEmpty(confidence, "low"),
		MissingEvidence:          []string{},
		ObservedEvidence:         []string{},
		VerifiedEvidence:         []string{},
		RuntimeContractGaps:      runtimeContractGaps(spec, obs),
		Warnings:                 append([]string{}, obs.Warnings...),
	}
	channels := map[string]EvidenceChannel{
		"signature":         obs.Evidence.Signature,
		"sbom":              obs.Evidence.SBOM,
		"provenance":        obs.Evidence.Provenance,
		"vulnerabilityScan": obs.Evidence.VulnerabilityScan,
		"tests":             obs.Evidence.Tests,
	}
	for _, name := range []string{"signature", "sbom", "provenance", "vulnerabilityScan", "tests"} {
		switch strings.ToLower(strings.TrimSpace(channels[name].Status)) {
		case "verified":
			item.VerifiedEvidence = append(item.VerifiedEvidence, name)
		case "observed", "attested", "stale":
			item.ObservedEvidence = append(item.ObservedEvidence, name)
		default:
			item.MissingEvidence = append(item.MissingEvidence, name)
		}
	}
	item.PolicyPosture = policyPosture(item, spec, channels)
	return item
}

func runtimeContractGaps(spec ImageSpec, obs Observation) []string {
	gaps := []string{}
	if isRootUser(obs.User) {
		gaps = append(gaps, "root user")
	}
	if spec.RuntimeContract != nil {
		if spec.RuntimeContract.ShellPresent != nil && *spec.RuntimeContract.ShellPresent {
			gaps = append(gaps, "shell present")
		}
		if spec.RuntimeContract.PackageManagerPresent != nil && *spec.RuntimeContract.PackageManagerPresent {
			gaps = append(gaps, "package manager present")
		}
		if spec.RuntimeContract.CACertificatesPresent != nil && !*spec.RuntimeContract.CACertificatesPresent {
			gaps = append(gaps, "no CA certificates")
		}
		if spec.RuntimeContract.TimezoneDataPresent != nil && !*spec.RuntimeContract.TimezoneDataPresent {
			gaps = append(gaps, "no timezone data")
		}
	}
	if len(obs.Platforms) > 0 {
		hasSupported := false
		for _, platform := range obs.Platforms {
			if platform == "linux/amd64" || platform == "linux/arm64" {
				hasSupported = true
			}
		}
		if !hasSupported {
			gaps = append(gaps, "unsupported architecture")
		}
	}
	return gaps
}

func isRootUser(user string) bool {
	principal := strings.TrimSpace(strings.SplitN(user, ":", 2)[0])
	return principal == "" || principal == "0" || strings.EqualFold(principal, "root")
}

func policyPosture(item ImageAssessment, spec ImageSpec, channels map[string]EvidenceChannel) string {
	if spec.Governance != nil && spec.Governance.ProductionIntent == "blocked" {
		return "blocked"
	}
	if len(missingRequiredEvidence(channels, spec)) > 0 {
		return "review-required"
	}
	if allEvidenceVerified(channels) && item.DigestRef != "" && len(item.RuntimeContractGaps) == 0 {
		return "production-admissible"
	}
	if len(item.VerifiedEvidence) > 0 && item.DigestRef != "" {
		return "candidate"
	}
	if item.MutableRef || item.ClassificationConfidence == "low" {
		return "review-required"
	}
	return "inventory-only"
}

func allEvidenceVerified(channels map[string]EvidenceChannel) bool {
	for _, channel := range []string{"signature", "sbom", "provenance", "vulnerabilityScan", "tests"} {
		if !strings.EqualFold(strings.TrimSpace(channels[channel].Status), catalog.EvidenceStatusVerified) {
			return false
		}
	}
	return true
}

func missingRequiredEvidence(channels map[string]EvidenceChannel, spec ImageSpec) []string {
	if spec.EvidencePolicy == nil {
		return nil
	}
	required := map[string]string{
		"signature":         spec.EvidencePolicy.Signature,
		"sbom":              spec.EvidencePolicy.SBOM,
		"provenance":        spec.EvidencePolicy.Provenance,
		"vulnerabilityScan": spec.EvidencePolicy.VulnerabilityScan,
		"tests":             spec.EvidencePolicy.Tests,
	}
	var missing []string
	for _, channel := range []string{"signature", "sbom", "provenance", "vulnerabilityScan", "tests"} {
		if strings.EqualFold(required[channel], "required") && !observationChannelSatisfies(channel, channels[channel]) {
			missing = append(missing, channel)
		}
	}
	return missing
}

func observationChannelSatisfies(name string, channel EvidenceChannel) bool {
	status := strings.ToLower(strings.TrimSpace(channel.Status))
	switch name {
	case "signature", "provenance", "tests":
		return status == catalog.EvidenceStatusVerified
	case "sbom", "vulnerabilityScan":
		return status == catalog.EvidenceStatusObserved || status == catalog.EvidenceStatusVerified || status == catalog.EvidenceStatusAttested
	default:
		return false
	}
}

func WriteAssessmentDir(dir string, assessment Assessment) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := map[string]any{
		"estate-summary.json":        assessment,
		"evidence-gaps.json":         evidenceGaps(assessment),
		"policy-posture.json":        assessment.Summary.PolicyPostureByStatus,
		"stale-tags.json":            staleTags(assessment),
		"runtime-contract-gaps.json": runtimeGaps(assessment),
	}
	for name, value := range files {
		if err := writeJSON(filepath.Join(dir, name), value); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "estate-summary.md"), []byte(SummaryMarkdown(assessment)), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-gaps.md"), []byte(EvidenceGapsMarkdown(assessment)), 0o644); err != nil {
		return err
	}
	return nil
}

func evidenceGaps(assessment Assessment) map[string]any {
	return map[string]any{
		"missingEvidenceByChannel": assessment.Summary.MissingEvidenceByChannel,
		"images":                   assessment.Images,
	}
}

func staleTags(assessment Assessment) []ImageAssessment {
	var out []ImageAssessment
	for _, image := range assessment.Images {
		if image.MutableRef {
			out = append(out, image)
		}
	}
	return out
}

func runtimeGaps(assessment Assessment) []ImageAssessment {
	var out []ImageAssessment
	for _, image := range assessment.Images {
		if len(image.RuntimeContractGaps) > 0 {
			out = append(out, image)
		}
	}
	return out
}

func SummaryMarkdown(assessment Assessment) string {
	s := assessment.Summary
	var b strings.Builder
	fmt.Fprintf(&b, "# Imported Fleet Assessment\n\n")
	fmt.Fprintf(&b, "ClearCutt did not build this estate. Missing evidence is a governance gap, not proof that an image is insecure.\n\n")
	fmt.Fprintf(&b, "- %d images imported\n", s.ImportedImages)
	fmt.Fprintf(&b, "- %d images cataloged\n", s.CatalogedImages)
	fmt.Fprintf(&b, "- %d refs resolved to digests\n", s.ResolvedDigestRefs)
	fmt.Fprintf(&b, "- %d refs remain mutable or unresolved\n", s.MutableOrUnresolvedRefs)
	fmt.Fprintf(&b, "- %d images have verified provenance\n", s.VerifiedEvidenceByChannel["provenance"])
	fmt.Fprintf(&b, "- %d images have observed SBOM evidence\n", s.ObservedEvidenceByChannel["sbom"])
	fmt.Fprintf(&b, "- %d images have verified SBOM evidence\n", s.VerifiedEvidenceByChannel["sbom"])
	fmt.Fprintf(&b, "- %d images are missing SBOM evidence\n", s.MissingEvidenceByChannel["sbom"])
	fmt.Fprintf(&b, "- %d images have low-confidence runtime classification\n", s.LowConfidenceClassifications)
	fmt.Fprintf(&b, "- %d images are production-admissible under current evidence policy\n", s.PolicyPostureByStatus["production-admissible"])
	fmt.Fprintf(&b, "- %d images are useful for inventory/catalog visibility\n", s.ImportedImages)
	fmt.Fprintf(&b, "\nObserved SBOM is not build provenance.\n")
	return b.String()
}

func EvidenceGapsMarkdown(assessment Assessment) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Evidence Gaps\n\n")
	fmt.Fprintf(&b, "| Channel | Missing | Observed | Verified |\n|---|---:|---:|---:|\n")
	for _, ch := range []string{"signature", "sbom", "provenance", "vulnerabilityScan", "tests"} {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n",
			ch,
			assessment.Summary.MissingEvidenceByChannel[ch],
			assessment.Summary.ObservedEvidenceByChannel[ch],
			assessment.Summary.VerifiedEvidenceByChannel[ch],
		)
	}
	return b.String()
}
