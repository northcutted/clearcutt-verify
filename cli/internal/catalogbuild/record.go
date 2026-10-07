package catalogbuild

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

type parsedCatalogAssetName struct {
	Target   string
	Kind     string
	Ext      string
	Filename string
}

var catalogAssetNameRe = regexp.MustCompile(`^(.+?)\.(sbom|test-results|intoto|digest|sigstore)\.(json|jsonl)$`)

func parseCatalogTargetName(filename string) *parsedCatalogAssetName {
	m := catalogAssetNameRe.FindStringSubmatch(filename)
	if m == nil {
		return nil
	}
	return &parsedCatalogAssetName{Target: m[1], Kind: m[2], Ext: m[3], Filename: filename}
}

type TargetInfo struct {
	LangKey string
	Tier    string
}

func TargetMeta(target string) *TargetInfo {
	idx := strings.LastIndex(target, "-")
	if idx == -1 {
		return nil
	}
	langKey := target[:idx]
	tier := target[idx+1:]
	if _, ok := gatherLanguages[langKey]; !ok {
		return nil
	}
	if _, ok := gatherTiers[tier]; !ok {
		return nil
	}
	return &TargetInfo{LangKey: langKey, Tier: tier}
}

type recordTarget struct {
	ID              string
	Kind            string
	SchemaVersion   string
	Language        Language
	Tier            Tier
	ImageNameKey    string
	Lifecycle       Lifecycle
	RuntimeContract RuntimeContract
	Service         *catalog.ServiceInfo
}

func runtimeRecordTarget(target string) *recordTarget {
	meta := TargetMeta(target)
	if meta == nil {
		return nil
	}
	langInfo := gatherLanguages[meta.LangKey]
	tierInfo := gatherTiers[meta.Tier]
	return &recordTarget{
		ID:              target,
		SchemaVersion:   catalog.ImageRecordSchemaVersion,
		Language:        Language{ID: langInfo.ID, DisplayName: langInfo.Display, Version: langInfo.Version},
		Tier:            Tier{ID: meta.Tier, Name: tierInfo.Name, Blurb: tierInfo.Blurb},
		ImageNameKey:    meta.LangKey,
		Lifecycle:       determineLifecycle(target, meta.Tier),
		RuntimeContract: determineRuntimeContract(target, meta.Tier),
	}
}

func displayAssertionName(name string) string {
	switch name {
	case "Grype Vulnerability Gating":
		return "Vulnerability gate"
	case "Syft SBOM Generation":
		return "SBOM generation"
	default:
		return name
	}
}

func normalizeAssertions(assertions []Assertion) []Assertion {
	out := make([]Assertion, 0, len(assertions))
	for _, assertion := range assertions {
		assertion.Name = displayAssertionName(assertion.Name)
		out = append(out, assertion)
	}
	return out
}

func remediationReason(finding catalog.FindingInfo) string {
	if finding.Remediation != nil && finding.Remediation.Reason != "" {
		return finding.Remediation.Reason
	}
	severity := strings.ToLower(FirstNonEmptyStr(finding.Severity, "Unknown"))
	layer := FirstNonEmptyStr(finding.Layer, "base")
	switch {
	case layer != "runtime":
		return "base_layer"
	case severity != "critical" && severity != "high":
		return "below_priority_threshold"
	case finding.FixedIn == nil || *finding.FixedIn == "":
		return "no_fixed_version"
	default:
		return "fix_available"
	}
}

func remediationBucket(reason string) string {
	switch reason {
	case "fix_available":
		return "eligible"
	case "base_layer":
		return "baseLayer"
	case "no_fixed_version":
		return "noFixedVersion"
	case "below_priority_threshold":
		return "belowPriorityThreshold"
	default:
		return "otherDeferred"
	}
}

func archForSystem(system string) string {
	if strings.Contains(system, "aarch64") || strings.Contains(system, "arm64") {
		return "arm64"
	}
	return "amd64"
}

func guessArchFromAsset(filename string, spdx *spdxDoc) string {
	if strings.Contains(filename, "arm64") || strings.Contains(filename, "aarch64") {
		return "arm64"
	}
	if strings.Contains(filename, "amd64") || strings.Contains(filename, "x86_64") {
		return "amd64"
	}
	if spdx != nil {
		ns := spdx.DocumentNamespace
		if strings.Contains(ns, "aarch64") || strings.Contains(ns, "arm64") {
			return "arm64"
		}
	}
	return "amd64"
}

func defaultArchPayload(arch, when string) gatherArchPayload {
	return gatherArchPayload{
		Arch:        arch,
		OS:          "linux",
		Layers:      []json.RawMessage{},
		Labels:      json.RawMessage(`{}`),
		SBOM:        gatherSBOMInfo{Tool: "unknown", CreatedAt: when, Packages: []spdxPackageOut{}},
		TestResults: nil,
	}
}

func releaseEvidenceFromGather(rel *gatherReleaseEntry) catalog.EvidenceSummary {
	archCount := len(rel.Architectures)
	var sbomArch, testArch, passedTestArch, vulnArch int
	for _, arch := range rel.Architectures {
		if arch.SBOM.PackageCount > 0 {
			sbomArch++
		}
		if arch.TestResults != nil {
			testArch++
			if catalog.TestResultStatusSatisfiesPolicy(arch.TestResults.Status, rel.Lifecycle.ProductionAllowed, rel.RuntimeContract.ProductionTier) {
				passedTestArch++
			}
		}
		if arch.Vulnerabilities != nil {
			vulnArch++
		}
	}
	evidence := catalog.EvidenceSummary{
		Signature:              rel.Signature != nil && rel.Signature.CosignBundlePresent,
		Provenance:             rel.Provenance != nil,
		SBOM:                   archCount > 0 && sbomArch == archCount,
		Tests:                  archCount > 0 && testArch == archCount && passedTestArch == archCount,
		Vulnerabilities:        archCount > 0 && vulnArch == archCount,
		ArchCount:              archCount,
		SBOMArchCount:          sbomArch,
		TestArchCount:          testArch,
		PassedTestArchCount:    passedTestArch,
		VulnerabilityArchCount: vulnArch,
	}
	evidence.Statuses = &catalog.EvidenceStatuses{
		Signature:       clearcuttVerifiedChannel(evidence.Signature, "sigstore"),
		Provenance:      clearcuttVerifiedChannel(evidence.Provenance, "slsa"),
		SBOM:            clearcuttVerifiedChannel(evidence.SBOM, "spdx-sbom"),
		Tests:           clearcuttVerifiedChannel(evidence.Tests, "test-results"),
		Vulnerabilities: observedChannel(evidence.Vulnerabilities, "vulnerability-scan"),
	}
	return evidence
}

func clearcuttVerifiedChannel(present bool, source string) catalog.EvidenceChannelStatus {
	if present {
		return catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusVerified, Source: source}
	}
	return catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "none"}
}

func observedChannel(present bool, source string) catalog.EvidenceChannelStatus {
	if present {
		return catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusObserved, Source: source}
	}
	return catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "none"}
}

func SummarizeImageForIndex(img ImageRecord) ImageSummary {
	latestRel := img.Releases[0]
	arches := make([]string, 0, len(latestRel.Architectures))
	totalPackages := 0
	passed := len(latestRel.Architectures) > 0
	withVulns := []gatherArchPayload{}
	for _, arch := range latestRel.Architectures {
		arches = append(arches, arch.Arch)
		totalPackages += arch.SBOM.PackageCount
		if arch.TestResults == nil || !catalog.TestResultStatusSatisfiesPolicy(arch.TestResults.Status, latestRel.Lifecycle.ProductionAllowed, latestRel.RuntimeContract.ProductionTier) {
			passed = false
		}
		if arch.vulnInfo != nil {
			withVulns = append(withVulns, arch)
		}
	}
	avgPkgs := 0
	if len(latestRel.Architectures) > 0 {
		avgPkgs = int(math.Round(float64(totalPackages) / float64(len(latestRel.Architectures))))
	}

	var vulnSummary *gatherVulnSummary
	if len(withVulns) > 0 {
		distinct := map[string]catalog.FindingInfo{}
		var scannedAt *string
		for _, arch := range withVulns {
			for _, finding := range arch.vulnInfo.Findings {
				key := finding.ID + "::" + finding.PackageName + "::" + finding.PackageVersion
				if _, ok := distinct[key]; !ok {
					distinct[key] = finding
				}
			}
			if arch.vulnInfo.ScannedAt != "" && (scannedAt == nil || arch.vulnInfo.ScannedAt > *scannedAt) {
				s := arch.vulnInfo.ScannedAt
				scannedAt = &s
			}
		}
		remediation := catalog.RemediationCounts{}
		vulnSummary = &gatherVulnSummary{ScannedAt: scannedAt, Remediation: remediation}
		for _, finding := range distinct {
			severity := strings.ToLower(finding.Severity)
			switch severity {
			case "critical":
				vulnSummary.Critical++
			case "high":
				vulnSummary.High++
			case "medium":
				vulnSummary.Medium++
			case "low":
				vulnSummary.Low++
			}
			if severity == "critical" || severity == "high" {
				switch remediationBucket(remediationReason(finding)) {
				case "eligible":
					vulnSummary.Remediation.Eligible++
				case "baseLayer":
					vulnSummary.Remediation.BaseLayer++
				case "noFixedVersion":
					vulnSummary.Remediation.NoFixedVersion++
				case "belowPriorityThreshold":
					vulnSummary.Remediation.BelowPriorityThreshold++
				default:
					vulnSummary.Remediation.OtherDeferred++
				}
			}
		}
	}

	return ImageSummary{
		ID:                   img.ID,
		Kind:                 img.Kind,
		Language:             img.Language.ID,
		LanguageDisplay:      img.Language.DisplayName,
		LanguageVersion:      img.Language.Version,
		Tier:                 img.Tier.ID,
		LatestTag:            latestRel.Tag,
		LatestManifestDigest: latestRel.ManifestDigest,
		LatestPackageCount:   avgPkgs,
		Architectures:        arches,
		Signed:               latestRel.Signature != nil && latestRel.Signature.CosignBundlePresent,
		Provenance:           latestRel.Provenance != nil,
		Evidence:             latestRel.Evidence,
		Passed:               passed,
		VulnSummary:          vulnSummary,
		Lifecycle:            img.Lifecycle,
		RuntimeContract:      img.RuntimeContract,
		Service:              img.Service,
	}
}

func attachReleaseAssetLinks(attestations []EnrichmentAttestation, provenanceURL *string) []gatherAttestation {
	out := make([]gatherAttestation, 0, len(attestations))
	for _, attestation := range attestations {
		releaseAttestation := gatherAttestation{
			Kind:                 attestation.Kind,
			PredicateType:        attestation.PredicateType,
			SubjectName:          attestation.SubjectName,
			SubjectDigest:        attestation.SubjectDigest,
			SignerIdentity:       attestation.SignerIdentity,
			Issuer:               attestation.Issuer,
			RunURL:               attestation.RunURL,
			WorkflowURL:          attestation.WorkflowURL,
			GithubAPIURL:         attestation.GithubAPIURL,
			TransparencyLogIndex: attestation.TransparencyLogIndex,
			TransparencyURL:      attestation.TransparencyURL,
			Sources:              attestation.Sources,
		}
		if releaseAttestation.Kind == "slsa-provenance" && StringSliceContains(releaseAttestation.Sources, "oci") {
			releaseAttestation.ReleaseAssetURL = provenanceURL
		}
		out = append(out, releaseAttestation)
	}
	return out
}

func StringSliceContains(values []string, needle string) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

type Enrichment struct {
	ManifestDigest *string                 `json:"manifestDigest"`
	Architectures  []EnrichmentArch        `json:"architectures"`
	Signature      *Signature              `json:"signature"`
	Provenance     *Provenance             `json:"provenance"`
	TestResults    *TestResults            `json:"testResults"`
	Attestations   []EnrichmentAttestation `json:"attestations"`
}

type EnrichmentArch struct {
	Arch                   string            `json:"arch"`
	Digest                 *string           `json:"digest"`
	Size                   *int64            `json:"size"`
	ManifestDescriptorSize *int64            `json:"manifestDescriptorSize,omitempty"`
	Layers                 []json.RawMessage `json:"layers"`
	Labels                 json.RawMessage   `json:"labels"`
}

func loadEnrichment(tag, target, enrichmentDir string) *Enrichment {
	if enrichmentDir == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(enrichmentDir, tag, target+".json"))
	if err != nil {
		return nil
	}
	var out Enrichment
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return &out
}

func loadVulnerabilities(tag, target, arch, vulnDir string) (*json.RawMessage, *catalog.VulnerabilitiesInfo) {
	if vulnDir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(vulnDir, tag, target+"-"+arch+".json"))
	if err != nil {
		return nil, nil
	}
	raw := json.RawMessage(data)
	var info catalog.VulnerabilitiesInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return &raw, nil
	}
	return &raw, &info
}

func BuildImageRecord(target string, releases []Release, refreshSet map[string]bool, opts BuildOptions) (*ImageRecord, error) {
	desc := runtimeRecordTarget(target)
	if desc == nil {
		return nil, nil
	}
	return buildImageRecord(desc, releases, refreshSet, opts)
}

func BuildServiceImageRecord(target string, service catalog.ServiceInfo, lifecycle Lifecycle, runtimeContract RuntimeContract, releases []Release, refreshSet map[string]bool, opts BuildOptions) (*ImageRecord, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, nil
	}
	return buildImageRecord(&recordTarget{
		ID:              target,
		Kind:            "service",
		SchemaVersion:   catalog.ImageRecordSchemaVersionV2,
		Language:        Language{ID: "service", DisplayName: "Service", Version: service.Version},
		Tier:            serviceTier,
		ImageNameKey:    target,
		Lifecycle:       lifecycle,
		RuntimeContract: runtimeContract,
		Service:         &service,
	}, releases, refreshSet, opts)
}

func buildImageRecord(desc *recordTarget, releases []Release, refreshSet map[string]bool, opts BuildOptions) (*ImageRecord, error) {
	target := desc.ID
	imagePrefix := opts.ImagePrefix
	if imagePrefix == "" {
		imagePrefix = "clearcutt"
	}
	imageNameKey := FirstNonEmptyStr(desc.ImageNameKey, target)
	imageName := imagePrefix + "-" + strings.ToLower(imageNameKey)
	fullName := strings.TrimRight(opts.RegistryBase, "/") + "/" + imageName
	releaseEntries := []gatherReleaseEntry{}
	isLatestSet := false

	for _, rel := range releases {
		mustRefresh := refreshSet[rel.Tag]
		sbomAssets := catalogArchAssets(rel.Assets, target, ".sbom.json")
		if len(sbomAssets) == 0 {
			sbomAssets = catalogAssetsNamed(rel.Assets, target+".sbom.json")
		}
		if len(sbomAssets) == 0 {
			continue
		}
		provAsset := catalogAssetNamed(rel.Assets, target+".intoto.jsonl")
		digestAsset := catalogAssetNamed(rel.Assets, target+".digest.json")
		testAssets := catalogArchAssets(rel.Assets, target, ".test-results.json")
		if len(testAssets) == 0 {
			testAssets = catalogAssetsNamed(rel.Assets, target+".test-results.json")
		}

		archMap := map[string]*gatherArchPayload{}
		for _, asset := range sbomAssets {
			arch := guessArchFromAsset(asset.Name, nil)
			cachePath := filepath.Join(opts.SBOMCacheDir, rel.Tag, target+"-"+arch+".sbom.json")
			buf, ok := readCachedSBOM(cachePath, mustRefresh)
			if !ok {
				if opts.Source == nil {
					continue
				}
				var err error
				buf, err = opts.Source.DownloadAsset(asset)
				if err != nil {
					continue
				}
			}
			var spdx spdxDoc
			if err := json.Unmarshal(buf, &spdx); err != nil {
				continue
			}
			if mustRefresh || !FileExists(cachePath) {
				_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)
				_ = os.WriteFile(cachePath, buf, 0o644)
			}
			compact := compactPackages(spdx)
			archEntry := defaultArchPayload(arch, rel.PublishedAt)
			archEntry.SBOM = gatherSBOMInfo{
				Tool:         spdxTool(spdx),
				CreatedAt:    FirstNonEmptyStr(spdx.CreationInfo.Created, rel.PublishedAt),
				RootDigest:   rootDigest(spdx),
				PackageCount: len(compact),
				Packages:     compact,
			}
			archMap[arch] = &archEntry
		}

		perArchTest := map[string]TestResults{}
		var legacyTest *TestResults
		for _, asset := range testAssets {
			if opts.Source == nil {
				continue
			}
			buf, err := opts.Source.DownloadAsset(asset)
			if err != nil {
				continue
			}
			var parsed TestResults
			if err := json.Unmarshal(buf, &parsed); err != nil {
				continue
			}
			arch := guessArchFromAsset(asset.Name, nil)
			if strings.HasPrefix(asset.Name, target+"-") {
				perArchTest[arch] = parsed
			} else {
				legacyTest = &parsed
			}
		}
		for arch, entry := range archMap {
			tr, ok := perArchTest[arch]
			if !ok && legacyTest != nil {
				tr = *legacyTest
				ok = true
			}
			if !ok {
				continue
			}
			tr.Assertions = normalizeAssertions(tr.Assertions)
			entry.TestResults = &tr
		}

		var provenance *Provenance
		if provAsset != nil {
			if opts.Source == nil {
				return nil, fmt.Errorf("download %s: release source is nil", provAsset.Name)
			}
			buf, err := opts.Source.DownloadAsset(*provAsset)
			if err != nil {
				return nil, err
			}
			p := summarizeProvenance(string(buf))
			provenance = &p
		}

		var manifestDigest *string
		if digestAsset != nil {
			if opts.Source == nil {
				return nil, fmt.Errorf("download %s: release source is nil", digestAsset.Name)
			}
			buf, err := opts.Source.DownloadAsset(*digestAsset)
			if err != nil {
				return nil, err
			}
			var parsed struct {
				Digest string `json:"digest"`
			}
			if err := json.Unmarshal(buf, &parsed); err == nil && parsed.Digest != "" {
				manifestDigest = &parsed.Digest
			}
		}

		enrich := loadEnrichment(rel.Tag, target, opts.EnrichmentDir)
		var signature *Signature
		attestations := []gatherAttestation{}
		if enrich != nil {
			if enrich.ManifestDigest != nil {
				manifestDigest = enrich.ManifestDigest
			}
			for _, archEnr := range enrich.Architectures {
				arch := archEnr.Arch
				if arch == "" {
					continue
				}
				entry, ok := archMap[arch]
				if !ok {
					payload := defaultArchPayload(arch, rel.PublishedAt)
					archMap[arch] = &payload
					entry = &payload
				}
				if archEnr.Digest != nil {
					entry.ImageDigest = archEnr.Digest
				}
				if archEnr.Size != nil {
					entry.ImageSize = archEnr.Size
				}
				if archEnr.ManifestDescriptorSize != nil {
					entry.ManifestDescriptorSize = archEnr.ManifestDescriptorSize
				}
				if archEnr.Layers != nil {
					layerCount := len(archEnr.Layers)
					entry.LayerCount = &layerCount
					entry.Layers = archEnr.Layers
				}
				if archEnr.Labels != nil {
					entry.Labels = archEnr.Labels
				}
			}
			if (provenance == nil || !isUsefulProvenanceSummary(*provenance)) && enrich.Provenance != nil {
				p := *enrich.Provenance
				provenance = &p
			}
			if enrich.TestResults != nil {
				for _, entry := range archMap {
					if entry.TestResults != nil {
						continue
					}
					tr := *enrich.TestResults
					tr.Status = FirstNonEmptyStr(tr.Status, "unknown")
					tr.Assertions = normalizeAssertions(tr.Assertions)
					entry.TestResults = &tr
				}
			}
			signature = enrich.Signature
			attestations = attachReleaseAssetLinks(enrich.Attestations, assetURL(provAsset))
		}

		lastRebuiltAt := rel.PublishedAt
		for arch, entry := range archMap {
			raw, info := loadVulnerabilities(rel.Tag, target, arch, opts.VulnDir)
			if raw != nil {
				entry.Vulnerabilities = raw
				entry.vulnInfo = info
				if info != nil && info.ScannedAt != "" && info.ScannedAt > lastRebuiltAt {
					lastRebuiltAt = info.ScannedAt
				}
			}
		}

		architectures := make([]gatherArchPayload, 0, len(archMap))
		for _, entry := range archMap {
			architectures = append(architectures, *entry)
		}
		sort.Slice(architectures, func(i, j int) bool { return architectures[i].Arch < architectures[j].Arch })
		if len(architectures) == 0 {
			continue
		}

		isLatest := !isLatestSet && !rel.Prerelease
		if isLatest {
			isLatestSet = true
		}
		releaseEntry := gatherReleaseEntry{
			Tag:             rel.Tag,
			PublishedAt:     rel.PublishedAt,
			LastRebuiltAt:   lastRebuiltAt,
			IsLatest:        isLatest,
			ManifestDigest:  manifestDigest,
			TotalSize:       totalImageSize(architectures),
			Architectures:   architectures,
			Signature:       signature,
			Provenance:      provenance,
			Attestations:    attestations,
			AssetURLs:       assetURLsFromAssets(sbomAssets, testAssets, provAsset, digestAsset),
			Lifecycle:       desc.Lifecycle,
			RuntimeContract: desc.RuntimeContract,
			Exceptions:      defaultGatherExceptions(),
		}
		releaseEntry.Evidence = releaseEvidenceFromGather(&releaseEntry)
		releaseEntries = append(releaseEntries, releaseEntry)
	}

	if len(releaseEntries) == 0 {
		return nil, nil
	}
	return &ImageRecord{
		SchemaVersion:   desc.SchemaVersion,
		ID:              target,
		Kind:            desc.Kind,
		Language:        desc.Language,
		Tier:            desc.Tier,
		Registry:        opts.RegistryBase,
		ImageName:       imageName,
		FullName:        fullName,
		Releases:        releaseEntries,
		Lifecycle:       desc.Lifecycle,
		RuntimeContract: desc.RuntimeContract,
		Service:         desc.Service,
	}, nil
}
