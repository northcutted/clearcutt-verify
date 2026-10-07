package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

const evidenceManifestFilename = "evidence-manifest.json"

type evidenceManifest struct {
	SchemaVersion string                    `json:"schemaVersion"`
	GeneratedAt   string                    `json:"generatedAt"`
	Source        catalog.CatalogSource     `json:"source"`
	Summary       evidenceManifestSummary   `json:"summary"`
	Releases      []evidenceManifestRelease `json:"releases"`
}

type evidenceManifestSummary struct {
	ImageReleases   int `json:"imageReleases"`
	Complete        int `json:"complete"`
	MissingEvidence int `json:"missingEvidence"`
}

type evidenceManifestRelease struct {
	ImageID            string                         `json:"imageId"`
	Kind               string                         `json:"kind"`
	Tag                string                         `json:"tag"`
	PublishedAt        string                         `json:"publishedAt"`
	IsLatest           bool                           `json:"isLatest"`
	FullName           string                         `json:"fullName"`
	ImageRef           string                         `json:"imageRef"`
	ImmutableRef       *string                        `json:"immutableRef,omitempty"`
	ManifestDigest     *string                        `json:"manifestDigest,omitempty"`
	Channels           evidenceManifestChannels       `json:"channels"`
	Missing            []string                       `json:"missing,omitempty"`
	Architectures      []evidenceManifestArchitecture `json:"architectures"`
	Imported           bool                           `json:"imported,omitempty"`
	CreatedByClearCutt *bool                          `json:"createdByClearCutt,omitempty"`
	ProvenanceClaim    string                         `json:"provenanceClaim,omitempty"`
	Signature          *evidenceManifestSignature     `json:"signature,omitempty"`
	Provenance         *evidenceManifestProvenance    `json:"provenance,omitempty"`
	Assets             catalog.AssetURLs              `json:"assets"`
	CatalogRecord      string                         `json:"catalogRecord"`
}

type evidenceManifestChannels struct {
	Signature       evidenceManifestChannel `json:"signature"`
	Provenance      evidenceManifestChannel `json:"provenance"`
	SBOM            evidenceManifestChannel `json:"sbom"`
	Tests           evidenceManifestChannel `json:"tests"`
	Vulnerabilities evidenceManifestChannel `json:"vulnerabilities"`
	Exceptions      evidenceManifestChannel `json:"exceptions"`
	VEX             evidenceManifestChannel `json:"vex"`
}

type evidenceManifestChannel struct {
	Expected bool   `json:"expected"`
	Observed bool   `json:"observed"`
	Status   string `json:"status"`
	Source   string `json:"source,omitempty"`
	Claim    string `json:"claim,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type evidenceManifestArchitecture struct {
	Arch            string  `json:"arch"`
	OS              string  `json:"os"`
	ImageDigest     *string `json:"imageDigest,omitempty"`
	SBOM            bool    `json:"sbom"`
	Tests           bool    `json:"tests"`
	Vulnerabilities bool    `json:"vulnerabilities"`
}

type evidenceManifestSignature struct {
	Subject       *string `json:"subject,omitempty"`
	Issuer        *string `json:"issuer,omitempty"`
	RekorLogIndex *int64  `json:"rekorLogIndex,omitempty"`
}

type evidenceManifestProvenance struct {
	PredicateType  string  `json:"predicateType"`
	BuilderID      string  `json:"builderId"`
	SlsaLevel      int     `json:"slsaLevel"`
	SourceURI      *string `json:"sourceUri,omitempty"`
	SourceRevision *string `json:"sourceRevision,omitempty"`
}

func writeEvidenceManifestFile(catalogPath string) error {
	manifest, err := buildEvidenceManifest(catalogPath)
	if err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(catalogPath, evidenceManifestFilename), manifest)
}

func loadEvidenceManifest(catalogPath string) (*evidenceManifest, error) {
	raw, err := os.ReadFile(filepath.Join(catalogPath, evidenceManifestFilename))
	if err != nil {
		return nil, err
	}
	var manifest evidenceManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func buildEvidenceManifest(catalogPath string) (evidenceManifest, error) {
	index, err := catalog.LoadCatalogIndex(catalogPath)
	if err != nil {
		return evidenceManifest{}, err
	}
	manifest := evidenceManifest{
		SchemaVersion: catalog.EvidenceManifestSchemaVersion,
		GeneratedAt:   index.GeneratedAt,
		Source: catalog.CatalogSource{
			Owner:        index.Owner,
			Repo:         index.Repo,
			RepoURL:      index.RepoURL,
			RegistryBase: index.RegistryBase,
		},
	}
	if index.Source != nil {
		manifest.Source = *index.Source
	}

	for _, summary := range index.Images {
		record, err := catalog.LoadImageRecord(catalogPath, summary.ID)
		if err != nil {
			return evidenceManifest{}, err
		}
		for _, release := range record.Releases {
			row := evidenceManifestReleaseForRecord(record, release)
			manifest.Summary.ImageReleases++
			if len(row.Missing) == 0 {
				manifest.Summary.Complete++
			} else {
				manifest.Summary.MissingEvidence++
			}
			manifest.Releases = append(manifest.Releases, row)
		}
	}
	sort.SliceStable(manifest.Releases, func(i, j int) bool {
		if manifest.Releases[i].Tag != manifest.Releases[j].Tag {
			return manifest.Releases[i].Tag > manifest.Releases[j].Tag
		}
		return manifest.Releases[i].ImageID < manifest.Releases[j].ImageID
	})
	return manifest, nil
}

func evidenceManifestReleaseForRecord(record *catalog.ImageRecord, release catalog.ReleaseEntry) evidenceManifestRelease {
	evidence := releaseEvidenceSummary(&release)
	archCount := len(release.Architectures)
	row := evidenceManifestRelease{
		ImageID:        record.ID,
		Kind:           firstNonEmpty(record.Kind, "runtime"),
		Tag:            release.Tag,
		PublishedAt:    release.PublishedAt,
		IsLatest:       release.IsLatest,
		FullName:       record.FullName,
		ImageRef:       releaseImageRef(record, release),
		ManifestDigest: release.ManifestDigest,
		Assets:         release.AssetURLs,
		CatalogRecord:  filepath.ToSlash(filepath.Join("images", record.ID+".json")),
	}
	if release.ManifestDigest != nil && *release.ManifestDigest != "" {
		immutable := record.FullName + "@" + *release.ManifestDigest
		row.ImmutableRef = &immutable
	}
	if record.Origin != nil && record.Origin.Kind == "imported" {
		row.Imported = true
		row.CreatedByClearCutt = &record.Origin.CreatedByClearCutt
		row.ProvenanceClaim = firstNonEmpty(record.Origin.ProvenanceClaim, "none")
	}
	catalog.NormalizeEvidenceSummary(&evidence)
	row.Channels = evidenceManifestChannels{
		Signature:       channelStatus(archCount > 0, evidence.Statuses.Signature, "catalog release record reports Sigstore signature evidence"),
		Provenance:      channelStatus(archCount > 0, evidence.Statuses.Provenance, "catalog release record reports SLSA provenance evidence"),
		SBOM:            countedChannelStatus(archCount > 0, evidence.Statuses.SBOM, evidence.SBOMArchCount, archCount, "architecture SBOMs"),
		Tests:           countedChannelStatus(archCount > 0, evidence.Statuses.Tests, evidence.PassedTestArchCount, archCount, "passing test results"),
		Vulnerabilities: countedChannelStatus(archCount > 0, evidence.Statuses.Vulnerabilities, evidence.VulnerabilityArchCount, archCount, "vulnerability scans"),
		Exceptions:      exceptionsChannelStatus(release.Exceptions),
		VEX:             vexChannelStatus(record.ID, release.Tag, release.Exceptions),
	}
	row.Missing = missingEvidenceChannels(row.Channels)
	// evidence-manifest.v2.schema.json types architectures as an array, so
	// releases without architectures must serialize as [] rather than null.
	row.Architectures = []evidenceManifestArchitecture{}
	for _, arch := range release.Architectures {
		testPassed := arch.TestResults != nil && catalog.TestResultStatusSatisfiesPolicy(arch.TestResults.Status, release.Lifecycle.ProductionAllowed, release.RuntimeContract.ProductionTier)
		row.Architectures = append(row.Architectures, evidenceManifestArchitecture{
			Arch:            arch.Arch,
			OS:              arch.OS,
			ImageDigest:     arch.ImageDigest,
			SBOM:            arch.SBOM.PackageCount > 0,
			Tests:           testPassed,
			Vulnerabilities: arch.Vulnerabilities != nil,
		})
	}
	if release.Signature != nil {
		row.Signature = &evidenceManifestSignature{RekorLogIndex: release.Signature.RekorLogIndex}
		if release.Signature.Certificate != nil {
			row.Signature.Subject = release.Signature.Certificate.Subject
			row.Signature.Issuer = release.Signature.Certificate.Issuer
		}
	}
	if release.Provenance != nil {
		row.Provenance = &evidenceManifestProvenance{
			PredicateType:  release.Provenance.PredicateType,
			BuilderID:      release.Provenance.Builder.ID,
			SlsaLevel:      release.Provenance.SlsaLevel,
			SourceURI:      release.Provenance.SourceURI,
			SourceRevision: release.Provenance.SourceRevision,
		}
	}
	return row
}

func releaseImageRef(record *catalog.ImageRecord, release catalog.ReleaseEntry) string {
	tag := release.Tag
	if record.Tier.ID != "" && record.Tier.ID != "service" {
		tag = tag + "-" + record.Tier.ID
	}
	return record.FullName + ":" + tag
}

func channelStatus(expected bool, status catalog.EvidenceChannelStatus, detail string) evidenceManifestChannel {
	normalized := strings.TrimSpace(status.Status)
	if normalized == "" {
		normalized = catalog.EvidenceStatusMissing
	}
	observed := catalog.EvidenceChannelPresent(catalog.EvidenceChannelStatus{Status: normalized})
	switch {
	case !expected:
		normalized = "not_applicable"
		observed = false
	}
	return evidenceManifestChannel{Expected: expected, Observed: observed, Status: normalized, Source: status.Source, Claim: status.Claim, Detail: detail}
}

func countedChannelStatus(expected bool, status catalog.EvidenceChannelStatus, count, total int, label string) evidenceManifestChannel {
	ch := channelStatus(expected, status, fmt.Sprintf("%d/%d %s", count, total, label))
	if expected && count > 0 && count < total && ch.Status == catalog.EvidenceStatusMissing {
		ch.Status = catalog.EvidenceStatusObserved
		ch.Observed = true
	}
	return ch
}

func exceptionsChannelStatus(summary catalog.ExceptionSummary) evidenceManifestChannel {
	if summary.Total == 0 {
		return evidenceManifestChannel{
			Expected: false,
			Observed: false,
			Status:   "not_applicable",
			Detail:   "no vulnerability exceptions recorded for this release",
		}
	}
	return evidenceManifestChannel{
		Expected: true,
		Observed: true,
		Status:   "present",
		Detail:   fmt.Sprintf("%d total exceptions, %d active, %d expired", summary.Total, summary.Active, summary.Expired),
	}
}

func vexChannelStatus(imageID, tag string, summary catalog.ExceptionSummary) evidenceManifestChannel {
	detail := fmt.Sprintf("generate on demand with clearcutt-verify vex %s --tag %s", imageID, tag)
	if summary.Total == 0 {
		return evidenceManifestChannel{Expected: false, Observed: false, Status: "not_applicable", Detail: detail}
	}
	return evidenceManifestChannel{Expected: false, Observed: false, Status: "on_demand", Detail: detail}
}

func missingEvidenceChannels(channels evidenceManifestChannels) []string {
	checks := []struct {
		name string
		ch   evidenceManifestChannel
	}{
		{"signature", channels.Signature},
		{"provenance", channels.Provenance},
		{"sbom", channels.SBOM},
		{"tests", channels.Tests},
		{"vulnerabilities", channels.Vulnerabilities},
		{"exceptions", channels.Exceptions},
	}
	var missing []string
	for _, check := range checks {
		if check.ch.Expected && !check.ch.Observed {
			missing = append(missing, check.name)
		}
	}
	return missing
}
