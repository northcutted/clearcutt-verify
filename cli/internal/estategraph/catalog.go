package estategraph

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func ApplyObservationEvidenceToCatalog(catalogPath string, observations Observations) (int, error) {
	byID := map[string]Observation{}
	for _, obs := range observations.Images {
		normalizeObservation(&obs)
		if obs.ID != "" {
			byID[obs.ID] = obs
		}
	}
	index, err := catalog.LoadCatalogIndex(catalogPath)
	if err != nil {
		return 0, err
	}
	updated := 0
	for i := range index.Images {
		obs, ok := byID[index.Images[i].ID]
		if !ok {
			continue
		}
		if applyObservationEvidence(index.Images[i].Evidence, obs) {
			updated++
		}
		if index.Images[i].Evidence != nil {
			index.Images[i].Signed = index.Images[i].Evidence.Signature
			index.Images[i].Provenance = index.Images[i].Evidence.Provenance
			index.Images[i].Passed = index.Images[i].Evidence.Tests
		}
		record, err := catalog.LoadImageRecord(catalogPath, index.Images[i].ID)
		if err != nil {
			return updated, err
		}
		recordUpdated := false
		for r := range record.Releases {
			if applyObservationEvidence(record.Releases[r].Evidence, obs) {
				recordUpdated = true
			}
		}
		if recordUpdated {
			if err := writeJSON(filepath.Join(catalogPath, "images", record.ID+".json"), record); err != nil {
				return updated, err
			}
		}
	}
	if index.Summary != nil {
		index.Summary.SignedCount = 0
		index.Summary.ProvenanceCount = 0
		index.Summary.SBOMCount = 0
		index.Summary.ScanCount = 0
		index.Summary.PassingCount = 0
		for _, image := range index.Images {
			if image.Signed {
				index.Summary.SignedCount++
			}
			if image.Provenance {
				index.Summary.ProvenanceCount++
			}
			if image.Passed {
				index.Summary.PassingCount++
			}
			if image.Evidence != nil {
				if image.Evidence.SBOM {
					index.Summary.SBOMCount++
				}
				if image.Evidence.Vulnerabilities {
					index.Summary.ScanCount++
				}
			}
		}
	}
	if err := writeJSON(filepath.Join(catalogPath, "index.json"), index); err != nil {
		return updated, err
	}
	return updated, nil
}

func applyObservationEvidence(evidence *catalog.EvidenceSummary, obs Observation) bool {
	if evidence == nil {
		return false
	}
	evidence.Statuses = &catalog.EvidenceStatuses{
		Signature:       catalogChannel(obs.Evidence.Signature),
		Provenance:      catalogChannel(obs.Evidence.Provenance),
		SBOM:            catalogChannel(obs.Evidence.SBOM),
		Tests:           catalogChannel(obs.Evidence.Tests),
		Vulnerabilities: catalogChannel(obs.Evidence.VulnerabilityScan),
	}
	catalog.NormalizeEvidenceSummary(evidence)
	if evidence.SBOM {
		evidence.SBOMArchCount = maxPositive(evidence.SBOMArchCount, evidence.ArchCount)
	}
	if evidence.Tests {
		evidence.TestArchCount = maxPositive(evidence.TestArchCount, evidence.ArchCount)
		evidence.PassedTestArchCount = maxPositive(evidence.PassedTestArchCount, evidence.ArchCount)
	}
	if evidence.Vulnerabilities {
		evidence.VulnerabilityArchCount = maxPositive(evidence.VulnerabilityArchCount, evidence.ArchCount)
	}
	return true
}

func catalogChannel(channel EvidenceChannel) catalog.EvidenceChannelStatus {
	status := strings.ToLower(strings.TrimSpace(channel.Status))
	if status == "" {
		status = catalog.EvidenceStatusMissing
	}
	return catalog.EvidenceChannelStatus{
		Status: status,
		Source: strings.TrimSpace(channel.Source),
		Claim:  strings.TrimSpace(channel.Claim),
	}
}

func maxPositive(current, fallback int) int {
	values := []int{current, fallback}
	sort.Ints(values)
	if values[len(values)-1] > 0 {
		return values[len(values)-1]
	}
	return current
}
