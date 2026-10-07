package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/spf13/cobra"
)

type verifyCatalogFlags struct {
	lenientEvidence bool
}

var verifyCatalogOpts verifyCatalogFlags

// validCatalogSupport enumerates the lifecycle support levels the catalog
// generator emits. Mirrors the support gate in the retired Node verifier.
var validCatalogSupport = map[string]bool{
	"lts":         true,
	"current":     true,
	"preview":     true,
	"legacy":      true,
	"unsupported": true,
}

// VerifyCatalogResponse is the structured payload for --format json|yaml,
// mirroring the check-list shape of VerifyResponse from `verify image`.
type VerifyCatalogResponse struct {
	Status        string              `json:"status"` // pass or fail
	LatestTag     string              `json:"latestTag"`
	ImagesChecked int                 `json:"imagesChecked"`
	Checks        []VerifyCheckResult `json:"checks"`
}

type rawCatalogIndex struct {
	Images []rawCatalogSummary `json:"images"`
}

type rawCatalogSummary struct {
	ID              string          `json:"id"`
	Lifecycle       json.RawMessage `json:"lifecycle"`
	RuntimeContract json.RawMessage `json:"runtimeContract"`
}

type rawImageRecord struct {
	ID              string             `json:"id"`
	Lifecycle       json.RawMessage    `json:"lifecycle"`
	RuntimeContract json.RawMessage    `json:"runtimeContract"`
	Releases        []rawReleaseRecord `json:"releases"`
}

type rawReleaseRecord struct {
	Tag             string          `json:"tag"`
	Lifecycle       json.RawMessage `json:"lifecycle"`
	RuntimeContract json.RawMessage `json:"runtimeContract"`
	Exceptions      json.RawMessage `json:"exceptions"`
}

// NewVerifyCatalogCmd creates the `verify catalog` subcommand, which fails the
// catalog build when the latest release would publish incomplete or
// contradictory trust data. It replaces the retired Node verifier.
func NewVerifyCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Verify the latest catalog release publishes complete, internally consistent trust data",
		Long: `Cross-checks the generated catalog index against each latest image record: the
index summary's evidence flags must agree with the authoritative release
evidence, and SBOM and vulnerability-scan coverage must be complete for every
latest-tag image. Unless --lenient-evidence is set, signature, provenance, and
passing tests are also required. Reads the catalog directory selected by --catalog.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerifyCatalog()
		},
	}
	cmd.Flags().BoolVar(&verifyCatalogOpts.lenientEvidence, "lenient-evidence", false,
		"Only require SBOM/scan coverage and consistent evidence summaries; do not require signature, provenance, or passing tests")
	return cmd
}

func runVerifyCatalog() error {
	index, err := catalog.LoadCatalogIndex(GlobalOpts.CatalogPath)
	if err != nil {
		return err
	}
	rawIndex, err := loadRawCatalogIndex(GlobalOpts.CatalogPath)
	if err != nil {
		return err
	}
	rawSummaries := make(map[string]rawCatalogSummary, len(rawIndex.Images))
	for _, summary := range rawIndex.Images {
		rawSummaries[summary.ID] = summary
	}
	strict := !verifyCatalogOpts.lenientEvidence

	var failures []VerifyCheckResult
	failFor := func(id, msg string) {
		failures = append(failures, VerifyCheckResult{ID: id, Status: "fail", Message: msg})
	}
	checked := 0

	for i := range index.Images {
		summary := index.Images[i]
		if summary.LatestTag != index.LatestTag {
			continue
		}
		checked++

		rawRecord, err := loadRawImageRecord(GlobalOpts.CatalogPath, summary.ID)
		if err != nil {
			if os.IsNotExist(err) {
				failFor(summary.ID, "image record is missing")
			} else {
				failFor(summary.ID, err.Error())
			}
			continue
		}

		record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, summary.ID)
		if err != nil {
			failFor(summary.ID, err.Error())
			continue
		}

		var release *catalog.ReleaseEntry
		for j := range record.Releases {
			if record.Releases[j].Tag == index.LatestTag {
				release = &record.Releases[j]
				break
			}
		}
		if release == nil {
			failFor(summary.ID, fmt.Sprintf("latest release %s is missing from image record", index.LatestTag))
			continue
		}

		rawSummary, ok := rawSummaries[summary.ID]
		if !ok {
			rawSummary = rawCatalogSummary{ID: summary.ID}
		}
		validateRawCatalogSummary(summary.ID, rawSummary, failFor)
		validateRawImageRecord(rawRecord, failFor)

		// Lifecycle enum gates on the index summary. JSON decoding catches
		// non-string status/support values; the raw preflight above catches
		// missing/null lifecycle and runtime contract objects plus boolean/number
		// fields that would otherwise collapse to Go zero values.
		if !catalog.ValidLifecycleStatus(summary.Lifecycle.Status) {
			failFor(summary.ID, "invalid lifecycle status: "+summary.Lifecycle.Status)
		}
		if !validCatalogSupport[summary.Lifecycle.Support] {
			failFor(summary.ID, "invalid lifecycle support: "+summary.Lifecycle.Support)
		}

		evidence := releaseEvidenceSummary(release)

		if summary.Signed != evidence.Signature {
			failFor(summary.ID, fmt.Sprintf("index signed=%t but signature evidence=%t", summary.Signed, evidence.Signature))
		}
		if summary.Provenance != evidence.Provenance {
			failFor(summary.ID, fmt.Sprintf("index provenance=%t but provenance evidence=%t", summary.Provenance, evidence.Provenance))
		}
		// When the index summary carries its own evidence object, every boolean it
		// asserts must match the authoritative release evidence. The generator
		// always emits a complete object, so all five flags are compared.
		if summary.Evidence != nil {
			for _, pair := range []struct {
				key      string
				summaryV bool
				relV     bool
			}{
				{"signature", summary.Evidence.Signature, evidence.Signature},
				{"provenance", summary.Evidence.Provenance, evidence.Provenance},
				{"sbom", summary.Evidence.SBOM, evidence.SBOM},
				{"tests", summary.Evidence.Tests, evidence.Tests},
				{"vulnerabilities", summary.Evidence.Vulnerabilities, evidence.Vulnerabilities},
			} {
				if pair.summaryV != pair.relV {
					failFor(summary.ID, fmt.Sprintf("index evidence.%s=%t but image evidence.%s=%t", pair.key, pair.summaryV, pair.key, pair.relV))
				}
			}
		}

		if summary.Kind == "service" && len(release.Architectures) == 0 {
			continue
		}

		if !evidence.SBOM {
			failFor(summary.ID, fmt.Sprintf("SBOM coverage incomplete (%d/%d archs)", evidence.SBOMArchCount, evidence.ArchCount))
		}
		if !evidence.Vulnerabilities {
			failFor(summary.ID, fmt.Sprintf("vulnerability scan coverage incomplete (%d/%d archs)", evidence.VulnerabilityArchCount, evidence.ArchCount))
		}
		if strict {
			if !evidence.Signature {
				failFor(summary.ID, "Sigstore signature is missing")
			}
			if !evidence.Provenance {
				failFor(summary.ID, "SLSA provenance is missing")
			}
			if !evidence.Tests {
				failFor(summary.ID, fmt.Sprintf("test evidence incomplete (%d/%d archs passed)", evidence.PassedTestArchCount, evidence.ArchCount))
			}
		}
	}

	if checked == 0 {
		failFor("catalog.index", fmt.Sprintf("no images are published for latest tag %s", index.LatestTag))
	}

	scope := "complete signature, provenance, SBOM, test, and scan evidence"
	if !strict {
		scope = "complete SBOM/scan coverage and internally consistent evidence summaries"
	}

	if structuredFormat() {
		response := VerifyCatalogResponse{
			Status:        "pass",
			LatestTag:     index.LatestTag,
			ImagesChecked: checked,
			Checks:        failures,
		}
		if len(failures) == 0 {
			response.Checks = []VerifyCheckResult{{
				ID:      "catalog.evidence",
				Status:  "pass",
				Message: fmt.Sprintf("%d latest images have %s", checked, scope),
			}}
		} else {
			response.Status = "fail"
		}
		if err := printStructured(response); err != nil {
			return err
		}
		if len(failures) > 0 {
			return ErrCheckFailed
		}
		return nil
	}

	if len(failures) > 0 {
		fmt.Fprintf(errOut, "[catalog-verify] %d catalog data issue(s):\n", len(failures))
		for _, failure := range failures {
			fmt.Fprintf(errOut, "- %s: %s\n", failure.ID, failure.Message)
		}
		return ErrCheckFailed
	}

	fmt.Fprintf(out, "[catalog-verify] ok: %d latest images have %s.\n", checked, scope)
	return nil
}

// releaseEvidenceSummary returns the release's own evidence summary when present,
// otherwise recomputes it from the per-architecture payloads, mirroring the
// releaseEvidence() fallback in the retired Node verifier.
func releaseEvidenceSummary(rel *catalog.ReleaseEntry) catalog.EvidenceSummary {
	if rel.Evidence != nil {
		evidence := *rel.Evidence
		catalog.NormalizeEvidenceSummary(&evidence)
		return evidence
	}
	archCount := len(rel.Architectures)
	var sbomArch, testArch, passedTestArch, vulnArch int
	for k := range rel.Architectures {
		arch := rel.Architectures[k]
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
		Signature:       boolEvidenceChannel(evidence.Signature, catalog.EvidenceStatusVerified, "sigstore"),
		Provenance:      boolEvidenceChannel(evidence.Provenance, catalog.EvidenceStatusVerified, "slsa"),
		SBOM:            boolEvidenceChannel(evidence.SBOM, catalog.EvidenceStatusVerified, "spdx-sbom"),
		Tests:           boolEvidenceChannel(evidence.Tests, catalog.EvidenceStatusVerified, "test-results"),
		Vulnerabilities: boolEvidenceChannel(evidence.Vulnerabilities, catalog.EvidenceStatusObserved, "vulnerability-scan"),
	}
	return evidence
}

func boolEvidenceChannel(present bool, presentStatus, source string) catalog.EvidenceChannelStatus {
	if present {
		return catalog.EvidenceChannelStatus{Status: presentStatus, Source: source}
	}
	return catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "none"}
}

func loadRawCatalogIndex(catalogPath string) (rawCatalogIndex, error) {
	indexPath := filepath.Join(catalogPath, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return rawCatalogIndex{}, err
	}
	var raw rawCatalogIndex
	if err := json.Unmarshal(data, &raw); err != nil {
		return rawCatalogIndex{}, fmt.Errorf("failed to unmarshal raw catalog index: %w", err)
	}
	return raw, nil
}

func loadRawImageRecord(catalogPath, imageID string) (rawImageRecord, error) {
	recordPath := filepath.Join(catalogPath, "images", imageID+".json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		return rawImageRecord{}, err
	}
	var raw rawImageRecord
	if err := json.Unmarshal(data, &raw); err != nil {
		return rawImageRecord{}, fmt.Errorf("failed to unmarshal raw image record for %s: %w", imageID, err)
	}
	return raw, nil
}

func validateRawCatalogSummary(id string, summary rawCatalogSummary, failFor func(string, string)) {
	lifecycle, ok := rawObject(summary.Lifecycle)
	if !ok {
		failFor(id, "index summary is missing lifecycle")
	} else if !rawBool(lifecycle["productionAllowed"]) {
		failFor(id, "lifecycle productionAllowed must be a boolean")
	}

	runtimeContract, ok := rawObject(summary.RuntimeContract)
	if !ok {
		failFor(id, "index summary is missing runtimeContract")
		return
	}
	if !rawBoolOrNull(runtimeContract["shellPresent"]) {
		failFor(id, "runtimeContract shellPresent must be a boolean or null")
	}
	if !rawBoolOrNull(runtimeContract["packageManagerPresent"]) {
		failFor(id, "runtimeContract packageManagerPresent must be a boolean or null")
	}
	if !rawBool(runtimeContract["productionTier"]) {
		failFor(id, "runtimeContract productionTier must be a boolean")
	}
}

func validateRawImageRecord(record rawImageRecord, failFor func(string, string)) {
	id := record.ID
	if !rawObjectPresent(record.Lifecycle) {
		failFor(id, "image record is missing lifecycle")
	}
	if !rawObjectPresent(record.RuntimeContract) {
		failFor(id, "image record is missing runtimeContract")
	}
	for _, rel := range record.Releases {
		if !rawObjectPresent(rel.Lifecycle) {
			failFor(id, fmt.Sprintf("release %s is missing lifecycle", rel.Tag))
		}
		if !rawObjectPresent(rel.RuntimeContract) {
			failFor(id, fmt.Sprintf("release %s is missing runtimeContract", rel.Tag))
		}
		validateRawExceptions(id, rel.Tag, rel.Exceptions, failFor)
	}
}

func validateRawExceptions(id, tag string, raw json.RawMessage, failFor func(string, string)) {
	exceptions, ok := rawObject(raw)
	if !ok {
		failFor(id, fmt.Sprintf("release %s is missing exceptions", tag))
		return
	}
	for _, field := range []string{"total", "expired", "active", "acceptedRisk", "noFixAvailable", "falsePositive", "inheritedFromBase"} {
		if !rawNumber(exceptions[field]) {
			failFor(id, fmt.Sprintf("release %s exceptions.%s must be a number", tag, field))
		}
	}
}

func rawObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if !rawObjectPresent(raw) {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

func rawObjectPresent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func rawBool(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return bytes.Equal(trimmed, []byte("true")) || bytes.Equal(trimmed, []byte("false"))
}

func rawBoolOrNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return rawBool(trimmed) || bytes.Equal(trimmed, []byte("null"))
}

func rawNumber(raw json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	_, ok := value.(json.Number)
	return ok
}
