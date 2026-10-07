package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type catalogValidateFlags struct {
	warningsAsErrors bool
	schemaVersion    string
}

var catalogValidateOpts catalogValidateFlags

type catalogValidationReport struct {
	CatalogPath  string   `json:"catalogPath"`
	ImageCount   int      `json:"imageCount"`
	ErrorCount   int      `json:"errorCount"`
	WarningCount int      `json:"warningCount"`
	Errors       []string `json:"errors"`
	Warnings     []string `json:"warnings"`
}

func newCatalogValidateCmd() *cobra.Command {
	catalogValidateOpts = catalogValidateFlags{}
	cmd := &cobra.Command{
		Use:   "validate [catalog-dir]",
		Short: "Validate a generated catalog directory",
		Long: `Validate index.json plus every images/*.json record for directory shape,
referential integrity, required release fields, required package/CVE fields, and
evidence-summary consistency. Missing optional evidence is reported as warnings
unless --strict or --warnings-as-errors is set.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := GlobalOpts.CatalogPath
			if len(args) == 1 {
				path = args[0]
			}
			return runCatalogValidate(path)
		},
	}
	cmd.Flags().BoolVar(&catalogValidateOpts.warningsAsErrors, "warnings-as-errors", false, "Fail validation when warnings are present")
	cmd.Flags().StringVar(&catalogValidateOpts.schemaVersion, "schema-version", "", "Require a specific catalog schema version")
	return cmd
}

func runCatalogValidate(catalogPath string) error {
	report := validateCatalogDirectory(catalogPath)
	failed := report.ErrorCount > 0 || ((catalogValidateOpts.warningsAsErrors || catalog.Strict) && report.WarningCount > 0)

	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		if err := output.PrintJSON(out, report); err != nil {
			return err
		}
	case "yaml", "yml":
		if err := output.PrintYAML(out, report); err != nil {
			return err
		}
	default:
		if report.ErrorCount == 0 && report.WarningCount == 0 {
			fmt.Fprintf(out, "[catalog-validate] ok: %d image record(s) validated in %s\n", report.ImageCount, catalogPath)
		} else {
			fmt.Fprintf(out, "[catalog-validate] %d error(s), %d warning(s) in %s\n", report.ErrorCount, report.WarningCount, catalogPath)
			for _, msg := range report.Errors {
				fmt.Fprintf(out, "- error: %s\n", msg)
			}
			for _, msg := range report.Warnings {
				fmt.Fprintf(out, "- warning: %s\n", msg)
			}
		}
	}

	if failed {
		return ErrCheckFailed
	}
	return nil
}

func validateCatalogDirectory(catalogPath string) catalogValidationReport {
	report := catalogValidationReport{CatalogPath: catalogPath}
	addError := func(format string, args ...any) {
		report.Errors = append(report.Errors, fmt.Sprintf(format, args...))
	}
	addWarning := func(format string, args ...any) {
		report.Warnings = append(report.Warnings, fmt.Sprintf(format, args...))
	}

	index, err := catalog.LoadCatalogIndex(catalogPath)
	if err != nil {
		addError("%s", err.Error())
		report.finish()
		return report
	}
	if err := catalog.ValidateCatalogIndex(index); err != nil {
		addError("index.json: %v", err)
	}

	schemaValidator, err := catalog.NewSchemaValidator()
	if err != nil {
		addError("embedded JSON schemas: %v", err)
	}

	validateIndexSchemaVersion(index, catalogValidateOpts.schemaVersion, addError)
	validateFileAgainstSchema(schemaValidator, catalogPath, "index.json", indexSchemaFile(index.SchemaVersion), addError)

	seen := map[string]bool{}
	for i, summary := range index.Images {
		if summary.ID == "" {
			addError("index images[%d]: missing id", i)
			continue
		}
		if seen[summary.ID] {
			addError("index images[%d] %q: duplicate image id", i, summary.ID)
			continue
		}
		seen[summary.ID] = true

		record, err := catalog.LoadImageRecord(catalogPath, summary.ID)
		if err != nil {
			addError("index image %q: %v", summary.ID, err)
			continue
		}
		report.ImageCount++
		validateImageSchemaVersion(record, catalogValidateOpts.schemaVersion, addError)
		validateFileAgainstSchema(schemaValidator, catalogPath, filepath.Join("images", summary.ID+".json"), imageRecordSchemaFile(record.SchemaVersion), addError)
		validateCatalogRecord(catalogPath, index, summary, record, addError, addWarning)
	}
	validateNoOrphanImageRecords(catalogPath, seen, addError)
	validateEvidenceManifest(catalogPath, catalogValidateOpts.schemaVersion, addError)
	validateEvidenceManifestSchema(schemaValidator, catalogPath, addError)

	report.finish()
	return report
}

func validateNoOrphanImageRecords(catalogPath string, indexed map[string]bool, addError func(string, ...any)) {
	imagesDir := filepath.Join(catalogPath, "images")
	entries, err := os.ReadDir(imagesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		addError("images/: %v", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !indexed[id] {
			addError("images/%s: image record is not referenced by index.json", entry.Name())
		}
	}
}

// indexSchemaFile resolves the embedded JSON Schema for a declared index
// schemaVersion. Indexes that omit schemaVersion are held to the v1 contract;
// unknown versions return "" so the structural unsupported-version error stays
// the single signal.
func indexSchemaFile(schemaVersion string) string {
	if schemaVersion == "" {
		schemaVersion = catalog.CatalogIndexSchemaVersion
	}
	if file, ok := catalog.SchemaFileForVersion(schemaVersion); ok {
		return file
	}
	return ""
}

// imageRecordSchemaFile mirrors indexSchemaFile for images/*.json records.
func imageRecordSchemaFile(schemaVersion string) string {
	if schemaVersion == "" {
		schemaVersion = catalog.ImageRecordSchemaVersion
	}
	switch schemaVersion {
	case catalog.ImageRecordSchemaVersion, catalog.ImageRecordSchemaVersionV2:
		file, _ := catalog.SchemaFileForVersion(schemaVersion)
		return file
	}
	return ""
}

// validateFileAgainstSchema validates a raw catalog file against an embedded
// JSON Schema and reports each violation with file and JSON-pointer detail.
func validateFileAgainstSchema(validator *catalog.SchemaValidator, catalogPath, relPath, schemaFile string, addError func(string, ...any)) {
	if validator == nil || schemaFile == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(catalogPath, relPath))
	if err != nil {
		addError("%s: %v", relPath, err)
		return
	}
	violations, err := validator.Validate(schemaFile, data)
	if err != nil {
		addError("%s: schema %s: %v", relPath, schemaFile, err)
		return
	}
	for _, violation := range violations {
		addError("%s: schema %s: at %s", relPath, schemaFile, violation)
	}
}

// validateEvidenceManifestSchema schema-validates evidence-manifest.json when
// present; absence is handled by validateEvidenceManifest.
func validateEvidenceManifestSchema(validator *catalog.SchemaValidator, catalogPath string, addError func(string, ...any)) {
	manifest, err := loadEvidenceManifest(catalogPath)
	if err != nil {
		return
	}
	schemaFile, _ := catalog.SchemaFileForVersion(manifest.SchemaVersion)
	validateFileAgainstSchema(validator, catalogPath, evidenceManifestFilename, schemaFile, addError)
}

func validateEvidenceManifest(catalogPath, requestedSchema string, addError func(string, ...any)) {
	manifest, err := loadEvidenceManifest(catalogPath)
	if err != nil {
		if os.IsNotExist(err) {
			if requestedSchema == catalog.EvidenceManifestSchemaVersion || requestedSchema == catalog.EvidenceManifestSchemaVersionV1 {
				addError("%s: missing required schemaVersion %q", evidenceManifestFilename, requestedSchema)
			}
			return
		}
		addError("%s: %v", evidenceManifestFilename, err)
		return
	}
	if manifest.SchemaVersion != catalog.EvidenceManifestSchemaVersion && manifest.SchemaVersion != catalog.EvidenceManifestSchemaVersionV1 {
		addError("%s: unsupported schemaVersion %q", evidenceManifestFilename, manifest.SchemaVersion)
	}
	if requestedSchema == catalog.EvidenceManifestSchemaVersion || requestedSchema == catalog.EvidenceManifestSchemaVersionV1 {
		if manifest.SchemaVersion != requestedSchema {
			addError("%s: schemaVersion %q does not match requested %q", evidenceManifestFilename, manifest.SchemaVersion, requestedSchema)
		}
	}
	if manifest.SchemaVersion == catalog.EvidenceManifestSchemaVersionV1 {
		return
	}
	expected, err := buildEvidenceManifest(catalogPath)
	if err != nil {
		addError("%s: failed to rebuild expected manifest: %v", evidenceManifestFilename, err)
		return
	}
	if !reflect.DeepEqual(*manifest, expected) {
		addError("%s: does not match catalog image records; regenerate catalog output", evidenceManifestFilename)
	}
}

func validateIndexSchemaVersion(index *catalog.CatalogIndex, requested string, addError func(string, ...any)) {
	if index.SchemaVersion != "" && index.SchemaVersion != catalog.CatalogIndexSchemaVersion && index.SchemaVersion != catalog.CatalogIndexSchemaVersionV2 {
		addError("index.json: unsupported schemaVersion %q", index.SchemaVersion)
	}
	if requested == "" {
		return
	}
	switch requested {
	case catalog.CatalogIndexSchemaVersion, catalog.CatalogIndexSchemaVersionV2:
		if index.SchemaVersion != requested {
			addError("index.json: schemaVersion %s does not match requested %q", schemaVersionLabel(index.SchemaVersion), requested)
		}
	case catalog.ImageRecordSchemaVersion, catalog.ImageRecordSchemaVersionV2, catalog.EvidenceManifestSchemaVersionV1, catalog.EvidenceManifestSchemaVersion:
		// Checked against each image record or the evidence manifest as files are loaded.
	default:
		addError("unsupported schema version %q (known: %q, %q, %q, %q, %q, %q)", requested, catalog.CatalogIndexSchemaVersion, catalog.CatalogIndexSchemaVersionV2, catalog.ImageRecordSchemaVersion, catalog.ImageRecordSchemaVersionV2, catalog.EvidenceManifestSchemaVersionV1, catalog.EvidenceManifestSchemaVersion)
	}
}

func validateImageSchemaVersion(record *catalog.ImageRecord, requested string, addError func(string, ...any)) {
	if record.SchemaVersion != "" && record.SchemaVersion != catalog.ImageRecordSchemaVersion && record.SchemaVersion != catalog.ImageRecordSchemaVersionV2 {
		addError("%s: unsupported schemaVersion %q", record.ID, record.SchemaVersion)
	}
	if requested != catalog.ImageRecordSchemaVersion && requested != catalog.ImageRecordSchemaVersionV2 {
		return
	}
	if record.SchemaVersion != requested {
		addError("%s: schemaVersion %s does not match requested %q", record.ID, schemaVersionLabel(record.SchemaVersion), requested)
	}
}

func schemaVersionLabel(value string) string {
	if value == "" {
		return "<missing>"
	}
	return fmt.Sprintf("%q", value)
}

func validateCatalogRecord(catalogPath string, index *catalog.CatalogIndex, summary catalog.CatalogImageSummary, record *catalog.ImageRecord, addError, addWarning func(string, ...any)) {
	if record.ID != summary.ID {
		addError("%s: record id %q does not match index id %q", imageRecordLabel(catalogPath, summary.ID), record.ID, summary.ID)
	}
	if err := catalog.ValidateImageRecord(record); err != nil {
		addError("%s: %v", imageRecordLabel(catalogPath, summary.ID), err)
	}
	if len(record.Releases) == 0 {
		addError("%s: no releases", imageRecordLabel(catalogPath, summary.ID))
		return
	}

	var latest *catalog.ReleaseEntry
	for i := range record.Releases {
		rel := &record.Releases[i]
		validateCatalogRelease(record.ID, rel, addError, addWarning)
		if rel.Tag == summary.LatestTag || rel.Tag == index.LatestTag || rel.IsLatest {
			if latest == nil {
				latest = rel
			}
		}
	}
	if latest == nil {
		addError("%s: latest release %q is missing from image record", record.ID, summary.LatestTag)
		return
	}
	validateIndexEvidence(summary, latest, addError, addWarning)
	warnMissingOptionalEvidence(summary.ID, latest, addWarning)
}

func validateCatalogRelease(imageID string, rel *catalog.ReleaseEntry, addError, addWarning func(string, ...any)) {
	if rel.Tag == "" {
		addError("%s: release is missing tag", imageID)
	}
	if len(rel.Architectures) == 0 {
		addWarning("%s:%s: no architectures", imageID, rel.Tag)
	}
	for i := range rel.Architectures {
		arch := &rel.Architectures[i]
		label := fmt.Sprintf("%s:%s architectures[%d]", imageID, rel.Tag, i)
		if arch.Arch == "" {
			addError("%s: missing arch", label)
		}
		if arch.OS == "" {
			addError("%s: missing os", label)
		}
		validateCatalogPackages(label, arch.SBOM.Packages, addError)
		validateCatalogFindings(label, arch.Vulnerabilities, addError)
		warnLayerMapping(label, arch, addWarning)
	}
}

func validateCatalogPackages(label string, packages []catalog.PackageEntry, addError func(string, ...any)) {
	for i, pkg := range packages {
		prefix := fmt.Sprintf("%s sbom.packages[%d]", label, i)
		if pkg.Name == "" {
			addError("%s: missing name", prefix)
		}
		if pkg.Version == "" {
			addError("%s: missing version", prefix)
		}
		if pkg.SpdxID == "" {
			addError("%s: missing spdxId", prefix)
		}
	}
}

func validateCatalogFindings(label string, vuln *catalog.VulnerabilitiesInfo, addError func(string, ...any)) {
	if vuln == nil {
		return
	}
	for i, finding := range vuln.Findings {
		prefix := fmt.Sprintf("%s vulnerabilities.findings[%d]", label, i)
		if finding.ID == "" {
			addError("%s: missing id", prefix)
		}
		if finding.Severity == "" {
			addError("%s: missing severity", prefix)
		}
		if finding.PackageName == "" {
			addError("%s: missing packageName", prefix)
		}
		if finding.PackageVersion == "" {
			addError("%s: missing packageVersion", prefix)
		}
	}
}

func validateIndexEvidence(summary catalog.CatalogImageSummary, rel *catalog.ReleaseEntry, addError, addWarning func(string, ...any)) {
	evidence := releaseEvidenceSummary(rel)
	for _, pair := range []struct {
		key      string
		summaryV bool
		relV     bool
	}{
		{"signed", summary.Signed, evidence.Signature},
		{"provenance", summary.Provenance, evidence.Provenance},
	} {
		if pair.summaryV != pair.relV {
			addError("%s: index %s=%t but latest release evidence=%t", summary.ID, pair.key, pair.summaryV, pair.relV)
		}
	}
	if summary.Evidence == nil {
		addWarning("%s: index summary is missing evidence object", summary.ID)
		return
	}
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
			addError("%s: index evidence.%s=%t but latest release evidence=%t", summary.ID, pair.key, pair.summaryV, pair.relV)
		}
	}
}

func warnMissingOptionalEvidence(imageID string, rel *catalog.ReleaseEntry, addWarning func(string, ...any)) {
	evidence := releaseEvidenceSummary(rel)
	if !evidence.Signature {
		addWarning("%s:%s: missing signature evidence", imageID, rel.Tag)
	}
	if !evidence.Provenance {
		addWarning("%s:%s: missing provenance evidence", imageID, rel.Tag)
	}
	if !evidence.SBOM {
		addWarning("%s:%s: missing or incomplete SBOM evidence (%d/%d architectures)", imageID, rel.Tag, evidence.SBOMArchCount, evidence.ArchCount)
	}
	if !evidence.Vulnerabilities {
		addWarning("%s:%s: missing or incomplete vulnerability scans (%d/%d architectures)", imageID, rel.Tag, evidence.VulnerabilityArchCount, evidence.ArchCount)
	}
}

func warnLayerMapping(label string, arch *catalog.ArchPayload, addWarning func(string, ...any)) {
	if len(arch.Layers) == 0 || len(arch.SBOM.Packages) == 0 {
		return
	}
	for _, pkg := range arch.SBOM.Packages {
		if pkg.LayerDigest != nil && *pkg.LayerDigest != "" {
			return
		}
	}
	addWarning("%s: layers and packages are present but package layerDigest mapping is unavailable", label)
}

func imageRecordLabel(catalogPath, imageID string) string {
	return filepath.Join(catalogPath, "images", imageID+".json")
}

func (r *catalogValidationReport) finish() {
	sort.Strings(r.Errors)
	sort.Strings(r.Warnings)
	r.ErrorCount = len(r.Errors)
	r.WarningCount = len(r.Warnings)
}
