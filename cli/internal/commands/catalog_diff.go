package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type catalogDiffFlags struct {
	oldPath string
	newPath string
}

var catalogDiffOpts catalogDiffFlags

type catalogDirectoryDiff struct {
	OldPath       string               `json:"oldPath"`
	NewPath       string               `json:"newPath"`
	AddedImages   []string             `json:"addedImages"`
	RemovedImages []string             `json:"removedImages"`
	ChangedImages []catalogImageChange `json:"changedImages"`
}

type catalogImageChange struct {
	ID                 string            `json:"id"`
	LatestTag          *stringChange     `json:"latestTag,omitempty"`
	ManifestDigest     *stringChange     `json:"manifestDigest,omitempty"`
	PackageCount       *intChange        `json:"packageCount,omitempty"`
	CriticalFindings   *intChange        `json:"criticalFindings,omitempty"`
	HighFindings       *intChange        `json:"highFindings,omitempty"`
	Signature          *boolChange       `json:"signature,omitempty"`
	Provenance         *boolChange       `json:"provenance,omitempty"`
	LifecycleStatus    *stringChange     `json:"lifecycleStatus,omitempty"`
	ProductionAllowed  *boolChange       `json:"productionAllowed,omitempty"`
	EvidenceProperties map[string]string `json:"evidenceProperties,omitempty"`
}

type stringChange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type intChange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

type boolChange struct {
	From bool `json:"from"`
	To   bool `json:"to"`
}

func newCatalogDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff --old <catalog-dir> --new <catalog-dir>",
		Short: "Compare two generated catalog directories",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogDirectoryDiff()
		},
	}
	cmd.Flags().StringVar(&catalogDiffOpts.oldPath, "old", "", "Previous catalog directory")
	cmd.Flags().StringVar(&catalogDiffOpts.newPath, "new", "", "New catalog directory")
	cmd.MarkFlagRequired("old")
	cmd.MarkFlagRequired("new")
	return cmd
}

func runCatalogDirectoryDiff() error {
	diff, err := buildCatalogDirectoryDiff(catalogDiffOpts.oldPath, catalogDiffOpts.newPath)
	if err != nil {
		return err
	}
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, diff)
	case "yaml", "yml":
		return output.PrintYAML(out, diff)
	default:
		printCatalogDirectoryDiff(diff)
		return nil
	}
}

func buildCatalogDirectoryDiff(oldPath, newPath string) (catalogDirectoryDiff, error) {
	oldIndex, err := catalog.LoadCatalogIndex(oldPath)
	if err != nil {
		return catalogDirectoryDiff{}, err
	}
	newIndex, err := catalog.LoadCatalogIndex(newPath)
	if err != nil {
		return catalogDirectoryDiff{}, err
	}
	oldImages := catalogSummaryByID(oldIndex.Images)
	newImages := catalogSummaryByID(newIndex.Images)

	diff := catalogDirectoryDiff{OldPath: oldPath, NewPath: newPath}
	for id := range newImages {
		if _, ok := oldImages[id]; !ok {
			diff.AddedImages = append(diff.AddedImages, id)
		}
	}
	for id := range oldImages {
		if _, ok := newImages[id]; !ok {
			diff.RemovedImages = append(diff.RemovedImages, id)
		}
	}
	sort.Strings(diff.AddedImages)
	sort.Strings(diff.RemovedImages)

	common := []string{}
	for id := range newImages {
		if _, ok := oldImages[id]; ok {
			common = append(common, id)
		}
	}
	sort.Strings(common)
	for _, id := range common {
		if change, ok := compareCatalogSummary(oldImages[id], newImages[id]); ok {
			diff.ChangedImages = append(diff.ChangedImages, change)
		}
	}
	return diff, nil
}

func catalogSummaryByID(images []catalog.CatalogImageSummary) map[string]catalog.CatalogImageSummary {
	out := map[string]catalog.CatalogImageSummary{}
	for _, img := range images {
		out[img.ID] = img
	}
	return out
}

func compareCatalogSummary(oldImg, newImg catalog.CatalogImageSummary) (catalogImageChange, bool) {
	change := catalogImageChange{ID: newImg.ID}
	if oldImg.LatestTag != newImg.LatestTag {
		change.LatestTag = &stringChange{From: oldImg.LatestTag, To: newImg.LatestTag}
	}
	oldDigest, newDigest := ptrString(oldImg.LatestManifestDigest), ptrString(newImg.LatestManifestDigest)
	if oldDigest != newDigest {
		change.ManifestDigest = &stringChange{From: oldDigest, To: newDigest}
	}
	if oldImg.LatestPackageCount != newImg.LatestPackageCount {
		change.PackageCount = &intChange{From: oldImg.LatestPackageCount, To: newImg.LatestPackageCount}
	}
	oldCritical, oldHigh := vulnCounts(oldImg)
	newCritical, newHigh := vulnCounts(newImg)
	if oldCritical != newCritical {
		change.CriticalFindings = &intChange{From: oldCritical, To: newCritical}
	}
	if oldHigh != newHigh {
		change.HighFindings = &intChange{From: oldHigh, To: newHigh}
	}
	if oldImg.Signed != newImg.Signed {
		change.Signature = &boolChange{From: oldImg.Signed, To: newImg.Signed}
	}
	if oldImg.Provenance != newImg.Provenance {
		change.Provenance = &boolChange{From: oldImg.Provenance, To: newImg.Provenance}
	}
	if oldImg.Lifecycle.Status != newImg.Lifecycle.Status {
		change.LifecycleStatus = &stringChange{From: oldImg.Lifecycle.Status, To: newImg.Lifecycle.Status}
	}
	if oldImg.Lifecycle.ProductionAllowed != newImg.Lifecycle.ProductionAllowed {
		change.ProductionAllowed = &boolChange{From: oldImg.Lifecycle.ProductionAllowed, To: newImg.Lifecycle.ProductionAllowed}
	}
	evidenceChanges := compareEvidenceSummary(oldImg.Evidence, newImg.Evidence)
	if len(evidenceChanges) > 0 {
		change.EvidenceProperties = evidenceChanges
	}
	return change, !catalogImageChangeEmpty(change)
}

func vulnCounts(img catalog.CatalogImageSummary) (int, int) {
	if img.VulnSummary == nil {
		return 0, 0
	}
	return img.VulnSummary.Critical, img.VulnSummary.High
}

func ptrString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func compareEvidenceSummary(oldEv, newEv *catalog.EvidenceSummary) map[string]string {
	if oldEv == nil && newEv == nil {
		return nil
	}
	changes := map[string]string{}
	oldValue := catalog.EvidenceSummary{}
	newValue := catalog.EvidenceSummary{}
	if oldEv != nil {
		oldValue = *oldEv
	}
	if newEv != nil {
		newValue = *newEv
	}
	for _, field := range []struct {
		name string
		old  bool
		new  bool
	}{
		{"signature", oldValue.Signature, newValue.Signature},
		{"provenance", oldValue.Provenance, newValue.Provenance},
		{"sbom", oldValue.SBOM, newValue.SBOM},
		{"tests", oldValue.Tests, newValue.Tests},
		{"vulnerabilities", oldValue.Vulnerabilities, newValue.Vulnerabilities},
	} {
		if field.old != field.new {
			changes[field.name] = fmt.Sprintf("%t -> %t", field.old, field.new)
		}
	}
	if len(changes) == 0 {
		return nil
	}
	return changes
}

func catalogImageChangeEmpty(change catalogImageChange) bool {
	return change.LatestTag == nil &&
		change.ManifestDigest == nil &&
		change.PackageCount == nil &&
		change.CriticalFindings == nil &&
		change.HighFindings == nil &&
		change.Signature == nil &&
		change.Provenance == nil &&
		change.LifecycleStatus == nil &&
		change.ProductionAllowed == nil &&
		len(change.EvidenceProperties) == 0
}

func printCatalogDirectoryDiff(diff catalogDirectoryDiff) {
	fmt.Fprintf(out, "Catalog Diff\n")
	fmt.Fprintf(out, "Old: %s\n", diff.OldPath)
	fmt.Fprintf(out, "New: %s\n\n", diff.NewPath)
	printStringList("Added images", diff.AddedImages)
	printStringList("Removed images", diff.RemovedImages)
	if len(diff.ChangedImages) == 0 {
		fmt.Fprintln(out, "Changed images: none")
		return
	}
	fmt.Fprintln(out, "Changed images:")
	for _, change := range diff.ChangedImages {
		fmt.Fprintf(out, "  %s\n", change.ID)
		printMaybeStringChange("latestTag", change.LatestTag)
		printMaybeStringChange("manifestDigest", change.ManifestDigest)
		printMaybeIntChange("package count", change.PackageCount)
		printMaybeIntChange("critical CVEs", change.CriticalFindings)
		printMaybeIntChange("high CVEs", change.HighFindings)
		printMaybeBoolChange("signature", change.Signature)
		printMaybeBoolChange("provenance", change.Provenance)
		printMaybeStringChange("lifecycle", change.LifecycleStatus)
		printMaybeBoolChange("production allowed", change.ProductionAllowed)
		keys := make([]string, 0, len(change.EvidenceProperties))
		for key := range change.EvidenceProperties {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(out, "    evidence.%s: %s\n", key, change.EvidenceProperties[key])
		}
	}
}

func printStringList(label string, values []string) {
	if len(values) == 0 {
		fmt.Fprintf(out, "%s: none\n\n", label)
		return
	}
	fmt.Fprintf(out, "%s:\n", label)
	for _, value := range values {
		fmt.Fprintf(out, "  %s\n", value)
	}
	fmt.Fprintln(out)
}

func printMaybeStringChange(label string, change *stringChange) {
	if change != nil {
		fmt.Fprintf(out, "    %s: %s -> %s\n", label, emptyAsMissing(change.From), emptyAsMissing(change.To))
	}
}

func printMaybeIntChange(label string, change *intChange) {
	if change != nil {
		fmt.Fprintf(out, "    %s: %d -> %d\n", label, change.From, change.To)
	}
}

func printMaybeBoolChange(label string, change *boolChange) {
	if change != nil {
		fmt.Fprintf(out, "    %s: %t -> %t\n", label, change.From, change.To)
	}
}

func emptyAsMissing(value string) string {
	if value == "" {
		return "missing"
	}
	return value
}
