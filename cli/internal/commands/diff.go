package commands

import (
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type diffFlags struct {
	fromTag string
	toTag   string
}

var diffOpts diffFlags

// DiffReport holds comparative data of two versioned releases.
type DiffReport struct {
	ImageID      string              `json:"imageId"`
	FromTag      string              `json:"fromTag"`
	ToTag        string              `json:"toTag"`
	DigestChange string              `json:"digestChange"`
	SizeChange   int64               `json:"sizeChange"`
	ArchChanges  []ArchDiffReport    `json:"architectureChanges"`
	Lifecycle    LifecycleDiffReport `json:"lifecycleChanges"`
	Exceptions   ExceptionDiffReport `json:"exceptionChanges"`
	Evidence     EvidenceDiffReport  `json:"evidenceChanges"`
}

// ArchDiffReport tracks changes per target execution platform.
type ArchDiffReport struct {
	Arch             string   `json:"arch"`
	DigestChange     string   `json:"digestChange"`
	SizeChange       int64    `json:"sizeChange"`
	LayerCountChange int      `json:"layerCountChange"`
	PackagesAdded    []string `json:"packagesAdded"`
	PackagesRemoved  []string `json:"packagesRemoved"`
	PackagesChanged  []string `json:"packagesChanged"`
	CVEsAdded        []string `json:"cvesAdded"`
	CVEsResolved     []string `json:"cvesResolved"`
}

// LifecycleDiffReport tracks changes in base OS compatibility policy.
type LifecycleDiffReport struct {
	StatusChanged            bool   `json:"statusChanged"`
	FromStatus               string `json:"fromStatus"`
	ToStatus                 string `json:"toStatus"`
	SupportChanged           bool   `json:"supportChanged"`
	FromSupport              string `json:"fromSupport"`
	ToSupport                string `json:"toSupport"`
	ProductionAllowedChanged bool   `json:"productionAllowedChanged"`
	FromProd                 bool   `json:"fromProductionAllowed"`
	ToProd                   bool   `json:"toProductionAllowed"`
}

// ExceptionDiffReport tracks exceptions shifts.
type ExceptionDiffReport struct {
	TotalChange int `json:"totalChange"`
}

// EvidenceDiffReport lists changes in attested supply-chain trust tags.
type EvidenceDiffReport struct {
	Changes []string `json:"changes"`
}

// NewDiffCmd creates the Cobra diff command.
func NewDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff <image-id>",
		Short: "Show what changed between two releases of an image",
		Long:  `Analyzes differences in layers, packages, vulnerabilities, evidence, lifecycles, and exceptions.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(args[0])
		},
	}

	cmd.Flags().StringVar(&diffOpts.fromTag, "from", "latest-1", "Tag to compare from (aliases: latest, latest-N)")
	cmd.Flags().StringVar(&diffOpts.toTag, "to", "latest", "Tag to compare to (aliases: latest, latest-N)")

	return cmd
}

func runDiff(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Resolve tags
	fromRelease, err := resolveRelease(record.Releases, diffOpts.fromTag)
	if err != nil {
		return fmt.Errorf("failed to resolve --from release: %w", err)
	}

	toRelease, err := resolveRelease(record.Releases, diffOpts.toTag)
	if err != nil {
		return fmt.Errorf("failed to resolve --to release: %w", err)
	}

	// Construct diff details
	report := DiffReport{
		ImageID:    imageID,
		FromTag:    fromRelease.Tag,
		ToTag:      toRelease.Tag,
		Lifecycle:  diffLifecycle(fromRelease.Lifecycle, toRelease.Lifecycle),
		Exceptions: ExceptionDiffReport{TotalChange: toRelease.Exceptions.Total - fromRelease.Exceptions.Total},
		Evidence:   diffEvidence(fromRelease.Evidence, toRelease.Evidence),
	}

	// Digest difference
	fromDigest := ""
	if fromRelease.ManifestDigest != nil {
		fromDigest = *fromRelease.ManifestDigest
	}
	toDigest := ""
	if toRelease.ManifestDigest != nil {
		toDigest = *toRelease.ManifestDigest
	}
	if fromDigest == toDigest {
		report.DigestChange = "unchanged"
	} else if fromDigest == "" {
		report.DigestChange = "added"
	} else if toDigest == "" {
		report.DigestChange = "removed"
	} else {
		report.DigestChange = "changed"
	}

	// Size difference
	fromSize := int64(0)
	if fromRelease.TotalSize != nil {
		fromSize = *fromRelease.TotalSize
	}
	toSize := int64(0)
	if toRelease.TotalSize != nil {
		toSize = *toRelease.TotalSize
	}
	report.SizeChange = toSize - fromSize

	// Architecture payloads difference
	for _, toArch := range toRelease.Architectures {
		var fromArch *catalog.ArchPayload
		for i := range fromRelease.Architectures {
			if fromRelease.Architectures[i].Arch == toArch.Arch {
				fromArch = &fromRelease.Architectures[i]
				break
			}
		}

		archReport := ArchDiffReport{Arch: toArch.Arch}
		if fromArch != nil {
			fd := ""
			if fromArch.ImageDigest != nil {
				fd = *fromArch.ImageDigest
			}
			td := ""
			if toArch.ImageDigest != nil {
				td = *toArch.ImageDigest
			}
			if fd == td {
				archReport.DigestChange = "unchanged"
			} else {
				archReport.DigestChange = "changed"
			}

			fsz := int64(0)
			if fromArch.ImageSize != nil {
				fsz = *fromArch.ImageSize
			}
			tsz := int64(0)
			if toArch.ImageSize != nil {
				tsz = *toArch.ImageSize
			}
			archReport.SizeChange = tsz - fsz

			flc := 0
			if fromArch.LayerCount != nil {
				flc = *fromArch.LayerCount
			}
			tlc := 0
			if toArch.LayerCount != nil {
				tlc = *toArch.LayerCount
			}
			archReport.LayerCountChange = tlc - flc

			// Compare packages
			archReport.PackagesAdded, archReport.PackagesRemoved, archReport.PackagesChanged = diffPackages(
				fromArch.SBOM.Packages, toArch.SBOM.Packages,
			)

			// Compare vulnerabilities
			if fromArch.Vulnerabilities != nil && toArch.Vulnerabilities != nil {
				archReport.CVEsAdded, archReport.CVEsResolved = diffCVEs(
					fromArch.Vulnerabilities.Findings, toArch.Vulnerabilities.Findings,
				)
			}
		} else {
			archReport.DigestChange = "added"
		}
		report.ArchChanges = append(report.ArchChanges, archReport)
	}

	// Format output
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, report)
	case "yaml", "yml":
		return output.PrintYAML(out, report)
	default:
		// Human readable tabular report
		fmt.Fprintf(out, "ClearCutt Release Diff Report for %s\n", imageID)
		fmt.Fprintf(out, "Comparing: %s -> %s\n", report.FromTag, report.ToTag)
		fmt.Fprintln(out, "-----------------------------------------------------------------")
		fmt.Fprintf(out, "Manifest Digest Change: %s\n", report.DigestChange)
		fmt.Fprintf(out, "Total Size Delta:       %+.2f MB\n", float64(report.SizeChange)/(1024*1024))

		if report.Lifecycle.StatusChanged {
			fmt.Fprintf(out, "Lifecycle Status:       %s -> %s\n", report.Lifecycle.FromStatus, report.Lifecycle.ToStatus)
		}
		if report.Lifecycle.ProductionAllowedChanged {
			fmt.Fprintf(out, "Production Gating:      %t -> %t\n", report.Lifecycle.FromProd, report.Lifecycle.ToProd)
		}
		if report.Exceptions.TotalChange != 0 {
			fmt.Fprintf(out, "Governance Exceptions:  %+d total\n", report.Exceptions.TotalChange)
		}

		for _, arch := range report.ArchChanges {
			fmt.Fprintf(out, "\nPlatform: linux/%s\n", arch.Arch)
			fmt.Fprintf(out, "  Image Digest:         %s\n", arch.DigestChange)
			fmt.Fprintf(out, "  Size Delta:           %+.2f MB\n", float64(arch.SizeChange)/(1024*1024))
			fmt.Fprintf(out, "  Layer Delta:          %+d layers\n", arch.LayerCountChange)
			fmt.Fprintf(out, "  Packages:             +%d added, -%d removed, *%d upgraded/changed\n",
				len(arch.PackagesAdded), len(arch.PackagesRemoved), len(arch.PackagesChanged))
			fmt.Fprintf(out, "  Vulnerabilities:      +%d new CVEs, -%d resolved CVEs\n",
				len(arch.CVEsAdded), len(arch.CVEsResolved))

			if len(arch.PackagesAdded) > 0 && GlobalOpts.Verbose {
				fmt.Fprintln(out, "    Added Packages:")
				for _, p := range arch.PackagesAdded {
					fmt.Fprintf(out, "      + %s\n", p)
				}
			}
			if len(arch.PackagesRemoved) > 0 && GlobalOpts.Verbose {
				fmt.Fprintln(out, "    Removed Packages:")
				for _, p := range arch.PackagesRemoved {
					fmt.Fprintf(out, "      - %s\n", p)
				}
			}
			if len(arch.CVEsAdded) > 0 {
				fmt.Fprintln(out, "    Newly Introduced CVEs:")
				for _, c := range arch.CVEsAdded {
					fmt.Fprintf(out, "      + %s\n", c)
				}
			}
			if len(arch.CVEsResolved) > 0 {
				fmt.Fprintln(out, "    Resolved CVEs:")
				for _, c := range arch.CVEsResolved {
					fmt.Fprintf(out, "      - %s\n", c)
				}
			}
		}
		fmt.Fprintln(out, "-----------------------------------------------------------------")
	}

	return nil
}

func resolveRelease(releases []catalog.ReleaseEntry, tag string) (*catalog.ReleaseEntry, error) {
	if len(releases) == 0 {
		return nil, fmt.Errorf("no releases available in this record")
	}

	if tag == "latest" {
		for i := range releases {
			if releases[i].IsLatest {
				return &releases[i], nil
			}
		}
		return &releases[0], nil
	}

	if strings.HasPrefix(tag, "latest-") {
		var n int
		_, err := fmt.Sscanf(tag, "latest-%d", &n)
		if err != nil {
			return nil, fmt.Errorf("invalid latest-N tag alias: %s", tag)
		}

		latestIdx := -1
		for i := range releases {
			if releases[i].IsLatest {
				latestIdx = i
				break
			}
		}
		if latestIdx == -1 {
			latestIdx = 0
		}

		targetIdx := latestIdx + n
		if targetIdx < 0 || targetIdx >= len(releases) {
			return nil, fmt.Errorf("release alias %q is out of bounds (only %d releases on record)", tag, len(releases))
		}

		return &releases[targetIdx], nil
	}

	// Match tag exactly
	for i := range releases {
		if releases[i].Tag == tag {
			return &releases[i], nil
		}
	}

	return nil, fmt.Errorf("tag %q not found on record", tag)
}

func diffLifecycle(from, to catalog.Lifecycle) LifecycleDiffReport {
	return LifecycleDiffReport{
		StatusChanged:            from.Status != to.Status,
		FromStatus:               from.Status,
		ToStatus:                 to.Status,
		SupportChanged:           from.Support != to.Support,
		FromSupport:              from.Support,
		ToSupport:                to.Support,
		ProductionAllowedChanged: from.ProductionAllowed != to.ProductionAllowed,
		FromProd:                 from.ProductionAllowed,
		ToProd:                   to.ProductionAllowed,
	}
}

func diffEvidence(from, to *catalog.EvidenceSummary) EvidenceDiffReport {
	changes := []string{}
	if from == nil || to == nil {
		return EvidenceDiffReport{Changes: changes}
	}

	if from.Signature != to.Signature {
		changes = append(changes, fmt.Sprintf("signature: %t -> %t", from.Signature, to.Signature))
	}
	if from.Provenance != to.Provenance {
		changes = append(changes, fmt.Sprintf("provenance: %t -> %t", from.Provenance, to.Provenance))
	}
	if from.SBOM != to.SBOM {
		changes = append(changes, fmt.Sprintf("sbom: %t -> %t", from.SBOM, to.SBOM))
	}
	if from.Tests != to.Tests {
		changes = append(changes, fmt.Sprintf("tests: %t -> %t", from.Tests, to.Tests))
	}
	if from.Vulnerabilities != to.Vulnerabilities {
		changes = append(changes, fmt.Sprintf("vulnerabilities: %t -> %t", from.Vulnerabilities, to.Vulnerabilities))
	}

	return EvidenceDiffReport{Changes: changes}
}

func diffPackages(fromPkgs, toPkgs []catalog.PackageEntry) (added, removed, changed []string) {
	fromMap := make(map[string]string)
	for _, p := range fromPkgs {
		fromMap[p.Name] = p.Version
	}

	toMap := make(map[string]string)
	for _, p := range toPkgs {
		toMap[p.Name] = p.Version
	}

	for name, toVer := range toMap {
		fromVer, exists := fromMap[name]
		if !exists {
			added = append(added, fmt.Sprintf("%s (%s)", name, toVer))
		} else if fromVer != toVer {
			changed = append(changed, fmt.Sprintf("%s (%s -> %s)", name, fromVer, toVer))
		}
	}

	for name, fromVer := range fromMap {
		if _, exists := toMap[name]; !exists {
			removed = append(removed, fmt.Sprintf("%s (%s)", name, fromVer))
		}
	}

	return added, removed, changed
}

func diffCVEs(fromFindings, toFindings []catalog.FindingInfo) (added, resolved []string) {
	fromMap := make(map[string]string)
	for _, f := range fromFindings {
		key := fmt.Sprintf("%s (%s)", f.ID, f.PackageName)
		fromMap[key] = f.Severity
	}

	toMap := make(map[string]string)
	for _, f := range toFindings {
		key := fmt.Sprintf("%s (%s)", f.ID, f.PackageName)
		toMap[key] = f.Severity
	}

	for key := range toMap {
		if _, exists := fromMap[key]; !exists {
			added = append(added, key)
		}
	}

	for key := range fromMap {
		if _, exists := toMap[key]; !exists {
			resolved = append(resolved, key)
		}
	}

	return added, resolved
}
