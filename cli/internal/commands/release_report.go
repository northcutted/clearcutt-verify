package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/spf13/cobra"
)

type releaseFlags struct {
	fromTag   string
	toTag     string
	image     string
	outputDir string
}

var releaseOpts releaseFlags

func NewReleaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release",
		Short: "Generate written release-comparison reports",
	}

	reportCmd := &cobra.Command{
		Use:   "diff-report",
		Short: "Generate detailed release diff reports as Markdown and JSON",
		Long:  `Generates high-fidelity evidence-backed release reports comparing manifest size, layers, packages, and CVE differences to establish promotional actions.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReleaseReport()
		},
	}

	reportCmd.Flags().StringVar(&releaseOpts.fromTag, "from", "latest-1", "Tag to compare from (aliases: latest, latest-N)")
	reportCmd.Flags().StringVar(&releaseOpts.toTag, "to", "latest", "Tag to compare to (aliases: latest, latest-N)")
	reportCmd.Flags().StringVar(&releaseOpts.image, "image", "", "Required ClearCutt image ID to diff")
	reportCmd.Flags().StringVar(&releaseOpts.outputDir, "output-dir", "dist/reports/releases", "Target write directory path")

	reportCmd.MarkFlagRequired("image")

	cmd.AddCommand(reportCmd)
	return cmd
}

func runReleaseReport() error {
	imageID := releaseOpts.image
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	fromRelease, err := resolveRelease(record.Releases, releaseOpts.fromTag)
	if err != nil {
		return fmt.Errorf("failed to resolve --from release: %w", err)
	}

	toRelease, err := resolveRelease(record.Releases, releaseOpts.toTag)
	if err != nil {
		return fmt.Errorf("failed to resolve --to release: %w", err)
	}

	// Calculate difference
	diffRep := DiffReport{
		ImageID:    imageID,
		FromTag:    fromRelease.Tag,
		ToTag:      toRelease.Tag,
		Lifecycle:  diffLifecycle(fromRelease.Lifecycle, toRelease.Lifecycle),
		Exceptions: ExceptionDiffReport{TotalChange: toRelease.Exceptions.Total - fromRelease.Exceptions.Total},
		Evidence:   diffEvidence(fromRelease.Evidence, toRelease.Evidence),
	}

	// Calculate size difference
	fromSize := int64(0)
	if fromRelease.TotalSize != nil {
		fromSize = *fromRelease.TotalSize
	}
	toSize := int64(0)
	if toRelease.TotalSize != nil {
		toSize = *toRelease.TotalSize
	}
	diffRep.SizeChange = toSize - fromSize

	// Calculate architectures difference
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

			archReport.PackagesAdded, archReport.PackagesRemoved, archReport.PackagesChanged = diffPackages(
				fromArch.SBOM.Packages, toArch.SBOM.Packages,
			)

			if fromArch.Vulnerabilities != nil && toArch.Vulnerabilities != nil {
				archReport.CVEsAdded, archReport.CVEsResolved = diffCVEs(
					fromArch.Vulnerabilities.Findings, toArch.Vulnerabilities.Findings,
				)
			}
		} else {
			archReport.DigestChange = "added"
		}
		diffRep.ArchChanges = append(diffRep.ArchChanges, archReport)
	}

	// Recommended Promotion Decision Logic
	decision := "promote"
	blockReasons := []string{}

	// Verify lifecycle blocking
	if strings.ToLower(toRelease.Lifecycle.Status) == "blocked" {
		decision = "blocked"
		blockReasons = append(blockReasons, "Lifecycle status is blocked")
	}

	// Verify evidence blocking
	if toRelease.Evidence != nil {
		if !toRelease.Evidence.Signature {
			decision = "hold"
			blockReasons = append(blockReasons, "Missing Sigstore keyless signatures")
		}
		if !toRelease.Evidence.SBOM {
			decision = "hold"
			blockReasons = append(blockReasons, "Missing SPDX SBOM attestation coverage")
		}
		if !toRelease.Evidence.Provenance {
			decision = "hold"
			blockReasons = append(blockReasons, "Missing SLSA provenance attestation")
		}
		if !toRelease.Evidence.Tests {
			decision = "hold"
			blockReasons = append(blockReasons, "Missing conformance and smoke test outcomes")
		}
	}

	// Verify CVE block rules
	for _, arch := range diffRep.ArchChanges {
		if len(arch.CVEsAdded) > 0 {
			decision = "manual_review"
			blockReasons = append(blockReasons, fmt.Sprintf("Newly introduced CVEs on %s: %s", arch.Arch, strings.Join(arch.CVEsAdded, ", ")))
		}
	}

	if len(blockReasons) == 0 {
		blockReasons = append(blockReasons, "All compliance policies pass cleanly.")
	}

	// Output Directories
	outDir := releaseOpts.outputDir
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write JSON Report
	jsonReport := struct {
		DiffReport
		Decision     string   `json:"recommendedAction"`
		BlockReasons []string `json:"reasons"`
	}{
		DiffReport:   diffRep,
		Decision:     decision,
		BlockReasons: blockReasons,
	}

	jsonData, err := json.MarshalIndent(jsonReport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}
	jsonPath := filepath.Join(outDir, fmt.Sprintf("%s.json", imageID))
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	// Write Markdown Report
	var md strings.Builder
	md.WriteString(fmt.Sprintf("# ClearCutt Release Diff Report: %s\n\n", imageID))
	md.WriteString(fmt.Sprintf("## Comparison Range: `%s` ➔ `%s`\n\n", diffRep.FromTag, diffRep.ToTag))
	md.WriteString("### 🛡️ Recommended Governance Action\n")
	md.WriteString(fmt.Sprintf("**Decision**: `%s`  \n", strings.ToUpper(decision)))
	md.WriteString("**Compliance Analysis Details**:\n")
	for _, reason := range blockReasons {
		md.WriteString(fmt.Sprintf("- %s\n", reason))
	}
	md.WriteString("\n---\n\n")

	md.WriteString("### 📊 Metrics Summary\n")
	md.WriteString(fmt.Sprintf("- **Total Size Change**: %+.2f MB\n", float64(diffRep.SizeChange)/(1024*1024)))
	if diffRep.Lifecycle.StatusChanged {
		md.WriteString(fmt.Sprintf("- **Lifecycle Status Transition**: `%s` ➔ `%s`\n", diffRep.Lifecycle.FromStatus, diffRep.Lifecycle.ToStatus))
	}
	if diffRep.Exceptions.TotalChange != 0 {
		md.WriteString(fmt.Sprintf("- **Exceptions Delta**: %+d exceptions\n", diffRep.Exceptions.TotalChange))
	}
	md.WriteString("\n---\n\n")

	md.WriteString("### 💻 Architecture Detail Reports\n")
	for _, arch := range diffRep.ArchChanges {
		md.WriteString(fmt.Sprintf("#### Platform `linux/%s`\n", arch.Arch))
		md.WriteString(fmt.Sprintf("- **Image Size Delta**: %+.2f MB\n", float64(arch.SizeChange)/(1024*1024)))
		md.WriteString(fmt.Sprintf("- **Layer Count Delta**: %+d layers\n", arch.LayerCountChange))
		md.WriteString(fmt.Sprintf("- **Packages**: +%d added, -%d removed, *%d changed\n", len(arch.PackagesAdded), len(arch.PackagesRemoved), len(arch.PackagesChanged)))
		md.WriteString(fmt.Sprintf("- **Vulnerabilities**: +%d new CVEs, -%d resolved CVEs\n", len(arch.CVEsAdded), len(arch.CVEsResolved)))

		if len(arch.CVEsAdded) > 0 {
			md.WriteString("\n**Newly Introduced CVEs**:\n")
			for _, c := range arch.CVEsAdded {
				md.WriteString(fmt.Sprintf("  - `+ %s`\n", c))
			}
		}
		md.WriteString("\n")
	}

	mdPath := filepath.Join(outDir, fmt.Sprintf("%s.md", imageID))
	if err := os.WriteFile(mdPath, []byte(md.String()), 0644); err != nil {
		return fmt.Errorf("failed to write Markdown report: %w", err)
	}

	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "Successfully generated release diff reports under: %s\n", outDir)
	}

	return nil
}
