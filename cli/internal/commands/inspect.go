package commands

import (
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type inspectFlags struct {
	tag string
}

var inspectOpts inspectFlags

// NewInspectCmd creates the Cobra inspect command.
func NewInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <image-id>",
		Short: "Inspect one image record from the catalog",
		Long:  `Inspect all supply chain evidence, lifecycle states, vulnerabilities, and assets for a single base image.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(args[0])
		},
	}

	cmd.Flags().StringVar(&inspectOpts.tag, "tag", "", "Inspect details for a specific versioned release tag")

	return cmd
}

func runInspect(imageID string) error {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return fmt.Errorf("image record validation failed: %w", err)
	}

	// Find the targeted release
	var targetRelease *catalog.ReleaseEntry
	if inspectOpts.tag != "" {
		for i := range record.Releases {
			if record.Releases[i].Tag == inspectOpts.tag {
				targetRelease = &record.Releases[i]
				break
			}
		}
		if targetRelease == nil {
			return fmt.Errorf("release tag %q not found for image %q", inspectOpts.tag, imageID)
		}
	} else {
		// Default to latest release
		for i := range record.Releases {
			if record.Releases[i].IsLatest {
				targetRelease = &record.Releases[i]
				break
			}
		}
		if targetRelease == nil && len(record.Releases) > 0 {
			targetRelease = &record.Releases[0]
		}
	}

	if targetRelease == nil {
		return fmt.Errorf("no releases found for image %q", imageID)
	}

	// Format output
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, struct {
			ImageRecord   *catalog.ImageRecord  `json:"imageRecord"`
			ActiveRelease *catalog.ReleaseEntry `json:"activeRelease"`
		}{
			ImageRecord:   record,
			ActiveRelease: targetRelease,
		})
	case "yaml", "yml":
		return output.PrintYAML(out, struct {
			ImageRecord   *catalog.ImageRecord  `json:"imageRecord"`
			ActiveRelease *catalog.ReleaseEntry `json:"activeRelease"`
		}{
			ImageRecord:   record,
			ActiveRelease: targetRelease,
		})
	default:
		// Human readable formatted terminal output
		fmt.Fprintf(out, "Image ID:           %s\n", record.ID)
		fmt.Fprintf(out, "Language/Runtime:   %s (%s)\n", record.Language.DisplayName, record.Language.Version)
		fmt.Fprintf(out, "Tier:               %s\n", record.Tier.Name)
		fmt.Fprintf(out, "Full Image Name:    %s\n", record.FullName)
		fmt.Fprintf(out, "Tag Reference:      %s:%s\n", record.FullName, targetRelease.Tag)

		// Digest-pinned reference
		if targetRelease.ManifestDigest != nil && *targetRelease.ManifestDigest != "" {
			fmt.Fprintf(out, "Digest Reference:   %s@%s\n", record.FullName, *targetRelease.ManifestDigest)
		} else {
			fmt.Fprintln(out, "Digest Reference:   [Evidence Incomplete - Manifest Digest Missing]")
		}

		fmt.Fprintln(out, "\n--- Lifecycle Policy ---")
		fmt.Fprintf(out, "Status:             %s\n", targetRelease.Lifecycle.Status)
		fmt.Fprintf(out, "Support Tier:       %s\n", targetRelease.Lifecycle.Support)
		prodAllowed := "no"
		if targetRelease.Lifecycle.ProductionAllowed {
			prodAllowed = "yes"
		}
		fmt.Fprintf(out, "Prod Allowed:       %s\n", prodAllowed)
		if targetRelease.Lifecycle.Reason != nil && *targetRelease.Lifecycle.Reason != "" {
			fmt.Fprintf(out, "Reason:             %s\n", *targetRelease.Lifecycle.Reason)
		}

		if record.Kind == "service" && record.Service != nil {
			fmt.Fprintln(out, "\n--- Service Metadata ---")
			fmt.Fprintf(out, "Template:           %s\n", record.Service.Template)
			fmt.Fprintf(out, "Version:            %s\n", record.Service.Version)
			fmt.Fprintf(out, "Ports:              %s\n", serviceInspectPorts(record.Service.Ports))
			storage := "stateless"
			if record.Service.Stateful {
				storage = strings.Join(record.Service.DataDirs, ", ")
				if storage == "" {
					storage = "stateful"
				}
			}
			fmt.Fprintf(out, "Storage:            %s\n", storage)
			fmt.Fprintf(out, "Smoke Status:       %s\n", firstNonEmptyString(record.Service.SmokeStatus, "pending"))
			if len(record.Service.Smoke) > 0 {
				fmt.Fprintf(out, "Smoke Commands:     %s\n", strings.Join(record.Service.Smoke, "; "))
			}
		}

		fmt.Fprintln(out, "\n--- Runtime Contract ---")
		if targetRelease.RuntimeContract.User != nil {
			fmt.Fprintf(out, "User:               %s\n", *targetRelease.RuntimeContract.User)
		} else {
			fmt.Fprintln(out, "User:               unknown")
		}
		if targetRelease.RuntimeContract.WorkingDir != nil {
			fmt.Fprintf(out, "Working Dir:        %s\n", *targetRelease.RuntimeContract.WorkingDir)
		} else {
			fmt.Fprintln(out, "Working Dir:        unknown")
		}

		shellVal := "unknown"
		if targetRelease.RuntimeContract.ShellPresent != nil {
			if *targetRelease.RuntimeContract.ShellPresent {
				shellVal = "present"
			} else {
				shellVal = "absent"
			}
		}
		fmt.Fprintf(out, "Shell:              %s\n", shellVal)

		pkgManagerVal := "unknown"
		if targetRelease.RuntimeContract.PackageManagerPresent != nil {
			if *targetRelease.RuntimeContract.PackageManagerPresent {
				pkgManagerVal = "present"
			} else {
				pkgManagerVal = "absent"
			}
		}
		fmt.Fprintf(out, "Package Manager:    %s\n", pkgManagerVal)

		caCertVal := "unknown"
		if targetRelease.RuntimeContract.CACertificatesPresent != nil {
			if *targetRelease.RuntimeContract.CACertificatesPresent {
				caCertVal = "present"
			} else {
				caCertVal = "absent"
			}
		}
		fmt.Fprintf(out, "CA Certificates:    %s\n", caCertVal)

		timezoneVal := "unknown"
		if targetRelease.RuntimeContract.TimezoneDataPresent != nil {
			if *targetRelease.RuntimeContract.TimezoneDataPresent {
				timezoneVal = "present"
			} else {
				timezoneVal = "absent"
			}
		}
		fmt.Fprintf(out, "Timezone Data:      %s\n", timezoneVal)

		if targetRelease.RuntimeContract.DefaultEntrypoint != nil {
			fmt.Fprintf(out, "Default Entrypoint:  %s\n", *targetRelease.RuntimeContract.DefaultEntrypoint)
		} else {
			fmt.Fprintln(out, "Default Entrypoint:  none")
		}

		fmt.Fprintln(out, "\n--- Architectures & Payloads ---")
		for _, arch := range targetRelease.Architectures {
			fmt.Fprintf(out, "Platform:           linux/%s\n", arch.Arch)
			if arch.ImageDigest != nil {
				fmt.Fprintf(out, "  Digest:           %s\n", *arch.ImageDigest)
			}
			if arch.ImageSize != nil {
				fmt.Fprintf(out, "  Size:             %.2f MB\n", float64(*arch.ImageSize)/(1024*1024))
			}
			if arch.LayerCount != nil {
				fmt.Fprintf(out, "  Layers:           %d\n", *arch.LayerCount)
			}
			fmt.Fprintf(out, "  SBOM Packages:    %d\n", arch.SBOM.PackageCount)

			// Test status
			testStatus := "missing"
			if arch.TestResults != nil {
				testStatus = strings.ToLower(arch.TestResults.Status)
			}
			fmt.Fprintf(out, "  Smoke Tests:      %s\n", testStatus)

			// Vulnerability counts
			if arch.Vulnerabilities != nil {
				counts := arch.Vulnerabilities.CountsBySeverity
				fmt.Fprintf(out, "  Vulnerabilities:  critical=%d, high=%d, medium=%d, low=%d (Scanned At: %s)\n",
					counts.Critical, counts.High, counts.Medium, counts.Low, arch.Vulnerabilities.ScannedAt)
			} else {
				fmt.Fprintln(out, "  Vulnerabilities:  no scan results on record")
			}
		}

		// Supply chain evidence flags
		fmt.Fprintln(out, "\n--- Supply Chain Evidence ---")
		sigVal := "absent"
		if targetRelease.Evidence != nil && targetRelease.Evidence.Signature {
			sigVal = "present"
		}
		fmt.Fprintf(out, "Cosign Signature:   %s\n", sigVal)

		sbomVal := "absent"
		if targetRelease.Evidence != nil && targetRelease.Evidence.SBOM {
			sbomVal = "present (all architectures)"
		} else if targetRelease.Evidence != nil && targetRelease.Evidence.SBOMArchCount > 0 {
			sbomVal = fmt.Sprintf("incomplete (%d/%d architectures)", targetRelease.Evidence.SBOMArchCount, targetRelease.Evidence.ArchCount)
		}
		fmt.Fprintf(out, "SPDX SBOMs:         %s\n", sbomVal)

		provVal := "absent"
		if targetRelease.Evidence != nil && targetRelease.Evidence.Provenance {
			provVal = "present"
		}
		fmt.Fprintf(out, "SLSA Provenance:    %s\n", provVal)

		testEvVal := "absent"
		if targetRelease.Evidence != nil && targetRelease.Evidence.Tests {
			testEvVal = "passed (all architectures)"
		} else if targetRelease.Evidence != nil && targetRelease.Evidence.TestArchCount > 0 {
			testEvVal = fmt.Sprintf("failed or incomplete (%d/%d architectures passed)", targetRelease.Evidence.PassedTestArchCount, targetRelease.Evidence.ArchCount)
		}
		fmt.Fprintf(out, "Conformance Tests:  %s\n", testEvVal)

		// Exceptions Summary
		fmt.Fprintln(out, "\n--- Vulnerability Governance ---")
		fmt.Fprintf(out, "Total Exceptions:   %d (active=%d, expired=%d)\n",
			targetRelease.Exceptions.Total, targetRelease.Exceptions.Active, targetRelease.Exceptions.Expired)
		fmt.Fprintf(out, "Remediation State:  acceptedRisk=%d, noFixAvailable=%d, falsePositive=%d, inheritedFromBase=%d\n",
			targetRelease.Exceptions.AcceptedRisk, targetRelease.Exceptions.NoFixAvailable,
			targetRelease.Exceptions.FalsePositive, targetRelease.Exceptions.InheritedFromBase)

		// Release Assets
		fmt.Fprintln(out, "\n--- Release Assets ---")
		if targetRelease.AssetURLs.Provenance != nil && *targetRelease.AssetURLs.Provenance != "" {
			fmt.Fprintf(out, "SLSA Provenance:    %s\n", *targetRelease.AssetURLs.Provenance)
		}
		if len(targetRelease.AssetURLs.SBOM) > 0 {
			fmt.Fprintln(out, "SBOM Archives:")
			for arch, url := range targetRelease.AssetURLs.SBOM {
				fmt.Fprintf(out, "  %-6s            %s\n", arch, url)
			}
		}
		if len(targetRelease.AssetURLs.TestResults) > 0 {
			fmt.Fprintln(out, "Test Results:")
			for arch, url := range targetRelease.AssetURLs.TestResults {
				fmt.Fprintf(out, "  %-6s            %s\n", arch, url)
			}
		}
		if targetRelease.AssetURLs.Digest != nil && *targetRelease.AssetURLs.Digest != "" {
			fmt.Fprintf(out, "Manifest Digest:    %s\n", *targetRelease.AssetURLs.Digest)
		}
	}
	return nil
}

func serviceInspectPorts(ports []catalog.ServicePortInfo) string {
	if len(ports) == 0 {
		return "none"
	}
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		if port.Name != "" {
			out = append(out, fmt.Sprintf("%s:%d/%s", port.Name, port.Port, protocol))
			continue
		}
		out = append(out, fmt.Sprintf("%d/%s", port.Port, protocol))
	}
	return strings.Join(out, ", ")
}
