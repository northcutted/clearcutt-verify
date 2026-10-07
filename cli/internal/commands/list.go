package commands

import (
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type listFlags struct {
	runtime        string
	tier           string
	productionOnly bool
	lifecycle      string
}

var listOpts listFlags

// NewListCmd creates the Cobra list command.
func NewListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the images recorded in the catalog",
		Long:  `List all ClearCutt images in the catalog index with support for filters and format outputs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList()
		},
	}

	cmd.Flags().StringVar(&listOpts.runtime, "runtime", "", "Filter images by language/runtime (e.g., java, node, python)")
	cmd.Flags().StringVar(&listOpts.tier, "tier", "", "Filter images by tier (dev, slim, distroless)")
	cmd.Flags().BoolVar(&listOpts.productionOnly, "production-only", false, "Filter images to only those allowed in production")
	cmd.Flags().StringVar(&listOpts.lifecycle, "lifecycle", "", "Filter images by lifecycle status (active, preview, deprecated, experimental, eol, blocked)")

	return cmd
}

func runList() error {
	idx, err := catalog.LoadCatalogIndex(GlobalOpts.CatalogPath)
	if err != nil {
		return err
	}

	if err := catalog.ValidateCatalogIndex(idx); err != nil {
		return fmt.Errorf("catalog index validation failed: %w", err)
	}

	// Filter images
	var filtered []catalog.CatalogImageSummary
	for _, img := range idx.Images {
		if listOpts.runtime != "" && !strings.EqualFold(img.Language, listOpts.runtime) {
			continue
		}
		if listOpts.tier != "" && !strings.EqualFold(img.Tier, listOpts.tier) {
			continue
		}
		if listOpts.productionOnly && !img.Lifecycle.ProductionAllowed {
			continue
		}
		if listOpts.lifecycle != "" && !strings.EqualFold(img.Lifecycle.Status, listOpts.lifecycle) {
			continue
		}
		filtered = append(filtered, img)
	}

	// Format output
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, filtered)
	case "yaml", "yml":
		return output.PrintYAML(out, filtered)
	default:
		// Render the default table view.
		tp := output.NewTablePrinter(
			"IMAGE",
			"RUNTIME",
			"VERSION",
			"TIER",
			"LIFECYCLE",
			"PROD",
			"LATEST",
			"DIGEST",
			"ARCHES",
			"CRITICAL",
			"HIGH",
			"EVIDENCE",
		)

		for _, img := range filtered {
			// The latest manifest digest is denormalized into the index summary, so
			// rendering the table no longer requires reading every image record.
			digestStr := "N/A"
			if img.LatestManifestDigest != nil && *img.LatestManifestDigest != "" {
				digestStr = truncateDigest(*img.LatestManifestDigest)
			}

			// Format production allowed
			prodStr := "no"
			if img.Lifecycle.ProductionAllowed {
				prodStr = "yes"
			}

			// Format architectures
			archesStr := strings.Join(img.Architectures, ",")

			// Format vulnerability counts
			critCount := "0"
			highCount := "0"
			if img.VulnSummary != nil {
				critCount = fmt.Sprintf("%d", img.VulnSummary.Critical)
				highCount = fmt.Sprintf("%d", img.VulnSummary.High)
			}

			// Format compact evidence summary: sig,sbom,prov,tests,vulns
			var evs []string
			if img.Evidence != nil {
				if img.Evidence.Signature {
					evs = append(evs, "sig")
				}
				if img.Evidence.SBOM {
					evs = append(evs, "sbom")
				}
				if img.Evidence.Provenance {
					evs = append(evs, "prov")
				}
				if img.Evidence.Tests {
					evs = append(evs, "tests")
				}
				if img.Evidence.Vulnerabilities {
					evs = append(evs, "vulns")
				}
			}
			evidenceStr := strings.Join(evs, ",")
			if evidenceStr == "" {
				evidenceStr = "none"
			}

			tp.AddRow(
				img.ID,
				img.LanguageDisplay,
				img.LanguageVersion,
				img.Tier,
				img.Lifecycle.Status,
				prodStr,
				img.LatestTag,
				digestStr,
				archesStr,
				critCount,
				highCount,
				evidenceStr,
			)
		}

		return tp.Print(out)
	}
}

// truncateDigest shortens a manifest digest for table display while keeping the
// algorithm prefix readable (e.g. "sha256:1234567890ab...").
func truncateDigest(digest string) string {
	if strings.HasPrefix(digest, "sha256:") && len(digest) >= 19 {
		return digest[:19] + "..."
	}
	if len(digest) > 12 {
		return digest[:12] + "..."
	}
	return digest
}
