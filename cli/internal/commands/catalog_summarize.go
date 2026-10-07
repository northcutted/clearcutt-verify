package commands

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type catalogSummarizeFlags struct {
	output string
}

var catalogSummarizeOpts catalogSummarizeFlags

type catalogSummaryReport struct {
	CatalogPath      string         `json:"catalogPath,omitempty"`
	GeneratedAt      string         `json:"generatedAt"`
	Owner            string         `json:"owner"`
	Repo             string         `json:"repo"`
	RepoURL          string         `json:"repoUrl"`
	RegistryBase     string         `json:"registryBase"`
	LatestTag        string         `json:"latestTag"`
	ImageCount       int            `json:"imageCount"`
	ReleaseCount     int            `json:"releaseCount"`
	SignedCount      int            `json:"signedCount"`
	ProvenanceCount  int            `json:"provenanceCount"`
	SBOMCount        int            `json:"sbomCount"`
	ScanCount        int            `json:"scanCount"`
	PassingCount     int            `json:"passingCount"`
	LifecycleCounts  map[string]int `json:"lifecycleCounts"`
	TierCounts       map[string]int `json:"tierCounts"`
	LanguageCounts   map[string]int `json:"languageCounts"`
	CriticalFindings int            `json:"criticalFindings"`
	HighFindings     int            `json:"highFindings"`
}

func newCatalogSummarizeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "summarize [catalog-dir]",
		Short: "Summarize catalog inventory and evidence coverage",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := GlobalOpts.CatalogPath
			if len(args) == 1 {
				path = args[0]
			}
			return runCatalogSummarize(path)
		},
	}
	cmd.Flags().StringVar(&catalogSummarizeOpts.output, "output", "", "Write summary JSON to this file")
	return cmd
}

func runCatalogSummarize(catalogPath string) error {
	summary, err := buildCatalogSummary(catalogPath)
	if err != nil {
		return err
	}
	if catalogSummarizeOpts.output != "" {
		if err := writeJSONFile(catalogSummarizeOpts.output, summary); err != nil {
			return err
		}
		fmt.Fprintf(out, "[catalog-summarize] wrote %s\n", catalogSummarizeOpts.output)
		return nil
	}
	return printCatalogSummary(summary)
}

func buildCatalogSummary(catalogPath string) (catalogSummaryReport, error) {
	index, err := catalog.LoadCatalogIndex(catalogPath)
	if err != nil {
		return catalogSummaryReport{}, err
	}
	if err := catalog.ValidateCatalogIndex(index); err != nil {
		return catalogSummaryReport{}, fmt.Errorf("catalog index validation failed: %w", err)
	}
	summary := catalogSummaryReport{
		CatalogPath:     catalogPath,
		GeneratedAt:     index.GeneratedAt,
		Owner:           index.Owner,
		Repo:            index.Repo,
		RepoURL:         index.RepoURL,
		RegistryBase:    index.RegistryBase,
		LatestTag:       index.LatestTag,
		ImageCount:      len(index.Images),
		ReleaseCount:    len(index.Releases),
		LifecycleCounts: map[string]int{},
		TierCounts:      map[string]int{},
		LanguageCounts:  map[string]int{},
	}
	for _, img := range index.Images {
		summary.LifecycleCounts[strings.ToLower(img.Lifecycle.Status)]++
		summary.TierCounts[strings.ToLower(img.Tier)]++
		summary.LanguageCounts[strings.ToLower(img.Language)]++
		if img.Signed {
			summary.SignedCount++
		}
		if img.Provenance {
			summary.ProvenanceCount++
		}
		if img.Passed {
			summary.PassingCount++
		}
		if img.Evidence != nil {
			if img.Evidence.SBOM {
				summary.SBOMCount++
			}
			if img.Evidence.Vulnerabilities {
				summary.ScanCount++
			}
		}
		if img.VulnSummary != nil {
			summary.CriticalFindings += img.VulnSummary.Critical
			summary.HighFindings += img.VulnSummary.High
		}
	}
	return summary, nil
}

func writeCatalogSummaryFile(catalogPath string) error {
	summary, err := buildCatalogSummary(catalogPath)
	if err != nil {
		return err
	}
	summary.CatalogPath = ""
	return writeJSONFile(filepath.Join(catalogPath, "summary.json"), summary)
}

func printCatalogSummary(summary catalogSummaryReport) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, summary)
	case "yaml", "yml":
		return output.PrintYAML(out, summary)
	default:
		fmt.Fprintf(out, "Catalog:        %s/%s\n", summary.Owner, summary.Repo)
		fmt.Fprintf(out, "Generated At:   %s\n", summary.GeneratedAt)
		fmt.Fprintf(out, "Latest Tag:     %s\n", summary.LatestTag)
		fmt.Fprintf(out, "Registry:       %s\n", summary.RegistryBase)
		fmt.Fprintf(out, "Images:         %d\n", summary.ImageCount)
		fmt.Fprintf(out, "Releases:       %d\n", summary.ReleaseCount)
		fmt.Fprintf(out, "Evidence:       signatures=%d provenance=%d sbom=%d scans=%d passing=%d\n",
			summary.SignedCount,
			summary.ProvenanceCount,
			summary.SBOMCount,
			summary.ScanCount,
			summary.PassingCount,
		)
		fmt.Fprintf(out, "Vulnerabilities: critical=%d high=%d\n", summary.CriticalFindings, summary.HighFindings)
		return nil
	}
}
