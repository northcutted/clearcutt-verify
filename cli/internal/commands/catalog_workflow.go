package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type catalogWorkflowFlags struct {
	configPath        string
	releaseLimit      string
	githubOutputPath  string
	vexOutputDir      string
	vexTag            string
	vexExceptionsFile string
}

var catalogWorkflowOpts catalogWorkflowFlags

type catalogWorkflowParams struct {
	ReleaseLimit int    `json:"releaseLimit"`
	ScanDepth    string `json:"scanDepth"`
}

type catalogVexAllResult struct {
	OutputDir string   `json:"outputDir"`
	Count     int      `json:"count"`
	Images    []string `json:"images"`
}

func newCatalogWorkflowParamsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workflow-params",
		Short: "Emit catalog publishing workflow parameters from clearcutt.yaml",
		Long: `Reads clearcutt.fleet.yaml and emits the catalog publishing parameters
used by GitHub Actions: release ingestion limit and vulnerability scan depth.
Use --github-output in workflows to append limit and scan_depth without jq.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolveRepoRootDefault(cmd, "fleet-config", &catalogWorkflowOpts.configPath)
			return runCatalogWorkflowParams()
		},
	}
	addConfigFlag(cmd, &catalogWorkflowOpts.configPath, "Path to the ClearCutt config")
	cmd.Flags().StringVar(&catalogWorkflowOpts.releaseLimit, "release-limit", "", "Optional workflow_dispatch release_limit override")
	cmd.Flags().StringVar(&catalogWorkflowOpts.githubOutputPath, "github-output", "", "Optional GITHUB_OUTPUT file to append limit and scan_depth")
	return cmd
}

func newCatalogVexAllCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vex-all",
		Short: "Generate OpenVEX documents for every image in a catalog",
		Long: `Loads the active catalog index and writes one OpenVEX JSON document per
image. This is the catalog-site workflow helper for publishing /vex/*.json
without making GitHub Actions parse catalog internals with jq.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogVexAll()
		},
	}
	cmd.Flags().StringVar(&catalogWorkflowOpts.vexOutputDir, "output-dir", filepath.Join("site", "public", "vex"), "Directory to write per-image OpenVEX JSON documents")
	cmd.Flags().StringVar(&catalogWorkflowOpts.vexTag, "tag", "", "Target release tag version for every image (defaults to each image's latest release)")
	cmd.Flags().StringVar(&catalogWorkflowOpts.vexExceptionsFile, "exceptions", "", "Path to local exceptions YAML triage governance file")
	return cmd
}

func runCatalogWorkflowParams() error {
	params, err := buildCatalogWorkflowParams(catalogWorkflowOpts.configPath, catalogWorkflowOpts.releaseLimit)
	if err != nil {
		return err
	}
	if strings.TrimSpace(catalogWorkflowOpts.githubOutputPath) != "" {
		if err := appendGitHubOutputs(catalogWorkflowOpts.githubOutputPath, map[string]string{
			"limit":      strconv.Itoa(params.ReleaseLimit),
			"scan_depth": params.ScanDepth,
		}); err != nil {
			return err
		}
	}
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, params)
	case "yaml", "yml":
		return output.PrintYAML(out, params)
	default:
		tp := output.NewTablePrinter("SETTING", "VALUE")
		tp.AddRow("releaseLimit", strconv.Itoa(params.ReleaseLimit))
		tp.AddRow("scanDepth", params.ScanDepth)
		return tp.Print(out)
	}
}

func buildCatalogWorkflowParams(configPath, releaseLimitOverride string) (catalogWorkflowParams, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return catalogWorkflowParams{}, fmt.Errorf("failed to load fleet config: %w", err)
	}
	limit := cfg.Catalog.ReleaseLimit
	if strings.TrimSpace(releaseLimitOverride) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(releaseLimitOverride))
		if err != nil || parsed < 1 {
			return catalogWorkflowParams{}, fmt.Errorf("--release-limit must be a positive integer when set")
		}
		limit = parsed
	}
	return catalogWorkflowParams{
		ReleaseLimit: limit,
		ScanDepth:    cfg.Catalog.ScanDepth,
	}, nil
}

func runCatalogVexAll() error {
	outputDir := strings.TrimSpace(catalogWorkflowOpts.vexOutputDir)
	if outputDir == "" {
		return fmt.Errorf("--output-dir is required")
	}
	result, err := generateOpenVEXForCatalog(GlobalOpts.CatalogPath, outputDir, catalogWorkflowOpts.vexTag, catalogWorkflowOpts.vexExceptionsFile)
	if err != nil {
		return err
	}
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, result)
	case "yaml", "yml":
		return output.PrintYAML(out, result)
	default:
		tp := output.NewTablePrinter("OUTPUT", "VALUE")
		tp.AddRow("outputDir", result.OutputDir)
		tp.AddRow("images", strconv.Itoa(result.Count))
		return tp.Print(out)
	}
}

func generateOpenVEXForCatalog(catalogPath, outputDir, tag, exceptionsFile string) (catalogVexAllResult, error) {
	index, err := catalog.LoadCatalogIndex(catalogPath)
	if err != nil {
		return catalogVexAllResult{}, err
	}
	ids := make([]string, 0, len(index.Images))
	seen := map[string]bool{}
	for _, image := range index.Images {
		id := strings.TrimSpace(image.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return catalogVexAllResult{}, fmt.Errorf("create OpenVEX output directory: %w", err)
	}
	oldCatalogPath := GlobalOpts.CatalogPath
	GlobalOpts.CatalogPath = catalogPath
	defer func() { GlobalOpts.CatalogPath = oldCatalogPath }()
	for _, id := range ids {
		doc, err := buildOpenVEXDocument(id, tag, exceptionsFile, time.Now().UTC())
		if err != nil {
			return catalogVexAllResult{}, err
		}
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return catalogVexAllResult{}, fmt.Errorf("serialize OpenVEX for %s: %w", id, err)
		}
		path := filepath.Join(outputDir, id+".json")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			return catalogVexAllResult{}, fmt.Errorf("write OpenVEX for %s: %w", id, err)
		}
	}
	return catalogVexAllResult{OutputDir: outputDir, Count: len(ids), Images: ids}, nil
}
