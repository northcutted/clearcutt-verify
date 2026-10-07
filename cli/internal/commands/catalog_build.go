package commands

import (
	"os"
	"path/filepath"

	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/spf13/cobra"
)

type catalogBuildFlags struct {
	config          string
	limit           int
	targets         string
	imagePrefix     string
	forceRefreshAll bool
	scanDepth       string
	scanAll         bool
	updateDB        bool
	coreDir         string
	lenientEvidence bool
	includeServices bool
}

var catalogBuildOpts catalogBuildFlags

func newCatalogBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Run the full catalog gather, enrich, scan, fold, and verify pipeline",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogBuildWithConfig(cmd.Flags().Changed("config"), cmd.Flags().Changed("limit"))
		},
	}
	cmd.Flags().StringVar(&catalogBuildOpts.config, "config", config.DefaultConfigPath, "ClearCutt fleet config used for owner/repo/registry/target defaults")
	cmd.Flags().IntVar(&catalogBuildOpts.limit, "limit", envIntValue("RELEASE_LIMIT", 10), "Maximum releases to inspect")
	cmd.Flags().StringVar(&catalogBuildOpts.targets, "targets", os.Getenv("CATALOG_TARGETS"), "Comma-separated target allowlist")
	cmd.Flags().StringVar(&catalogBuildOpts.imagePrefix, "image-prefix", "", "Image name prefix for catalog records and registry enrichment")
	cmd.Flags().BoolVar(&catalogBuildOpts.forceRefreshAll, "force-refresh-all", parseScanBool(os.Getenv("FORCE_REFRESH_ALL")), "Refresh enrichment and SBOMs for every release")
	cmd.Flags().StringVar(&catalogBuildOpts.scanDepth, "scan-depth", envOr("SCAN_TAG_DEPTH", "4"), "Newest cached tag count to scan")
	cmd.Flags().BoolVar(&catalogBuildOpts.scanAll, "scan-all", parseScanBool(os.Getenv("SCAN_ALL_TAGS")), "Scan every cached SBOM tag")
	cmd.Flags().BoolVar(&catalogBuildOpts.updateDB, "update-db", parseScanBool(os.Getenv("SCAN_UPDATE_DB")), "Refresh the local Grype vulnerability database before scanning")
	cmd.Flags().StringVar(&catalogBuildOpts.coreDir, "core-dir", "", "Optional Nix fleet core directory; when set, run scanner tooling through the pinned Nix dev shell")
	cmd.Flags().BoolVar(&catalogBuildOpts.lenientEvidence, "lenient-evidence", false, "Run verify catalog without requiring signature/provenance/tests")
	cmd.Flags().BoolVar(&catalogBuildOpts.includeServices, "include-services", false, "Include configured first-class service images from clearcutt.fleet.yaml")
	return cmd
}

func runCatalogBuild() error {
	return runCatalogBuildWithConfig(false, false)
}

func runCatalogBuildWithConfig(explicitConfig, limitChanged bool) error {
	catalogGatherOpts.config = catalogBuildOpts.config
	catalogGatherOpts.limit = catalogBuildOpts.limit
	catalogGatherOpts.targets = catalogBuildOpts.targets
	catalogGatherOpts.imagePrefix = catalogBuildOpts.imagePrefix
	catalogGatherOpts.forceRefreshAll = catalogBuildOpts.forceRefreshAll
	catalogGatherOpts.forceRefreshTags = os.Getenv("FORCE_REFRESH_TAGS")
	catalogGatherOpts.includeServices = catalogBuildOpts.includeServices
	if err := applyCatalogGatherConfig(catalogBuildOpts.config, explicitConfig, limitChanged); err != nil {
		return err
	}
	if err := runCatalogGather(); err != nil {
		return err
	}

	catalogEnrichOpts.config = catalogBuildOpts.config
	catalogEnrichOpts.limit = catalogGatherOpts.limit
	catalogEnrichOpts.owner = catalogGatherOpts.owner
	catalogEnrichOpts.repo = catalogGatherOpts.repo
	catalogEnrichOpts.registryBase = catalogGatherOpts.registryBase
	catalogEnrichOpts.imagePrefix = catalogGatherOpts.imagePrefix
	catalogEnrichOpts.targets = catalogGatherOpts.targets
	catalogEnrichOpts.forceRefreshAll = catalogBuildOpts.forceRefreshAll
	catalogEnrichOpts.forceRefreshTags = os.Getenv("FORCE_REFRESH_TAGS")
	catalogEnrichOpts.includeServices = catalogBuildOpts.includeServices
	if err := runCatalogEnrichWithConfig(explicitConfig, limitChanged); err != nil {
		return err
	}

	scanOpts.mode = "catalog"
	scanOpts.sbomDir = catalogGatherOpts.sbomCacheDir
	scanOpts.outDir = catalogGatherOpts.vulnDir
	scanOpts.depth = catalogBuildOpts.scanDepth
	scanOpts.tags = os.Getenv("SCAN_TAGS")
	scanOpts.all = catalogBuildOpts.scanAll || catalogBuildOpts.forceRefreshAll
	scanOpts.concurrency = 0
	scanOpts.updateDB = catalogBuildOpts.updateDB
	scanOpts.coreDir = catalogBuildOpts.coreDir
	if err := runScan(); err != nil {
		return err
	}

	// Second gather folds enrichment and vulnerability JSON into image records;
	// do not force SBOM downloads again because the first gather already populated
	// the cache for this build.
	catalogGatherOpts.forceRefreshAll = false
	catalogGatherOpts.forceRefreshTags = ""
	catalogGatherOpts.includeServices = catalogBuildOpts.includeServices
	if err := runCatalogGather(); err != nil {
		return err
	}
	if catalogBuildOpts.includeServices {
		cfg, err := config.Load(catalogBuildOpts.config)
		if err != nil {
			return err
		}
		outDir := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.outDir, GlobalOpts.CatalogPath, filepath.Join("site", "src", "data", "catalog"))
		if err := appendServiceCatalogRecords(outDir, cfg); err != nil {
			return err
		}
		if err := stampCatalogIndexMetadata(outDir); err != nil {
			return err
		}
	}
	outDir := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.outDir, GlobalOpts.CatalogPath, filepath.Join("site", "src", "data", "catalog"))
	if err := finalizeGeneratedCatalog(outDir); err != nil {
		return err
	}

	verifyCatalogOpts.lenientEvidence = catalogBuildOpts.lenientEvidence
	return runVerifyCatalog()
}
