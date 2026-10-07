package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/northcutted/clearcutt-verify/internal/evidence"
	"github.com/spf13/cobra"
)

type catalogGatherFlags struct {
	evidenceSource   string
	config           string
	imagesFile       string
	limit            int
	owner            string
	repo             string
	registryBase     string
	imagePrefix      string
	outDir           string
	enrichmentDir    string
	sbomCacheDir     string
	vulnDir          string
	targets          string
	forceRefreshAll  bool
	forceRefreshTags string
	generatedAt      string
	pretty           bool
	includeServices  bool
}

var catalogGatherOpts catalogGatherFlags

func NewCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Build and enrich the site catalog data",
	}
	cmd.AddCommand(newCatalogGenerateCmd())
	cmd.AddCommand(newCatalogGatherCmd())
	cmd.AddCommand(newCatalogEnrichCmd())
	cmd.AddCommand(newCatalogBuildCmd())
	cmd.AddCommand(newCatalogWorkflowParamsCmd())
	cmd.AddCommand(newCatalogVexAllCmd())
	cmd.AddCommand(newCatalogValidateCmd())
	cmd.AddCommand(newCatalogSummarizeCmd())
	cmd.AddCommand(newCatalogInspectCmd())
	cmd.AddCommand(newCatalogDiffCmd())
	cmd.AddCommand(newCatalogSiteCmd())
	return cmd
}

func newCatalogGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate portable catalog JSON from ClearCutt release evidence",
		Long: `Generate the site-compatible catalog JSON used by ClearCutt discovery
commands and Astro catalog pages. This first public generator path reuses the
ClearCutt-native GitHub release evidence pipeline by default. Pass --images to
build a minimal Nix-free catalog from a generic OCI image inventory; unavailable
evidence channels are preserved as explicit missing-evidence states.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogGenerate(cmd)
		},
	}
	addCatalogGatherFlags(cmd)
	cmd.Flags().StringVar(&catalogGatherOpts.config, "config", config.DefaultConfigPath, "ClearCutt fleet config used for owner/repo/registry/target defaults")
	cmd.Flags().StringVar(&catalogGatherOpts.imagesFile, "images", "", "Generic OCI images.yaml inventory to convert into catalog data")
	cmd.Flags().StringVar(&catalogGatherOpts.outDir, "output", "", "Catalog output directory")
	cmd.Flags().BoolVar(&catalogGatherOpts.pretty, "pretty", true, "Write indented JSON output")
	cmd.Flags().BoolVar(&catalogGatherOpts.includeServices, "include-services", false, "Include configured first-class service images from clearcutt.fleet.yaml")
	return cmd
}

func newCatalogGatherCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gather",
		Short: "Gather GitHub release assets into catalog image records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogGather()
		},
	}
	addCatalogGatherFlags(cmd)
	return cmd
}

func addCatalogGatherFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&catalogGatherOpts.limit, "limit", envIntValue("RELEASE_LIMIT", 10), "Maximum non-draft releases to inspect")
	cmd.Flags().StringVar(&catalogGatherOpts.evidenceSource, "evidence-source", "github", "Where release evidence lives: github (release assets, default) or registry (OCI referrers; works on any registry)")
	cmd.Flags().StringVar(&catalogGatherOpts.owner, "owner", os.Getenv("GH_OWNER"), "GitHub owner (defaults to GH_OWNER, GITHUB_REPOSITORY, fleet config, or git remote)")
	cmd.Flags().StringVar(&catalogGatherOpts.repo, "repo", os.Getenv("GH_REPO"), "GitHub repository (defaults to GH_REPO, GITHUB_REPOSITORY, fleet config, or git remote)")
	cmd.Flags().StringVar(&catalogGatherOpts.registryBase, "registry-base", "", "Registry namespace (defaults to fleet config or ghcr.io/<owner>/<repo>)")
	cmd.Flags().StringVar(&catalogGatherOpts.imagePrefix, "image-prefix", "", "Image name prefix for catalog records (defaults to fleet config registry.imagePrefix or \"clearcutt\")")
	cmd.Flags().StringVar(&catalogGatherOpts.outDir, "out-dir", "", "Catalog output directory (defaults to --catalog)")
	cmd.Flags().StringVar(&catalogGatherOpts.enrichmentDir, "enrichment-dir", envOr("ENRICHMENT_DIR", filepath.Join("site", "src", "data", "enrichment")), "Directory of registry enrichment JSON")
	cmd.Flags().StringVar(&catalogGatherOpts.sbomCacheDir, "sbom-cache-dir", envOr("SBOM_CACHE_DIR", filepath.Join("site", "src", "data", "sboms")), "Directory to cache downloaded SBOM assets")
	cmd.Flags().StringVar(&catalogGatherOpts.vulnDir, "vuln-dir", envOr("VULN_DIR", filepath.Join("site", "src", "data", "vulnerabilities")), "Directory of vulnerability scan JSON")
	cmd.Flags().StringVar(&catalogGatherOpts.targets, "targets", os.Getenv("CATALOG_TARGETS"), "Comma-separated target allowlist")
	cmd.Flags().BoolVar(&catalogGatherOpts.forceRefreshAll, "force-refresh-all", parseScanBool(os.Getenv("FORCE_REFRESH_ALL")), "Refresh every release asset instead of reusing the SBOM cache")
	cmd.Flags().StringVar(&catalogGatherOpts.forceRefreshTags, "force-refresh-tags", os.Getenv("FORCE_REFRESH_TAGS"), "Comma-separated release tags to refresh")
	cmd.Flags().StringVar(&catalogGatherOpts.generatedAt, "generated-at", "", "Override index generatedAt timestamp (tests/reproducibility)")
}

func runCatalogGenerate(cmd *cobra.Command) error {
	return runCatalogGenerateWithConfig(cmd.Flags().Changed("config"), cmd.Flags().Changed("limit"))
}

func runCatalogGenerateWithConfig(explicitConfig, limitChanged bool) error {
	if catalogGatherOpts.imagesFile != "" {
		return runCatalogGenerateFromImages()
	}
	if err := applyCatalogGatherConfig(catalogGatherOpts.config, explicitConfig, limitChanged); err != nil {
		return err
	}
	if catalogGatherOpts.outDir != "" {
		GlobalOpts.CatalogPath = catalogGatherOpts.outDir
	}
	if err := runCatalogGather(); err != nil {
		return err
	}
	outDir := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.outDir, GlobalOpts.CatalogPath, filepath.Join("site", "src", "data", "catalog"))
	if catalogGatherOpts.includeServices {
		cfg, err := config.Load(catalogGatherOpts.config)
		if err != nil {
			return fmt.Errorf("failed to load service fleet config: %w", err)
		}
		if err := appendServiceCatalogRecords(outDir, cfg); err != nil {
			return err
		}
	}
	return finalizeGeneratedCatalog(outDir)
}

func applyCatalogGatherConfig(configPath string, explicitConfig, limitChanged bool) error {
	if configPath == "" {
		return nil
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		if explicitConfig || !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if catalogGatherOpts.owner == "" {
		catalogGatherOpts.owner = cfg.Registry.Owner
	}
	if catalogGatherOpts.repo == "" {
		catalogGatherOpts.repo = cfg.Registry.Repository
	}
	if catalogGatherOpts.registryBase == "" {
		catalogGatherOpts.registryBase = cfg.RegistryBase()
	}
	if catalogGatherOpts.imagePrefix == "" {
		catalogGatherOpts.imagePrefix = cfg.Registry.ImagePrefix
	}
	if catalogGatherOpts.targets == "" {
		catalogGatherOpts.targets = catalogTargets(cfg)
	}
	if !limitChanged && cfg.Catalog.ReleaseLimit > 0 {
		catalogGatherOpts.limit = cfg.Catalog.ReleaseLimit
	}
	return nil
}

func finalizeGeneratedCatalog(outDir string) error {
	if err := stampCatalogIndexMetadata(outDir); err != nil {
		return err
	}
	if err := removeStaleImageRecords(outDir); err != nil {
		return err
	}
	if err := ensureRawEvidenceDirs(outDir); err != nil {
		return err
	}
	if err := writeCatalogSummaryFile(outDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "[generate] wrote summary.json\n")
	if err := writeEvidenceManifestFile(outDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "[generate] wrote %s\n", evidenceManifestFilename)
	if err := writeCatalogSchemaFiles(outDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "[generate] wrote schemas/\n")
	return nil
}

func removeStaleImageRecords(outDir string) error {
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, image := range index.Images {
		expected[image.ID] = true
	}
	imagesDir := filepath.Join(outDir, "images")
	entries, err := os.ReadDir(imagesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if expected[id] {
			continue
		}
		if err := os.Remove(filepath.Join(imagesDir, entry.Name())); err != nil {
			return err
		}
		fmt.Fprintf(out, "[generate] removed stale image record %s\n", entry.Name())
	}
	return nil
}

func ensureRawEvidenceDirs(outDir string) error {
	for _, rel := range []string{
		filepath.Join("raw", "sbom"),
		filepath.Join("raw", "provenance"),
		filepath.Join("raw", "scans"),
		filepath.Join("raw", "test-results"),
	} {
		if err := os.MkdirAll(filepath.Join(outDir, rel), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// generatorIdentity resolves the version and commit stamped into generated
// catalog indexes. The ldflags-injected Version always wins; the commit falls
// back to the VCS metadata Go embeds into binaries built from a git checkout,
// so a plain `go build` still records real provenance.
func generatorIdentity() (version, commit string) {
	info, _ := debug.ReadBuildInfo()
	return generatorIdentityFromBuildInfo(Version, info)
}

func generatorIdentityFromBuildInfo(version string, info *debug.BuildInfo) (string, string) {
	commit := "unknown"
	if info != nil {
		revision := ""
		modified := false
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
		if revision != "" {
			commit = revision
			if modified {
				commit += "-dirty"
			}
		}
	}
	return catalogbuild.FirstNonEmptyStr(version, "dev"), commit
}

func stampCatalogIndexMetadata(outDir string) error {
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		return err
	}
	generatorVersion, generatorCommit := generatorIdentity()
	index.Generator = &catalog.CatalogGenerator{
		Name:    "clearcutt",
		Version: generatorVersion,
		Commit:  generatorCommit,
	}
	index.Source = &catalog.CatalogSource{
		Owner:        index.Owner,
		Repo:         index.Repo,
		RepoURL:      index.RepoURL,
		RegistryBase: index.RegistryBase,
	}
	index.Summary = catalogIndexSummary(index)
	return writeJSONFile(filepath.Join(outDir, "index.json"), index)
}

func catalogIndexSummary(index *catalog.CatalogIndex) *catalog.CatalogSummary {
	if index == nil {
		return nil
	}
	summary := &catalog.CatalogSummary{
		ImageCount:   len(index.Images),
		ReleaseCount: len(index.Releases),
	}
	for _, img := range index.Images {
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
	}
	return summary
}

func catalogTargets(cfg config.Config) string {
	targets := []string{}
	for _, language := range cfg.Matrix.Languages {
		for _, tier := range cfg.Matrix.Tiers {
			targets = append(targets, language+"-"+tier)
		}
	}
	return strings.Join(targets, ",")
}

func appendFleetServiceTargets(targets string, cfg config.Config) string {
	seen := map[string]bool{}
	out := []string{}
	for _, target := range strings.Split(targets, ",") {
		target = strings.TrimSpace(target)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	for _, service := range cfg.Services {
		id := strings.TrimSpace(service.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return strings.Join(out, ",")
}

func appendServiceCatalogRecords(outDir string, cfg config.Config) error {
	if len(cfg.Services) == 0 {
		return nil
	}
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		return err
	}
	generatedAt := index.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		index.GeneratedAt = generatedAt
	}
	latestTag := catalogbuild.FirstNonEmptyStr(index.LatestTag, "preview")
	if index.LatestTag == "" {
		index.LatestTag = latestTag
	}

	byID := map[string]int{}
	for i, img := range index.Images {
		byID[img.ID] = i
	}
	for _, service := range cfg.Services {
		service, _ = cfg.ServiceInfo(service.ID)
		record := serviceCatalogRecord(cfg, service, latestTag, generatedAt)
		if existing, err := catalog.LoadImageRecord(outDir, service.ID); err == nil && len(existing.Releases) > 0 {
			record = serviceCatalogRecordFromExisting(cfg, service, *existing)
		}
		if err := writeJSONFile(filepath.Join(outDir, "images", service.ID+".json"), record); err != nil {
			return err
		}
		summary := serviceCatalogSummary(record)
		if idx, ok := byID[summary.ID]; ok {
			index.Images[idx] = summary
		} else {
			byID[summary.ID] = len(index.Images)
			index.Images = append(index.Images, summary)
		}
		fmt.Fprintf(out, "[generate] wrote service %s\n", service.ID)
	}
	index.SchemaVersion = catalog.CatalogIndexSchemaVersionV2
	// The v2 index schema requires kind on every image summary; pre-existing
	// runtime summaries never carry one, so default them explicitly.
	for i := range index.Images {
		if index.Images[i].Kind == "" {
			index.Images[i].Kind = "runtime"
		}
	}
	ensureServiceTierEntry(index)
	return writeJSONFile(filepath.Join(outDir, "index.json"), index)
}

// ensureServiceTierEntry appends the service tier to the index tier list when
// it is missing. Gather-built indexes already carry it (catalogbuild.tierList
// adds it whenever service images are present), but this generate path can
// synthesize service summaries into an index whose gather pass saw none.
func ensureServiceTierEntry(index *catalog.CatalogIndex) {
	for _, tier := range index.Tiers {
		if tier.ID == "service" {
			return
		}
	}
	index.Tiers = append(index.Tiers, catalog.TierInfo{ID: "service", Name: "Service", Blurb: "Platform-owned service image"})
}

func serviceCatalogRecordFromExisting(cfg config.Config, service config.ServiceImage, existing catalog.ImageRecord) catalog.ImageRecord {
	fallback := serviceCatalogRecord(cfg, service, "", "")
	existing.SchemaVersion = catalog.ImageRecordSchemaVersionV2
	existing.ID = service.ID
	existing.Kind = "service"
	existing.Language = fallback.Language
	existing.Tier = fallback.Tier
	existing.Registry = fallback.Registry
	existing.ImageName = fallback.ImageName
	existing.FullName = fallback.FullName
	existing.Lifecycle = fallback.Lifecycle
	existing.RuntimeContract = fallback.RuntimeContract
	serviceInfo := serviceCatalogInfo(service)
	existing.Service = &serviceInfo
	for i := range existing.Releases {
		existing.Releases[i].Lifecycle = fallback.Lifecycle
		existing.Releases[i].RuntimeContract = fallback.RuntimeContract
		if existing.Releases[i].Evidence == nil {
			evidence := serviceEvidenceSummary(existing.Releases[i])
			existing.Releases[i].Evidence = &evidence
		}
	}
	return existing
}

func serviceCatalogRecord(cfg config.Config, service config.ServiceImage, latestTag, generatedAt string) catalog.ImageRecord {
	lifecycle := serviceCatalogLifecycle(service)
	runtimeContract := serviceCatalogRuntimeContract(service)
	serviceInfo := serviceCatalogInfo(service)
	imageName := cfg.Registry.ImagePrefix + "-" + strings.ToLower(service.ID)
	fullName := strings.TrimRight(cfg.RegistryBase(), "/") + "/" + imageName
	evidence := catalog.EvidenceSummary{}
	return catalog.ImageRecord{
		SchemaVersion:   catalog.ImageRecordSchemaVersionV2,
		ID:              service.ID,
		Kind:            "service",
		Language:        catalog.LanguageInfo{ID: "service", DisplayName: "Service", Version: service.Version},
		Tier:            catalog.TierInfo{ID: "service", Name: "Service", Blurb: "Platform-owned service image"},
		Registry:        cfg.RegistryBase(),
		ImageName:       imageName,
		FullName:        fullName,
		Lifecycle:       lifecycle,
		RuntimeContract: runtimeContract,
		Service:         &serviceInfo,
		Releases: []catalog.ReleaseEntry{{
			Tag:             latestTag,
			PublishedAt:     generatedAt,
			IsLatest:        true,
			Architectures:   []catalog.ArchPayload{},
			Attestations:    []catalog.AttestationEntry{},
			AssetURLs:       catalog.AssetURLs{SBOM: map[string]string{}, TestResults: map[string]string{}},
			Evidence:        &evidence,
			Lifecycle:       lifecycle,
			RuntimeContract: runtimeContract,
			Exceptions:      catalog.ExceptionSummary{},
		}},
	}
}

func serviceCatalogSummary(record catalog.ImageRecord) catalog.CatalogImageSummary {
	latest := record.Releases[0]
	evidence := serviceEvidenceSummary(latest)
	if latest.Evidence != nil {
		evidence = *latest.Evidence
	}
	architectures := make([]string, 0, len(latest.Architectures))
	totalPackages := 0
	passed := len(latest.Architectures) > 0
	for _, arch := range latest.Architectures {
		architectures = append(architectures, arch.Arch)
		totalPackages += arch.SBOM.PackageCount
		if arch.TestResults == nil || !catalog.TestResultStatusSatisfiesPolicy(arch.TestResults.Status, latest.Lifecycle.ProductionAllowed, latest.RuntimeContract.ProductionTier) {
			passed = false
		}
	}
	avgPackageCount := 0
	if len(latest.Architectures) > 0 {
		avgPackageCount = (totalPackages + len(latest.Architectures)/2) / len(latest.Architectures)
	}
	return catalog.CatalogImageSummary{
		ID:                   record.ID,
		Kind:                 "service",
		Language:             record.Language.ID,
		LanguageDisplay:      record.Language.DisplayName,
		LanguageVersion:      record.Language.Version,
		Tier:                 record.Tier.ID,
		LatestTag:            latest.Tag,
		LatestManifestDigest: latest.ManifestDigest,
		LatestPackageCount:   avgPackageCount,
		Architectures:        architectures,
		Signed:               evidence.Signature,
		Provenance:           evidence.Provenance,
		Evidence:             &evidence,
		Passed:               passed,
		VulnSummary:          serviceVulnSummary(latest),
		Lifecycle:            record.Lifecycle,
		RuntimeContract:      record.RuntimeContract,
		Service:              record.Service,
	}
}

func serviceVulnSummary(release catalog.ReleaseEntry) *catalog.VulnSummary {
	distinct := map[string]catalog.FindingInfo{}
	var scannedAt *string
	for _, arch := range release.Architectures {
		if arch.Vulnerabilities == nil {
			continue
		}
		if arch.Vulnerabilities.ScannedAt != "" && (scannedAt == nil || arch.Vulnerabilities.ScannedAt > *scannedAt) {
			value := arch.Vulnerabilities.ScannedAt
			scannedAt = &value
		}
		for _, finding := range arch.Vulnerabilities.Findings {
			key := finding.ID + "::" + finding.PackageName + "::" + finding.PackageVersion
			if _, ok := distinct[key]; !ok {
				distinct[key] = finding
			}
		}
	}
	if scannedAt == nil && len(distinct) == 0 {
		return nil
	}
	remediation := catalog.RemediationCounts{}
	summary := &catalog.VulnSummary{ScannedAt: scannedAt, Remediation: &remediation}
	for _, finding := range distinct {
		severity := strings.ToLower(finding.Severity)
		switch severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
		if severity == "critical" || severity == "high" {
			switch serviceRemediationBucket(serviceRemediationReason(finding)) {
			case "eligible":
				summary.Remediation.Eligible++
			case "baseLayer":
				summary.Remediation.BaseLayer++
			case "noFixedVersion":
				summary.Remediation.NoFixedVersion++
			case "belowPriorityThreshold":
				summary.Remediation.BelowPriorityThreshold++
			default:
				summary.Remediation.OtherDeferred++
			}
		}
	}
	return summary
}

func serviceRemediationReason(finding catalog.FindingInfo) string {
	if finding.Remediation != nil && finding.Remediation.Reason != "" {
		return finding.Remediation.Reason
	}
	severity := strings.ToLower(catalogbuild.FirstNonEmptyStr(finding.Severity, "Unknown"))
	layer := catalogbuild.FirstNonEmptyStr(finding.Layer, "base")
	switch {
	case layer != "runtime":
		return "base_layer"
	case severity != "critical" && severity != "high":
		return "below_priority_threshold"
	case finding.FixedIn == nil || *finding.FixedIn == "":
		return "no_fixed_version"
	default:
		return "fix_available"
	}
}

func serviceRemediationBucket(reason string) string {
	switch reason {
	case "fix_available":
		return "eligible"
	case "base_layer":
		return "baseLayer"
	case "no_fixed_version":
		return "noFixedVersion"
	case "below_priority_threshold":
		return "belowPriorityThreshold"
	default:
		return "otherDeferred"
	}
}

func serviceEvidenceSummary(release catalog.ReleaseEntry) catalog.EvidenceSummary {
	archCount := len(release.Architectures)
	var sbomArch, testArch, passedTestArch, vulnArch int
	for _, arch := range release.Architectures {
		if arch.SBOM.PackageCount > 0 {
			sbomArch++
		}
		if arch.TestResults != nil {
			testArch++
			if catalog.TestResultStatusSatisfiesPolicy(arch.TestResults.Status, release.Lifecycle.ProductionAllowed, release.RuntimeContract.ProductionTier) {
				passedTestArch++
			}
		}
		if arch.Vulnerabilities != nil {
			vulnArch++
		}
	}
	evidence := catalog.EvidenceSummary{
		Signature:              release.Signature != nil && release.Signature.CosignBundlePresent,
		Provenance:             release.Provenance != nil,
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

func serviceCatalogLifecycle(service config.ServiceImage) catalog.Lifecycle {
	return catalog.Lifecycle{
		Status:            catalogbuild.FirstNonEmptyStr(service.Lifecycle.Status, "preview"),
		Support:           catalogbuild.FirstNonEmptyStr(service.Lifecycle.Support, "current"),
		ProductionAllowed: service.ProductionAllowed,
	}
}

func serviceCatalogBuildLifecycle(service config.ServiceImage) catalogbuild.Lifecycle {
	lifecycle := serviceCatalogLifecycle(service)
	return catalogbuild.Lifecycle{
		Status:            lifecycle.Status,
		Support:           lifecycle.Support,
		ProductionAllowed: lifecycle.ProductionAllowed,
		DeprecatedAt:      lifecycle.DeprecatedAt,
		EOLAt:             lifecycle.EOLAt,
		Reason:            lifecycle.Reason,
	}
}

func serviceCatalogRuntimeContract(service config.ServiceImage) catalog.RuntimeContract {
	user := "10001:10001"
	workingDir := "/app"
	shellPresent := service.Template == "postgres"
	packageManagerPresent := false
	caPresent := true
	timezonePresent := false
	productionTier := false
	defaultEntrypoint := serviceDefaultEntrypoint(service)
	return catalog.RuntimeContract{
		User:                  &user,
		WorkingDir:            &workingDir,
		ShellPresent:          &shellPresent,
		PackageManagerPresent: &packageManagerPresent,
		CACertificatesPresent: &caPresent,
		TimezoneDataPresent:   &timezonePresent,
		DefaultEntrypoint:     catalogbuild.PtrIfNotEmpty(defaultEntrypoint),
		ProductionTier:        productionTier,
	}
}

func serviceCatalogBuildRuntimeContract(service config.ServiceImage) catalogbuild.RuntimeContract {
	runtimeContract := serviceCatalogRuntimeContract(service)
	out := catalogbuild.RuntimeContract{
		ProductionTier: runtimeContract.ProductionTier,
	}
	if runtimeContract.User != nil {
		out.User = *runtimeContract.User
	}
	if runtimeContract.WorkingDir != nil {
		out.WorkingDir = *runtimeContract.WorkingDir
	}
	if runtimeContract.ShellPresent != nil {
		out.ShellPresent = *runtimeContract.ShellPresent
	}
	if runtimeContract.PackageManagerPresent != nil {
		out.PackageManagerPresent = *runtimeContract.PackageManagerPresent
	}
	if runtimeContract.CACertificatesPresent != nil {
		out.CACertificatesPresent = *runtimeContract.CACertificatesPresent
	}
	if runtimeContract.TimezoneDataPresent != nil {
		out.TimezoneDataPresent = *runtimeContract.TimezoneDataPresent
	}
	out.DefaultEntrypoint = runtimeContract.DefaultEntrypoint
	return out
}

func serviceDefaultEntrypoint(service config.ServiceImage) string {
	if len(service.Entrypoint) == 0 {
		return ""
	}
	parts := make([]string, 0, len(service.Entrypoint))
	for _, entry := range service.Entrypoint {
		if strings.HasPrefix(entry, "/") {
			parts = append(parts, entry)
			continue
		}
		parts = append(parts, "/bin/"+entry)
	}
	return strings.Join(parts, " ")
}

func serviceCatalogInfo(service config.ServiceImage) catalog.ServiceInfo {
	return catalog.ServiceInfo{
		Template:    service.Template,
		Version:     service.Version,
		Ports:       serviceCatalogPorts(service.Ports),
		Stateful:    service.Stateful,
		DataDirs:    append([]string(nil), service.DataDirs...),
		Smoke:       append([]string(nil), service.Smoke...),
		SmokeStatus: serviceSmokeStatus(service),
	}
}

func serviceCatalogPorts(ports []config.ServicePort) []catalog.ServicePortInfo {
	out := make([]catalog.ServicePortInfo, 0, len(ports))
	for _, port := range ports {
		out = append(out, catalog.ServicePortInfo{
			Name:     port.Name,
			Port:     port.Port,
			Protocol: catalogbuild.FirstNonEmptyStr(port.Protocol, "tcp"),
		})
	}
	return out
}

func serviceSmokeStatus(service config.ServiceImage) string {
	if len(service.Smoke) == 0 {
		return "missing"
	}
	return "configured"
}

func runCatalogGather() error {
	owner, repo, err := detectCatalogRepo(catalogGatherOpts.owner, catalogGatherOpts.repo)
	if err != nil {
		return err
	}
	registryBase := catalogGatherOpts.registryBase
	if registryBase == "" {
		registryBase = "ghcr.io/" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	}
	outDir := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.outDir, GlobalOpts.CatalogPath, filepath.Join("site", "src", "data", "catalog"))
	imgDir := filepath.Join(outDir, "images")
	if err := os.MkdirAll(imgDir, 0o755); err != nil {
		return err
	}

	source, err := resolveReleaseSource(owner, repo, registryBase)
	if err != nil {
		return err
	}
	releases, err := source.ListReleases(catalogGatherOpts.limit)
	if err != nil {
		return err
	}
	generatedAt := catalogGatherOpts.generatedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if len(releases) == 0 {
		ok, err := catalogbuild.RebuildIndexFromExistingImages(owner, repo, registryBase, outDir, catalogGatherOpts.vulnDir, generatedAt)
		if err != nil {
			return err
		}
		if ok {
			if err := stampCatalogIndexMetadata(outDir); err != nil {
				return err
			}
			fmt.Fprintln(out, "[gather] rebuilt index.json from existing image records")
			return nil
		}
		empty := catalogbuild.BuildIndex(owner, repo, registryBase, generatedAt, nil, nil)
		if err := writeJSONFile(filepath.Join(outDir, "index.json"), empty); err != nil {
			return err
		}
		return stampCatalogIndexMetadata(outDir)
	}

	refreshSet := catalogbuild.RefreshTagSet(releases, catalogGatherOpts.forceRefreshAll, catalogGatherOpts.forceRefreshTags)
	targets := catalogbuild.Targets(catalogGatherOpts.targets)
	images := []catalogbuild.ImageRecord{}
	for _, target := range targets {
		rec, err := catalogbuild.BuildImageRecord(target, releases, refreshSet, catalogbuild.BuildOptions{
			RegistryBase:  registryBase,
			ImagePrefix:   catalogGatherOpts.imagePrefix,
			SBOMCacheDir:  catalogGatherOpts.sbomCacheDir,
			EnrichmentDir: catalogGatherOpts.enrichmentDir,
			VulnDir:       catalogGatherOpts.vulnDir,
			Source:        source,
		})
		if err != nil {
			fmt.Fprintf(errOut, "[gather] %s: %v\n", target, err)
			continue
		}
		if rec == nil {
			continue
		}
		if err := writeJSONFile(filepath.Join(imgDir, target+".json"), rec); err != nil {
			return err
		}
		images = append(images, *rec)
		fmt.Fprintf(out, "[gather] wrote %s (%d releases)\n", target, len(rec.Releases))
	}
	if catalogGatherOpts.includeServices {
		cfg, err := config.Load(catalogGatherOpts.config)
		if err != nil {
			return fmt.Errorf("failed to load service fleet config: %w", err)
		}
		for _, service := range cfg.Services {
			service, _ = cfg.ServiceInfo(service.ID)
			info := serviceCatalogInfo(service)
			rec, err := catalogbuild.BuildServiceImageRecord(service.ID, info, serviceCatalogBuildLifecycle(service), serviceCatalogBuildRuntimeContract(service), releases, refreshSet, catalogbuild.BuildOptions{
				RegistryBase:  registryBase,
				ImagePrefix:   catalogGatherOpts.imagePrefix,
				SBOMCacheDir:  catalogGatherOpts.sbomCacheDir,
				EnrichmentDir: catalogGatherOpts.enrichmentDir,
				VulnDir:       catalogGatherOpts.vulnDir,
				Source:        source,
			})
			if err != nil {
				fmt.Fprintf(errOut, "[gather] service %s: %v\n", service.ID, err)
				continue
			}
			if rec == nil {
				continue
			}
			if err := writeJSONFile(filepath.Join(imgDir, service.ID+".json"), rec); err != nil {
				return err
			}
			images = append(images, *rec)
			fmt.Fprintf(out, "[gather] wrote service %s (%d releases)\n", service.ID, len(rec.Releases))
		}
	}
	index := catalogbuild.BuildIndex(owner, repo, registryBase, generatedAt, releases, images)
	if err := writeJSONFile(filepath.Join(outDir, "index.json"), index); err != nil {
		return err
	}
	if err := stampCatalogIndexMetadata(outDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "[gather] wrote index.json with %d images\n", len(index.Images))
	return nil
}

// resolveReleaseSource picks where release evidence is read from.
//
// The catalog builder never knew: it consumes a two-method ReleaseSource, which
// is why swapping the control plane costs an implementation rather than a
// rewrite. "registry" reads evidence attached to image digests via OCI
// referrers and works on any registry; "github" reads GitHub release assets.
//
// THE DEFAULT IS GITHUB, on purpose. Registry-native evidence is where this is
// going, but defaulting to it would silently repoint every existing fork at a
// registry that does not have their evidence yet — turning an upgrade into an
// outage and a catalog into a list of empty releases. Switching planes is a
// migration, so it is opt-in.
//
// The first version of this defaulted to the registry whenever a registry base
// was configured, which is almost always, and three offline tests immediately
// started reaching for ghcr.io. That was the behaviour change arriving
// unannounced, caught by tests rather than by users.
func resolveReleaseSource(owner, repo, registryBase string) (catalogbuild.ReleaseSource, error) {
	mode := strings.ToLower(strings.TrimSpace(catalogGatherOpts.evidenceSource))
	if mode == "" {
		mode = "github"
	}
	switch mode {
	case "github":
		return newReleaseSource(owner, repo, os.Getenv("GITHUB_TOKEN")), nil
	case "registry":
		if strings.TrimSpace(registryBase) == "" {
			return nil, fmt.Errorf("--evidence-source=registry needs a registry base; set registry.host/owner/repository in the fleet config or pass --registry-base")
		}
		return evidence.NewReleaseSource(evidence.NewClient(), registryBase), nil
	default:
		return nil, fmt.Errorf("unknown --evidence-source %q; want github or registry", catalogGatherOpts.evidenceSource)
	}
}

// newReleaseSource builds the GitHub release source. It is a package var so
// tests can inject an offline fake and exercise the full gather-to-index path
// without touching api.github.com.
var newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
	return &githubReleaseSource{
		owner:  owner,
		repo:   repo,
		token:  token,
		client: http.DefaultClient,
	}
}

type githubReleaseSource struct {
	owner  string
	repo   string
	token  string
	client *http.Client
}

func (s *githubReleaseSource) ListReleases(limit int) ([]catalogbuild.Release, error) {
	if limit <= 0 {
		limit = 10
	}
	perPage := limit * 2
	if perPage < 1 {
		perPage = 1
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=%d", s.owner, s.repo, perPage)
	body, err := s.get(url, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		PublishedAt string `json:"published_at"`
		CreatedAt   string `json:"created_at"`
		Prerelease  bool   `json:"prerelease"`
		Draft       bool   `json:"draft"`
		Assets      []struct {
			Name               string  `json:"name"`
			BrowserDownloadURL string  `json:"browser_download_url"`
			Size               int64   `json:"size"`
			Digest             *string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	releases := []catalogbuild.Release{}
	for _, rel := range raw {
		if rel.Draft {
			continue
		}
		assets := make([]catalogbuild.Asset, 0, len(rel.Assets))
		for _, asset := range rel.Assets {
			assets = append(assets, catalogbuild.Asset{
				Name:   asset.Name,
				URL:    asset.BrowserDownloadURL,
				Size:   asset.Size,
				Digest: asset.Digest,
			})
		}
		releases = append(releases, catalogbuild.Release{
			Tag:         rel.TagName,
			Name:        rel.Name,
			PublishedAt: catalogbuild.FirstNonEmptyStr(rel.PublishedAt, rel.CreatedAt),
			Prerelease:  rel.Prerelease,
			Assets:      assets,
		})
		if len(releases) >= limit {
			break
		}
	}
	return releases, nil
}

func (s *githubReleaseSource) DownloadAsset(asset catalogbuild.Asset) ([]byte, error) {
	return s.get(asset.URL, "application/octet-stream")
}

func (s *githubReleaseSource) get(url, accept string) ([]byte, error) {
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, readErr := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		if len(body) > 240 {
			body = body[:240]
		}
		return nil, fmt.Errorf("GitHub request %s failed: %s: %s", url, res.Status, strings.TrimSpace(string(body)))
	}
	if readErr != nil {
		return nil, readErr
	}
	return body, nil
}

func detectCatalogRepo(ownerFlag, repoFlag string) (string, string, error) {
	if ownerFlag != "" && repoFlag != "" {
		return ownerFlag, repoFlag, nil
	}
	if owner := os.Getenv("GH_OWNER"); owner != "" && os.Getenv("GH_REPO") != "" {
		return owner, os.Getenv("GH_REPO"), nil
	}
	if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
		parts := strings.SplitN(repo, "/", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1], nil
		}
	}
	cmd := exec.Command("git", "remote", "get-url", "origin")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("unable to detect GitHub repo: set --owner/--repo or GH_OWNER/GH_REPO")
	}
	owner, repo := parseGitHubRemote(strings.TrimSpace(string(raw)))
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("unable to parse GitHub repo from origin %q: set --owner/--repo", strings.TrimSpace(string(raw)))
	}
	return owner, repo, nil
}

func parseGitHubRemote(remote string) (string, string) {
	remote = strings.TrimSuffix(remote, ".git")
	if idx := strings.Index(remote, "github.com"); idx != -1 {
		rest := strings.TrimLeft(remote[idx+len("github.com"):], ":/")
		parts := strings.Split(rest, "/")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
	}
	parts := strings.Split(remote, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var (
		data []byte
		err  error
	)
	if catalogGatherOpts.pretty {
		data, err = json.MarshalIndent(value, "", "  ")
	} else {
		data, err = json.Marshal(value)
	}
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
