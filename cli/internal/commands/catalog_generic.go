package commands

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"sigs.k8s.io/yaml"
)

type genericImageRecordBundle struct {
	Summary catalog.CatalogImageSummary
	Record  catalog.ImageRecord
}

func runCatalogGenerateFromImages() error {
	outDir := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.outDir, GlobalOpts.CatalogPath, filepath.Join("site", "src", "data", "catalog"))
	if catalogGatherOpts.outDir != "" {
		GlobalOpts.CatalogPath = catalogGatherOpts.outDir
	}
	generatedAt := catalogGatherOpts.generatedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	bundles, err := loadGenericImageBundles(catalogGatherOpts.imagesFile, generatedAt)
	if err != nil {
		return err
	}
	if len(bundles) == 0 {
		return fmt.Errorf("%s contains no images", catalogGatherOpts.imagesFile)
	}
	if err := os.RemoveAll(filepath.Join(outDir, "images")); err != nil {
		return err
	}
	for _, bundle := range bundles {
		if err := writeJSONFile(filepath.Join(outDir, "images", bundle.Record.ID+".json"), bundle.Record); err != nil {
			return err
		}
	}
	index := genericCatalogIndex(generatedAt, bundles)
	if err := writeJSONFile(filepath.Join(outDir, "index.json"), index); err != nil {
		return err
	}
	fmt.Fprintf(out, "[generate] wrote %d generic OCI image record(s)\n", len(bundles))
	return finalizeGeneratedCatalog(outDir)
}

func loadGenericImageBundles(path string, generatedAt string) ([]genericImageRecordBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read generic OCI images inventory: %w", err)
	}
	var inventory estategraph.ImagesFile
	if err := yaml.Unmarshal(raw, &inventory); err != nil {
		return nil, fmt.Errorf("parse generic OCI images inventory: %w", err)
	}
	bundles := make([]genericImageRecordBundle, 0, len(inventory.Images))
	seen := map[string]bool{}
	for i, spec := range inventory.Images {
		bundle, err := genericImageBundle(spec, generatedAt)
		if err != nil {
			return nil, fmt.Errorf("images[%d]: %w", i, err)
		}
		if seen[bundle.Record.ID] {
			return nil, fmt.Errorf("images[%d]: duplicate image id %q", i, bundle.Record.ID)
		}
		seen[bundle.Record.ID] = true
		bundles = append(bundles, bundle)
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].Record.ID < bundles[j].Record.ID })
	return bundles, nil
}

func genericImageBundle(spec estategraph.ImageSpec, generatedAt string) (genericImageRecordBundle, error) {
	if strings.TrimSpace(spec.ID) == "" {
		return genericImageRecordBundle{}, fmt.Errorf("missing id")
	}
	if strings.TrimSpace(spec.Image) == "" {
		return genericImageRecordBundle{}, fmt.Errorf("%s: missing image", spec.ID)
	}
	if spec.Language.ID == "" {
		return genericImageRecordBundle{}, fmt.Errorf("%s: missing language.id", spec.ID)
	}
	if spec.Language.DisplayName == "" {
		spec.Language.DisplayName = spec.Language.ID
	}
	if spec.Language.Version == "" {
		spec.Language.Version = "unknown"
	}
	if spec.Tier == "" {
		spec.Tier = "slim"
	}
	if !catalog.ValidTier(spec.Tier) {
		return genericImageRecordBundle{}, fmt.Errorf("%s: unsupported tier %q", spec.ID, spec.Tier)
	}
	ref, err := name.ParseReference(spec.Image, name.WeakValidation)
	if err != nil {
		return genericImageRecordBundle{}, fmt.Errorf("%s: parse image reference: %w", spec.ID, err)
	}

	tag := catalogbuild.FirstNonEmptyStr(spec.Tag, ref.Identifier())
	manifestDigest := digestIfPinned(ref.Identifier())
	registry := ref.Context().RegistryStr()
	repository := ref.Context().RepositoryStr()
	fullName := ref.Context().Name()
	imageName := path.Base(repository)
	architectures, err := genericArchitectures(spec.Architectures, generatedAt, manifestDigest)
	if err != nil {
		return genericImageRecordBundle{}, fmt.Errorf("%s: %w", spec.ID, err)
	}
	lifecycle := defaultGenericLifecycle()
	if spec.Lifecycle != nil {
		lifecycle = *spec.Lifecycle
	}
	runtime := defaultGenericRuntimeContract(spec.Tier)
	if spec.RuntimeContract != nil {
		runtime = *spec.RuntimeContract
	}
	if spec.Origin == nil {
		spec.Origin = &catalog.ImageOrigin{
			Kind:               "imported",
			CreatedByClearCutt: false,
			SourceRef:          spec.Image,
			ObservationMode:    "inventory-only",
			ProvenanceClaim:    "none",
		}
	}
	if spec.Governance == nil {
		spec.Governance = &catalog.ImageGovernance{
			Imported:                 true,
			ClassificationConfidence: "user-supplied",
			ProductionIntent:         "unassessed",
		}
	}
	tier := catalog.TierInfo{ID: spec.Tier, Name: genericTierName(spec.Tier), Blurb: genericTierBlurb(spec.Tier)}
	evidence := catalog.EvidenceSummary{
		ArchCount: len(architectures),
		Statuses: &catalog.EvidenceStatuses{
			Signature:       catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "none", Claim: "No signature evidence inferred for generic OCI image"},
			Provenance:      catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "none", Claim: "No build provenance inferred for generic OCI image"},
			SBOM:            catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "none", Claim: "No SBOM evidence supplied for generic OCI image"},
			Tests:           catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "none", Claim: "No test evidence supplied for generic OCI image"},
			Vulnerabilities: catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "none", Claim: "No vulnerability scan evidence supplied for generic OCI image"},
		},
	}
	release := catalog.ReleaseEntry{
		Tag:             tag,
		PublishedAt:     generatedAt,
		IsLatest:        true,
		ManifestDigest:  manifestDigest,
		Architectures:   architectures,
		Attestations:    []catalog.AttestationEntry{},
		AssetURLs:       catalog.AssetURLs{SBOM: map[string]string{}, TestResults: map[string]string{}},
		Evidence:        &evidence,
		Lifecycle:       lifecycle,
		RuntimeContract: runtime,
		Exceptions:      catalog.ExceptionSummary{},
	}
	record := catalog.ImageRecord{
		SchemaVersion:   catalog.ImageRecordSchemaVersion,
		ID:              spec.ID,
		Language:        spec.Language,
		Tier:            tier,
		Registry:        registry,
		ImageName:       imageName,
		FullName:        fullName,
		Lifecycle:       lifecycle,
		RuntimeContract: runtime,
		Origin:          spec.Origin,
		Governance:      spec.Governance,
		EvidencePolicy:  spec.EvidencePolicy,
		Releases:        []catalog.ReleaseEntry{release},
	}
	summary := catalog.CatalogImageSummary{
		ID:                   spec.ID,
		Language:             spec.Language.ID,
		LanguageDisplay:      spec.Language.DisplayName,
		LanguageVersion:      spec.Language.Version,
		Tier:                 spec.Tier,
		LatestTag:            tag,
		LatestManifestDigest: manifestDigest,
		LatestPackageCount:   0,
		Architectures:        archNames(architectures),
		Signed:               false,
		Provenance:           false,
		Evidence:             &evidence,
		Passed:               false,
		VulnSummary:          &catalog.VulnSummary{Remediation: &catalog.RemediationCounts{}},
		Lifecycle:            lifecycle,
		RuntimeContract:      runtime,
		Origin:               spec.Origin,
		Governance:           spec.Governance,
		EvidencePolicy:       spec.EvidencePolicy,
	}
	return genericImageRecordBundle{Summary: summary, Record: record}, nil
}

func genericCatalogIndex(generatedAt string, bundles []genericImageRecordBundle) catalog.CatalogIndex {
	owner := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.owner, "generic")
	repo := catalogbuild.FirstNonEmptyStr(catalogGatherOpts.repo, "oci-fleet")
	images := make([]catalog.CatalogImageSummary, 0, len(bundles))
	languagesByKey := map[string]catalog.LanguageInfo{}
	tiersByID := map[string]catalog.TierInfo{}
	releaseSeen := map[string]bool{}
	releases := []catalog.ReleaseSummary{}
	registryBase := catalogGatherOpts.registryBase
	for _, bundle := range bundles {
		images = append(images, bundle.Summary)
		lang := bundle.Record.Language
		languagesByKey[lang.ID+"@"+lang.Version] = lang
		tiersByID[bundle.Record.Tier.ID] = bundle.Record.Tier
		if registryBase == "" {
			registryBase = bundle.Record.Registry
		}
		for _, rel := range bundle.Record.Releases {
			if !releaseSeen[rel.Tag] {
				releaseSeen[rel.Tag] = true
				releases = append(releases, catalog.ReleaseSummary{Tag: rel.Tag, PublishedAt: rel.PublishedAt, IsLatest: len(releases) == 0})
			}
		}
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].PublishedAt > releases[j].PublishedAt })
	for i := range releases {
		releases[i].IsLatest = i == 0
	}
	latestTag := ""
	if len(releases) > 0 {
		latestTag = releases[0].Tag
	}
	return catalog.CatalogIndex{
		SchemaVersion: catalog.CatalogIndexSchemaVersion,
		GeneratedAt:   generatedAt,
		Owner:         owner,
		Repo:          repo,
		RepoURL:       "",
		RegistryBase:  registryBase,
		LatestTag:     latestTag,
		Releases:      releases,
		Languages:     sortedGenericLanguages(languagesByKey),
		Tiers:         sortedGenericTiers(tiersByID),
		Images:        images,
	}
}

func genericArchitectures(values []string, generatedAt string, imageDigest *string) ([]catalog.ArchPayload, error) {
	if len(values) == 0 {
		values = []string{"amd64"}
	}
	out := make([]catalog.ArchPayload, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		arch := strings.TrimSpace(value)
		if arch == "" {
			continue
		}
		if arch != "amd64" && arch != "arm64" {
			return nil, fmt.Errorf("unsupported architecture %q; supported: amd64, arm64", arch)
		}
		if seen[arch] {
			continue
		}
		seen[arch] = true
		layerCount := 0
		out = append(out, catalog.ArchPayload{
			Arch:        arch,
			OS:          "linux",
			ImageDigest: imageDigest,
			LayerCount:  &layerCount,
			Layers:      []catalog.LayerInfo{},
			Labels:      map[string]string{},
			SBOM: catalog.SBOMInfo{
				Tool:         "unavailable",
				CreatedAt:    generatedAt,
				PackageCount: 0,
				Packages:     []catalog.PackageEntry{},
			},
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable architectures")
	}
	return out, nil
}

func sortedGenericLanguages(values map[string]catalog.LanguageInfo) []catalog.LanguageInfo {
	out := make([]catalog.LanguageInfo, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return out[i].Version < out[j].Version
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func sortedGenericTiers(values map[string]catalog.TierInfo) []catalog.TierInfo {
	out := make([]catalog.TierInfo, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func defaultGenericLifecycle() catalog.Lifecycle {
	return catalog.Lifecycle{Status: "active", Support: "current", ProductionAllowed: true}
}

func defaultGenericRuntimeContract(tier string) catalog.RuntimeContract {
	return catalog.RuntimeContract{ProductionTier: tier != "dev"}
}

func genericTierName(id string) string {
	switch id {
	case "dev":
		return "Dev"
	case "distroless":
		return "Distroless"
	default:
		return "Slim"
	}
}

func genericTierBlurb(id string) string {
	switch id {
	case "dev":
		return "Generic OCI development image; runtime contract is inferred from inventory metadata."
	case "distroless":
		return "Generic OCI hardened runtime image; detailed shell/package-manager evidence is unavailable until registry inspection is configured."
	default:
		return "Generic OCI runtime image; detailed runtime evidence is unavailable until registry inspection is configured."
	}
}

func archNames(architectures []catalog.ArchPayload) []string {
	out := make([]string, 0, len(architectures))
	for _, arch := range architectures {
		out = append(out, arch.Arch)
	}
	return out
}

func digestIfPinned(identifier string) *string {
	if strings.HasPrefix(identifier, "sha256:") {
		return &identifier
	}
	return nil
}
