package commands

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/northcutted/clearcutt-verify/internal/oci"
	"github.com/northcutted/clearcutt-verify/internal/sign"
	"github.com/spf13/cobra"
)

type catalogEnrichFlags struct {
	config           string
	limit            int
	tags             string
	owner            string
	repo             string
	registryBase     string
	imagePrefix      string
	outDir           string
	targets          string
	forceRefreshAll  bool
	forceRefreshTags string
	cosignPath       string
	identity         string
	issuer           string
	includeServices  bool
}

var catalogEnrichOpts catalogEnrichFlags

func newCatalogEnrichCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enrich",
		Short: "Enrich catalog records from GHCR manifests and Sigstore evidence",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogEnrichWithConfig(cmd.Flags().Changed("config"), cmd.Flags().Changed("limit"))
		},
	}
	cmd.Flags().StringVar(&catalogEnrichOpts.config, "config", config.DefaultConfigPath, "ClearCutt fleet config used for owner/repo/registry/target defaults")
	cmd.Flags().IntVar(&catalogEnrichOpts.limit, "limit", envIntValue("RELEASE_LIMIT", 10), "Maximum releases to inspect for tags")
	cmd.Flags().StringVar(&catalogEnrichOpts.tags, "tags", os.Getenv("GATHER_TAGS"), "Comma-separated release tags to enrich")
	cmd.Flags().StringVar(&catalogEnrichOpts.owner, "owner", os.Getenv("GH_OWNER"), "GitHub owner")
	cmd.Flags().StringVar(&catalogEnrichOpts.repo, "repo", os.Getenv("GH_REPO"), "GitHub repository")
	cmd.Flags().StringVar(&catalogEnrichOpts.registryBase, "registry-base", "", "Registry namespace (defaults to fleet config or ghcr.io/<owner>/<repo>)")
	cmd.Flags().StringVar(&catalogEnrichOpts.imagePrefix, "image-prefix", "", "Image name prefix for registry enrichment (defaults to fleet config registry.imagePrefix or \"clearcutt\")")
	cmd.Flags().StringVar(&catalogEnrichOpts.outDir, "out-dir", envOr("ENRICHMENT_DIR", filepath.Join("site", "src", "data", "enrichment")), "Enrichment output directory")
	cmd.Flags().StringVar(&catalogEnrichOpts.targets, "targets", os.Getenv("CATALOG_TARGETS"), "Comma-separated target allowlist")
	cmd.Flags().BoolVar(&catalogEnrichOpts.forceRefreshAll, "force-refresh-all", parseScanBool(os.Getenv("FORCE_REFRESH_ALL")), "Refresh every tag even when cached")
	cmd.Flags().StringVar(&catalogEnrichOpts.forceRefreshTags, "force-refresh-tags", os.Getenv("FORCE_REFRESH_TAGS"), "Comma-separated tags to refresh")
	cmd.Flags().StringVar(&catalogEnrichOpts.cosignPath, "cosign-path", envOr("COSIGN_PATH", "cosign"), "Path to cosign binary")
	cmd.Flags().StringVar(&catalogEnrichOpts.identity, "certificate-identity-regexp", "", "Cosign certificate identity regexp")
	cmd.Flags().StringVar(&catalogEnrichOpts.issuer, "certificate-oidc-issuer", envOr("COSIGN_OIDC_ISSUER", "https://token.actions.githubusercontent.com"), "Cosign certificate OIDC issuer")
	cmd.Flags().BoolVar(&catalogEnrichOpts.includeServices, "include-services", false, "Also enrich configured first-class service images")
	return cmd
}

func runCatalogEnrich() error {
	return runCatalogEnrichWithConfig(false, false)
}

func runCatalogEnrichWithConfig(explicitConfig, limitChanged bool) error {
	if err := applyCatalogEnrichConfig(explicitConfig, limitChanged); err != nil {
		return err
	}
	owner, repo, err := detectCatalogRepo(catalogEnrichOpts.owner, catalogEnrichOpts.repo)
	if err != nil {
		return err
	}
	registryBase := catalogEnrichOpts.registryBase
	if registryBase == "" {
		registryBase = "ghcr.io/" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
	}
	tags, err := catalogEnrichTags(owner, repo)
	if err != nil {
		return err
	}
	refresh := enrichTagSet(tags, catalogEnrichOpts.forceRefreshAll, catalogEnrichOpts.forceRefreshTags)
	identity := catalogEnrichOpts.identity
	if identity == "" {
		identity = fmt.Sprintf(`^https://github\.com/%s/%s/\.github/workflows/release\.yml@refs/heads/.+$`, regexp.QuoteMeta(owner), regexp.QuoteMeta(repo))
	}
	cosign := sign.New(catalogEnrichOpts.cosignPath, identity, catalogEnrichOpts.issuer, out, errOut)
	if err := cosign.Available(); err != nil {
		fmt.Fprintf(errOut, "[enrich] %v; continuing with manifest metadata only\n", err)
		cosign = nil
	}
	source := &githubReleaseSource{owner: owner, repo: repo, token: catalogbuild.FirstNonEmptyStr(os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN")), client: nil}
	enricher := &registryCatalogEnricher{
		owner:        owner,
		repo:         repo,
		registryBase: registryBase,
		imagePrefix:  catalogEnrichOpts.imagePrefix,
		oci:          oci.NewClient(),
		cosign:       cosign,
		github:       source,
	}

	fetched, cached := 0, 0
	for _, tag := range tags {
		if err := os.MkdirAll(filepath.Join(catalogEnrichOpts.outDir, tag), 0o755); err != nil {
			return err
		}
		mustRefresh := refresh[tag]
		for _, target := range catalogbuild.Targets(catalogEnrichOpts.targets) {
			outFile := filepath.Join(catalogEnrichOpts.outDir, tag, target+".json")
			if !mustRefresh && catalogbuild.FileExists(outFile) {
				cached++
				continue
			}
			enrichment, err := enricher.Enrich(tag, target)
			if err != nil {
				fmt.Fprintf(errOut, "[enrich] %s/%s: %v\n", tag, target, err)
				continue
			}
			if enrichment == nil {
				continue
			}
			if err := writeJSONFile(outFile, enrichment); err != nil {
				return err
			}
			fetched++
			fmt.Fprintf(out, "[enrich] wrote %s/%s\n", tag, target)
		}
	}
	fmt.Fprintf(out, "[enrich] done fetched=%d cached=%d\n", fetched, cached)
	return nil
}

func applyCatalogEnrichConfig(explicitConfig, limitChanged bool) error {
	if catalogEnrichOpts.config == "" {
		return nil
	}
	cfg, err := config.Load(catalogEnrichOpts.config)
	if err != nil {
		if explicitConfig || !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if catalogEnrichOpts.owner == "" {
		catalogEnrichOpts.owner = cfg.Registry.Owner
	}
	if catalogEnrichOpts.repo == "" {
		catalogEnrichOpts.repo = cfg.Registry.Repository
	}
	if catalogEnrichOpts.registryBase == "" {
		catalogEnrichOpts.registryBase = cfg.RegistryBase()
	}
	if catalogEnrichOpts.imagePrefix == "" {
		catalogEnrichOpts.imagePrefix = cfg.Registry.ImagePrefix
	}
	if catalogEnrichOpts.targets == "" {
		catalogEnrichOpts.targets = catalogTargets(cfg)
	}
	if catalogEnrichOpts.includeServices {
		catalogEnrichOpts.targets = appendFleetServiceTargets(catalogEnrichOpts.targets, cfg)
	}
	if !limitChanged && cfg.Catalog.ReleaseLimit > 0 {
		catalogEnrichOpts.limit = cfg.Catalog.ReleaseLimit
	}
	return nil
}

func catalogEnrichTags(owner, repo string) ([]string, error) {
	if catalogEnrichOpts.tags != "" {
		tags := []string{}
		for _, tag := range strings.Split(catalogEnrichOpts.tags, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tags = append(tags, tag)
			}
		}
		return tags, nil
	}
	source := &githubReleaseSource{owner: owner, repo: repo, token: catalogbuild.FirstNonEmptyStr(os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN")), client: nil}
	releases, err := source.ListReleases(catalogEnrichOpts.limit)
	if err != nil {
		return nil, err
	}
	tags := make([]string, 0, len(releases))
	for _, rel := range releases {
		tags = append(tags, rel.Tag)
	}
	return tags, nil
}

func enrichTagSet(tags []string, forceAll bool, forceTags string) map[string]bool {
	out := map[string]bool{}
	if forceAll {
		for _, tag := range tags {
			out[tag] = true
		}
		return out
	}
	if forceTags != "" {
		for _, tag := range strings.Split(forceTags, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				out[tag] = true
			}
		}
	}
	return out
}

type registryCatalogEnricher struct {
	owner        string
	repo         string
	registryBase string
	imagePrefix  string
	oci          *oci.Client
	cosign       *sign.Cosign
	github       *githubReleaseSource
}

func (e *registryCatalogEnricher) Enrich(tag, target string) (*catalogbuild.Enrichment, error) {
	refs := e.catalogRefs(tag, target)
	if len(refs) == 0 || e.oci == nil {
		return nil, nil
	}
	var res *oci.Resolved
	for _, ref := range refs {
		pulled, err := e.oci.Pull(ref)
		if err == nil {
			res = pulled
			break
		}
	}
	if res == nil {
		return nil, nil
	}
	result := &catalogbuild.Enrichment{Architectures: []catalogbuild.EnrichmentArch{}, Attestations: []catalogbuild.EnrichmentAttestation{}}
	if digest, err := res.ManifestDigest(); err == nil {
		result.ManifestDigest = &digest
	}
	arches, err := enrichmentArchitectures(res)
	if err != nil {
		return nil, err
	}
	result.Architectures = arches

	allAttestations := []cosignAttestation{}
	seen := map[string]bool{}
	for _, ref := range refs {
		if e.cosign != nil && result.Signature == nil {
			result.Signature = e.verifySignature(ref)
		}
		for _, att := range e.downloadAttestations(ref) {
			key := att.dedupeKey()
			if seen[key] {
				continue
			}
			seen[key] = true
			allAttestations = append(allAttestations, att)
		}
		if result.Signature != nil && len(allAttestations) > 0 {
			break
		}
	}
	if result.Signature != nil && result.Signature.CosignBundlePresent {
		if meta := e.signatureCertMetadata(allAttestations); meta != nil {
			result.Signature.Certificate = meta
		}
	}
	for _, att := range allAttestations {
		if strings.Contains(att.PredicateType, "slsa.dev/provenance") && result.Provenance == nil {
			if prov := provenanceFromPayload(att.Payload); prov != nil {
				result.Provenance = prov
			}
		}
		if strings.Contains(att.PredicateType, "cosign.sigstore.dev/attestation/v1") && result.TestResults == nil {
			result.TestResults = extractCosignTestResults(att.Payload)
		}
	}

	githubAttestations := e.listGithubAttestations(result.ManifestDigest)
	normalized := []catalogbuild.EnrichmentAttestation{}
	for _, att := range allAttestations {
		if n := e.normalizeAttestation(att, "oci", nil); n != nil {
			normalized = append(normalized, *n)
		}
	}
	normalized = append(normalized, githubAttestations...)
	result.Attestations = mergeEnrichmentAttestations(normalized)
	return result, nil
}

func (e *registryCatalogEnricher) catalogRefs(tag, target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	imagePrefix := catalogbuild.FirstNonEmptyStr(e.imagePrefix, "clearcutt")
	if meta := catalogbuild.TargetMeta(target); meta != nil {
		baseImage := strings.TrimRight(e.registryBase, "/") + "/" + imagePrefix + "-" + strings.ToLower(meta.LangKey)
		return []string{
			fmt.Sprintf("%s:%s-%s", baseImage, tag, meta.Tier),
			fmt.Sprintf("%s:%s", baseImage, meta.Tier),
		}
	}
	baseImage := strings.TrimRight(e.registryBase, "/") + "/" + imagePrefix + "-" + strings.ToLower(target)
	return []string{
		fmt.Sprintf("%s:%s-service", baseImage, tag),
	}
}

func enrichmentArchitectures(res *oci.Resolved) ([]catalogbuild.EnrichmentArch, error) {
	out := []catalogbuild.EnrichmentArch{}
	if res.IsIndex {
		manifest, err := res.Index.IndexManifest()
		if err != nil {
			return nil, err
		}
		for _, desc := range manifest.Manifests {
			if !desc.MediaType.IsImage() {
				continue
			}
			img, err := res.Index.Image(desc.Digest)
			if err != nil {
				return nil, err
			}
			arch := "amd64"
			if desc.Platform != nil && desc.Platform.Architecture == "arm64" {
				arch = "arm64"
			}
			enr, err := enrichmentArchitecture(arch, desc.Size, img)
			if err != nil {
				return nil, err
			}
			enr.Digest = catalogbuild.Str(desc.Digest.String())
			out = append(out, enr)
		}
		return out, nil
	}
	cfg, err := res.Image.ConfigFile()
	if err != nil {
		return nil, err
	}
	size := int64(0)
	if res.Desc != nil {
		size = res.Desc.Size
	}
	arch := "amd64"
	if cfg.Architecture == "arm64" {
		arch = "arm64"
	}
	enr, err := enrichmentArchitecture(arch, size, res.Image)
	if err != nil {
		return nil, err
	}
	if digest, err := res.Image.Digest(); err == nil {
		enr.Digest = catalogbuild.Str(digest.String())
	}
	return append(out, enr), nil
}

func enrichmentArchitecture(arch string, descriptorSize int64, img v1.Image) (catalogbuild.EnrichmentArch, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return catalogbuild.EnrichmentArch{}, err
	}
	manifest, err := img.Manifest()
	if err != nil {
		return catalogbuild.EnrichmentArch{}, err
	}
	layers := make([]json.RawMessage, 0, len(manifest.Layers))
	var total int64
	for i, layer := range manifest.Layers {
		total += layer.Size
		var diffID *string
		if i < len(cfg.RootFS.DiffIDs) {
			diffID = catalogbuild.Str(cfg.RootFS.DiffIDs[i].String())
		}
		raw, err := json.Marshal(struct {
			Digest string  `json:"digest"`
			Size   int64   `json:"size"`
			DiffID *string `json:"diffID"`
		}{Digest: layer.Digest.String(), Size: layer.Size, DiffID: diffID})
		if err != nil {
			return catalogbuild.EnrichmentArch{}, err
		}
		layers = append(layers, raw)
	}
	labels := cfg.Config.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labelRaw, err := json.Marshal(labels)
	if err != nil {
		return catalogbuild.EnrichmentArch{}, err
	}
	// The image size is the compressed layer sum; the OCI manifest descriptor
	// byte size is a few KiB and lives in its own field.
	var manifestDescriptorSize *int64
	if descriptorSize > 0 {
		manifestDescriptorSize = &descriptorSize
	}
	return catalogbuild.EnrichmentArch{
		Arch:                   arch,
		Size:                   &total,
		ManifestDescriptorSize: manifestDescriptorSize,
		Layers:                 layers,
		Labels:                 labelRaw,
	}, nil
}

func (e *registryCatalogEnricher) verifySignature(ref string) *catalogbuild.Signature {
	if e.cosign == nil {
		return nil
	}
	raw, err := e.cosign.VerifyImageJSON(ref)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	first := parsed
	if arr, ok := parsed.([]any); ok && len(arr) > 0 {
		first = arr[0]
	}
	optional := mapAt(first, "optional")
	var rekor *int64
	if v := numberAt(optional, "Bundle", "Payload", "logIndex"); v != nil {
		rekor = v
	} else if v := numberAt(optional, "Bundle", "payload", "logIndex"); v != nil {
		rekor = v
	}
	return &catalogbuild.Signature{
		CosignBundlePresent: true,
		RekorLogIndex:       rekor,
		Certificate: &catalogbuild.Certificate{
			Subject:       stringPtrAt(optional, "Subject"),
			Issuer:        firstNonEmptyPtrFromPtrs(stringPtrAt(optional, "Issuer"), catalogbuild.Str("https://token.actions.githubusercontent.com")),
			RunInvocation: nil,
		},
	}
}

func (e *registryCatalogEnricher) downloadAttestations(ref string) []cosignAttestation {
	if e.cosign == nil {
		return nil
	}
	raw, err := e.cosign.DownloadAttestations(ref)
	if err != nil || len(raw) == 0 {
		return nil
	}
	out := []cosignAttestation{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		att, err := parseCosignAttestation([]byte(line))
		if err == nil && att != nil {
			out = append(out, *att)
		}
	}
	return out
}

type cosignAttestation struct {
	PredicateType string
	Payload       map[string]any
	Cert          *x509.Certificate
	Bundle        map[string]any
	GithubAPIURL  *string
}

func (a cosignAttestation) dedupeKey() string {
	return strings.Join([]string{
		a.PredicateType,
		catalogbuild.FirstNonEmptyStr(subjectDigestFromPayload(a.Payload), ""),
		catalogbuild.FirstNonEmptyStr(stringAt(a.Payload, "predicate", "Timestamp"), stringAt(a.Payload, "predicate", "createdOn")),
	}, "|")
}

func parseCosignAttestation(line []byte) (*cosignAttestation, error) {
	var bundle map[string]any
	if err := json.Unmarshal(line, &bundle); err != nil {
		return nil, err
	}
	payload := payloadFromBundle(bundle)
	if payload == nil {
		return nil, fmt.Errorf("attestation has no payload")
	}
	return &cosignAttestation{
		PredicateType: catalogbuild.FirstNonEmptyStr(stringAt(payload, "predicateType"), "unknown"),
		Payload:       payload,
		Cert:          certificateFromBundle(bundle),
		Bundle:        bundle,
	}, nil
}

func payloadFromBundle(bundle map[string]any) map[string]any {
	payloadB64 := stringAt(bundle, "dsseEnvelope", "payload")
	if payloadB64 == "" {
		payloadB64 = stringAt(bundle, "payload")
	}
	if payloadB64 == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil
	}
	return payload
}

func certificateFromBundle(bundle map[string]any) *x509.Certificate {
	certB64 := stringAt(bundle, "verificationMaterial", "certificate", "rawBytes")
	if certB64 == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(decoded)
	if err != nil {
		return nil
	}
	return cert
}

func (e *registryCatalogEnricher) normalizeAttestation(att cosignAttestation, source string, githubAPIURL *string) *catalogbuild.EnrichmentAttestation {
	if att.Payload == nil {
		return nil
	}
	signer := certSubjectURI(att.Cert)
	logIndex := transparencyLogIndex(att.Bundle)
	return &catalogbuild.EnrichmentAttestation{
		Kind:                 attestationKind(att.Payload),
		PredicateType:        catalogbuild.FirstNonEmptyStr(stringAt(att.Payload, "predicateType"), "unknown"),
		SubjectName:          catalogbuild.PtrIfNotEmpty(subjectNameFromPayload(att.Payload)),
		SubjectDigest:        catalogbuild.PtrIfNotEmpty(subjectDigestFromPayload(att.Payload)),
		SignerIdentity:       catalogbuild.PtrIfNotEmpty(signer),
		Issuer:               catalogbuild.PtrIfNotEmpty(catalogbuild.FirstNonEmptyStr(certIssuer(att.Cert), "https://token.actions.githubusercontent.com")),
		RunURL:               catalogbuild.PtrIfNotEmpty(stringAt(att.Payload, "predicate", "runDetails", "metadata", "invocationId")),
		WorkflowURL:          catalogbuild.PtrIfNotEmpty(attestationWorkflowURL(signer)),
		GithubAPIURL:         githubAPIURL,
		TransparencyLogIndex: logIndex,
		TransparencyURL:      transparencyURL(logIndex),
		Sources:              []string{source},
	}
}

func attestationKind(payload map[string]any) string {
	predicateType := catalogbuild.FirstNonEmptyStr(stringAt(payload, "predicateType"), "unknown")
	switch {
	case strings.Contains(predicateType, "spdx.dev/Document"):
		return "sbom"
	case strings.Contains(predicateType, "slsa.dev/provenance"):
		return "slsa-provenance"
	case strings.Contains(predicateType, "cosign.sigstore.dev/attestation") && extractCosignTestResults(payload) != nil:
		return "test-results"
	case strings.Contains(predicateType, "cosign.sigstore.dev/attestation"):
		return "custom"
	default:
		return "custom"
	}
}

func provenanceFromPayload(payload map[string]any) *catalogbuild.Provenance {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	var stmt catalogbuild.IntotoStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil
	}
	out := catalogbuild.SummarizeIntotoStatement(stmt)
	return &out
}

func extractCosignTestResults(payload map[string]any) *catalogbuild.TestResults {
	data := stringAt(payload, "predicate", "Data")
	if data == "" {
		return nil
	}
	var tr catalogbuild.TestResults
	if err := json.Unmarshal([]byte(data), &tr); err != nil {
		return nil
	}
	if tr.Status == "" || len(tr.Assertions) == 0 {
		return nil
	}
	return &tr
}

func (e *registryCatalogEnricher) signatureCertMetadata(atts []cosignAttestation) *catalogbuild.Certificate {
	for _, att := range atts {
		subject := certSubjectURI(att.Cert)
		if subject == "" || !strings.Contains(subject, fmt.Sprintf("github.com/%s/%s/.github/workflows/release.yml@", e.owner, e.repo)) {
			continue
		}
		return &catalogbuild.Certificate{
			Subject:       &subject,
			Issuer:        catalogbuild.Str(catalogbuild.FirstNonEmptyStr(certIssuer(att.Cert), "https://token.actions.githubusercontent.com")),
			RunInvocation: catalogbuild.PtrIfNotEmpty(stringAt(att.Payload, "predicate", "runDetails", "metadata", "invocationId")),
		}
	}
	return nil
}

func (e *registryCatalogEnricher) listGithubAttestations(subjectDigest *string) []catalogbuild.EnrichmentAttestation {
	if subjectDigest == nil || *subjectDigest == "" || e.github == nil {
		return nil
	}
	for _, scope := range []string{"users/" + e.owner, "orgs/" + e.owner} {
		apiURL := fmt.Sprintf("https://api.github.com/%s/attestations/%s", scope, url.PathEscape(*subjectDigest))
		raw, err := e.github.get(apiURL, "application/vnd.github+json")
		if err != nil {
			continue
		}
		var parsed struct {
			Attestations []struct {
				Bundle map[string]any `json:"bundle"`
			} `json:"attestations"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			continue
		}
		api := apiURL
		out := []catalogbuild.EnrichmentAttestation{}
		for _, ghAtt := range parsed.Attestations {
			payload := payloadFromBundle(ghAtt.Bundle)
			if payload == nil {
				continue
			}
			att := cosignAttestation{
				PredicateType: catalogbuild.FirstNonEmptyStr(stringAt(payload, "predicateType"), "unknown"),
				Payload:       payload,
				Cert:          certificateFromBundle(ghAtt.Bundle),
				Bundle:        ghAtt.Bundle,
				GithubAPIURL:  &api,
			}
			if n := e.normalizeAttestation(att, "github", &api); n != nil {
				out = append(out, *n)
			}
		}
		return out
	}
	return nil
}

func mergeEnrichmentAttestations(attestations []catalogbuild.EnrichmentAttestation) []catalogbuild.EnrichmentAttestation {
	byKey := map[string]*catalogbuild.EnrichmentAttestation{}
	order := []string{}
	for i := range attestations {
		att := attestations[i]
		key := strings.Join([]string{
			att.Kind,
			att.PredicateType,
			ptrStringValue(att.SubjectDigest),
			ptrStringValue(att.SignerIdentity),
			ptrStringValue(att.RunURL),
			int64Value(att.TransparencyLogIndex),
		}, "|")
		existing, ok := byKey[key]
		if !ok {
			att.Sources = append([]string{}, att.Sources...)
			byKey[key] = &att
			order = append(order, key)
			continue
		}
		for _, source := range att.Sources {
			if !catalogbuild.StringSliceContains(existing.Sources, source) {
				existing.Sources = append(existing.Sources, source)
			}
		}
		if existing.GithubAPIURL == nil {
			existing.GithubAPIURL = att.GithubAPIURL
		}
		if existing.WorkflowURL == nil {
			existing.WorkflowURL = att.WorkflowURL
		}
		if existing.RunURL == nil {
			existing.RunURL = att.RunURL
		}
		if existing.TransparencyURL == nil {
			existing.TransparencyURL = att.TransparencyURL
		}
	}
	out := make([]catalogbuild.EnrichmentAttestation, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	sort.SliceStable(out, func(i, j int) bool {
		oi, oj := attestationSortOrder(out[i].Kind), attestationSortOrder(out[j].Kind)
		if oi != oj {
			return oi < oj
		}
		return out[i].PredicateType < out[j].PredicateType
	})
	return out
}

func attestationSortOrder(kind string) int {
	switch kind {
	case "slsa-provenance":
		return 0
	case "sbom":
		return 1
	case "test-results":
		return 2
	default:
		return 3
	}
}

func certSubjectURI(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, uri := range cert.URIs {
		if uri.Scheme == "https" && uri.Host == "github.com" {
			return uri.String()
		}
	}
	return ""
}

func certIssuer(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if strings.Contains(strings.ToLower(cert.Issuer.String()), "sigstore") {
		return "https://token.actions.githubusercontent.com"
	}
	return ""
}

func subjectNameFromPayload(payload map[string]any) string {
	subjects, _ := payload["subject"].([]any)
	if len(subjects) == 0 {
		return ""
	}
	return stringAt(subjects[0], "name")
}

func subjectDigestFromPayload(payload map[string]any) string {
	subjects, _ := payload["subject"].([]any)
	if len(subjects) == 0 {
		return ""
	}
	digest := mapAt(subjects[0], "digest")
	if digest == nil {
		return ""
	}
	for _, alg := range []string{"sha256", "sha512"} {
		if v := stringAt(digest, alg); v != "" {
			return alg + ":" + v
		}
	}
	keys := make([]string, 0, len(digest))
	for k := range digest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	if v := stringAt(digest, keys[0]); v != "" {
		return keys[0] + ":" + v
	}
	return ""
}

func transparencyLogIndex(bundle map[string]any) *int64 {
	entries, _ := valueAt(bundle, "verificationMaterial", "tlogEntries").([]any)
	if len(entries) == 0 {
		return nil
	}
	return numberAt(entries[0], "logIndex")
}

func transparencyURL(logIndex *int64) *string {
	if logIndex == nil {
		return nil
	}
	return catalogbuild.Str(fmt.Sprintf("https://search.sigstore.dev/?logIndex=%d", *logIndex))
}

func attestationWorkflowURL(signerIdentity string) string {
	if signerIdentity == "" {
		return ""
	}
	re := regexp.MustCompile(`github\.com/([^/]+)/([^/]+)/\.github/workflows/([^@\s]+)@`)
	m := re.FindStringSubmatch(signerIdentity)
	if m == nil {
		return ""
	}
	return fmt.Sprintf("https://github.com/%s/%s/actions/workflows/%s", m[1], m[2], m[3])
}

func valueAt(v any, keys ...string) any {
	cur := v
	for _, key := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[key]
	}
	return cur
}

func mapAt(v any, keys ...string) map[string]any {
	m, _ := valueAt(v, keys...).(map[string]any)
	return m
}

func stringAt(v any, keys ...string) string {
	raw := valueAt(v, keys...)
	s, _ := raw.(string)
	return s
}

func stringPtrAt(v any, keys ...string) *string {
	if s := stringAt(v, keys...); s != "" {
		return &s
	}
	return nil
}

func numberAt(v any, keys ...string) *int64 {
	raw := valueAt(v, keys...)
	switch n := raw.(type) {
	case float64:
		i := int64(n)
		return &i
	case int64:
		return &n
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return &i
		}
	case string:
		var i int64
		if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
			return &i
		}
	}
	return nil
}

func firstNonEmptyPtrFromPtrs(values ...*string) *string {
	for _, value := range values {
		if value != nil && *value != "" {
			return value
		}
	}
	return nil
}

func ptrStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func int64Value(value *int64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}
