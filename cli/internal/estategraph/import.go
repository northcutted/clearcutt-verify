package estategraph

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"sigs.k8s.io/yaml"
)

var versionRe = regexp.MustCompile(`(?i)(java|jdk|jre|node|nodejs|python|py|go|golang|dotnet|aspnet|nginx|postgres|valkey|redis)[^0-9]*([0-9]+(?:\.[0-9]+)?)`)

func ReadImagesFile(path string) (ImagesFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ImagesFile{}, err
	}
	var inventory ImagesFile
	if err := yaml.Unmarshal(raw, &inventory); err != nil {
		return ImagesFile{}, err
	}
	return inventory, nil
}

func WriteImagesFile(path string, inventory ImagesFile) error {
	data, err := yaml.Marshal(inventory)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func ImportRefs(opts ImportOptions) (ImagesFile, ImportSummary, error) {
	refs, err := readRefs(opts.RefsPath)
	if err != nil {
		return ImagesFile{}, ImportSummary{}, err
	}
	return ImportRefList(refs, opts)
}

// ImportRefList classifies an in-memory ref list into an inventory.
//
// It is the same path as ImportRefs without the file round-trip, so a producer that
// already holds refs — a registry scan, for one — can feed classification directly
// instead of writing a temporary file only to read it back.
func ImportRefList(refs []string, opts ImportOptions) (ImagesFile, ImportSummary, error) {
	generatedAt := opts.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	defaultTier := firstNonEmpty(opts.DefaultTier, "slim")
	defaultLifecycle := firstNonEmpty(opts.DefaultLifecycle, "active")

	if len(refs) == 0 {
		return ImagesFile{}, ImportSummary{}, fmt.Errorf("no image refs to import")
	}
	inventory := ImagesFile{
		APIVersion:   APIVersion,
		Kind:         "ImportedFleetInventory",
		Owner:        strings.TrimSpace(opts.Owner),
		Repo:         strings.TrimSpace(opts.Repo),
		RegistryBase: strings.TrimSuffix(strings.TrimSpace(opts.RegistryBase), "/"),
		GeneratedAt:  generatedAt,
		Images:       make([]ImageSpec, 0, len(refs)),
	}
	summary := ImportSummary{GeneratedAt: generatedAt}
	// A reference listed twice is one image.
	var unique []string
	listed := map[string]bool{}
	for _, ref := range refs {
		canonical, err := canonicalRef(ref)
		if err != nil {
			return ImagesFile{}, ImportSummary{}, fmt.Errorf("parse image ref %q: %w", ref, err)
		}
		if !listed[canonical] {
			listed[canonical] = true
			unique = append(unique, ref)
		}
	}
	ids := AssignIDs(unique)
	for i, ref := range unique {
		spec, item, err := importedImageSpec(ref, ids[i], defaultTier, defaultLifecycle, generatedAt, firstNonEmpty(opts.Owner, "unknown"))
		if err != nil {
			return ImagesFile{}, ImportSummary{}, err
		}
		inventory.Images = append(inventory.Images, spec)
		if item.ClassificationConfidence == "low" {
			summary.LowConfidence++
		}
		summary.Images = append(summary.Images, item)
	}
	sort.SliceStable(inventory.Images, func(i, j int) bool { return inventory.Images[i].ID < inventory.Images[j].ID })
	sort.SliceStable(summary.Images, func(i, j int) bool { return summary.Images[i].ID < summary.Images[j].ID })
	summary.ImageCount = len(inventory.Images)
	return inventory, summary, nil
}

func readRefs(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }() // read-only, so a failed Close loses nothing

	var refs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		refs = append(refs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("%s contains no image refs", path)
	}
	return refs, nil
}

func importedImageSpec(ref, id, defaultTier, lifecycleStatus, generatedAt, owner string) (ImageSpec, ImportImageSummary, error) {
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return ImageSpec{}, ImportImageSummary{}, fmt.Errorf("parse image ref %q: %w", ref, err)
	}
	lang, confidence := InferLanguage(path.Base(parsed.Context().RepositoryStr()), parsed.Identifier())
	spec := ImageSpec{
		ID:    id,
		Image: ref,
		Language: LanguageInfo{
			ID:          lang.ID,
			DisplayName: lang.DisplayName,
			Version:     lang.Version,
		},
		Tier: defaultTier,
		Lifecycle: &Lifecycle{
			Status:            lifecycleStatus,
			Support:           "unsupported",
			ProductionAllowed: false,
		},
		Origin: &ImageOrigin{
			Kind:               "imported",
			CreatedByClearCutt: false,
			SourceRef:          ref,
			ObservedAt:         generatedAt,
			ObservationMode:    "explicit-list",
			ProvenanceClaim:    "none",
		},
		Governance: &ImageGovernance{
			Imported:                 true,
			Owner:                    owner,
			ClassificationConfidence: confidence,
			ProductionIntent:         "unknown",
			Notes:                    []string{},
		},
		EvidencePolicy: &EvidencePolicy{
			Signature:         "optional",
			SBOM:              "optional",
			Provenance:        "optional",
			VulnerabilityScan: "optional",
			Tests:             "optional",
		},
	}
	item := ImportImageSummary{
		ID:                       id,
		Image:                    ref,
		Language:                 spec.Language.ID,
		LanguageVersion:          spec.Language.Version,
		Tier:                     spec.Tier,
		ClassificationConfidence: confidence,
	}
	return spec, item, nil
}

// ImageID is the ID an image reference gets in inventories and estate
// reports: its registry, repository path, and tag or digest, lower-cased,
// with every run of other characters made one dash. The tag latest is left
// out, and a digest is cut to its first 12 hex digits:
//
//	ghcr.io/acme/billing:1.2     ghcr-io-acme-billing-1-2
//	ghcr.io/acme/billing         ghcr-io-acme-billing
//	debian:trixie-slim           docker-io-library-debian-trixie-slim
//	ghcr.io/acme/billing@sha256:0123456789abcdef…  ghcr-io-acme-billing-sha256-0123456789ab
//
// It depends on nothing but the reference, so a reference has the same ID in
// every run, whatever else the estate holds. Two references can spell the
// same ID (acme/a-b and acme/a/b); AssignIDs tells them apart.
func ImageID(ref string) string {
	parsed, err := name.ParseReference(strings.TrimSpace(ref), name.WeakValidation)
	if err != nil {
		return sanitizeID(ref)
	}
	id := sanitizeID(registryName(parsed) + "/" + parsed.Context().RepositoryStr())
	switch identifier := parsed.Identifier(); {
	case strings.HasPrefix(identifier, "sha256:") && len(identifier) >= 19:
		id += "-" + sanitizeID(identifier[:19])
	case identifier != "latest":
		id += "-" + sanitizeID(identifier)
	}
	return id
}

// AssignIDs gives each reference its ImageID, made unique without regard to
// order: references that are different but spell the same ID each get the
// first 8 hex digits of the sha256 of the reference (as canonicalRef spells
// it) appended. The same reference twice gets the same ID; callers list each
// image once.
func AssignIDs(refs []string) []string {
	canonical := make([]string, len(refs))
	byID := map[string]map[string]bool{}
	for i, ref := range refs {
		c, err := canonicalRef(ref)
		if err != nil {
			c = strings.TrimSpace(ref)
		}
		canonical[i] = c
		id := ImageID(ref)
		if byID[id] == nil {
			byID[id] = map[string]bool{}
		}
		byID[id][c] = true
	}
	out := make([]string, len(refs))
	for i, ref := range refs {
		id := ImageID(ref)
		if len(byID[id]) > 1 {
			id += "-" + shortHash(canonical[i])
		}
		out[i] = id
	}
	return out
}

// CanonicalRef spells a reference the one way (canonicalRef), or returns it
// trimmed when it isn't one.
func CanonicalRef(ref string) string {
	if c, err := canonicalRef(ref); err == nil {
		return c
	}
	return strings.TrimSpace(ref)
}

// canonicalRef spells a reference the one way: registry (Docker Hub as
// docker.io), repository, and tag or digest.
func canonicalRef(ref string) (string, error) {
	parsed, err := name.ParseReference(strings.TrimSpace(ref), name.WeakValidation)
	if err != nil {
		return "", err
	}
	sep := ":"
	if _, ok := parsed.(name.Digest); ok {
		sep = "@"
	}
	return registryName(parsed) + "/" + parsed.Context().RepositoryStr() + sep + parsed.Identifier(), nil
}

// registryName is a reference's registry, Docker Hub's as docker.io.
func registryName(ref name.Reference) string {
	reg := ref.Context().RegistryStr()
	if reg == name.DefaultRegistry {
		return "docker.io"
	}
	return reg
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func sanitizeID(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

type inferredLanguage struct {
	ID          string
	DisplayName string
	Version     string
}

func InferLanguage(imageName, identifier string) (inferredLanguage, string) {
	needle := strings.ToLower(imageName + "-" + identifier)
	family := ""
	display := ""
	for _, candidate := range []struct {
		terms   []string
		id      string
		display string
	}{
		{[]string{"java", "jdk", "jre", "corretto", "temurin"}, "java", "Java"},
		{[]string{"node", "nodejs"}, "node", "Node.js"},
		{[]string{"python", "py"}, "python", "Python"},
		{[]string{"golang", "go"}, "go", "Go"},
		{[]string{"dotnet", "aspnet"}, "dotnet", ".NET"},
		{[]string{"nginx"}, "nginx", "Nginx"},
		{[]string{"postgres"}, "postgres", "Postgres"},
		{[]string{"valkey", "redis"}, "valkey", "Valkey/Redis"},
	} {
		for _, term := range candidate.terms {
			if containsToken(needle, term) {
				family = candidate.id
				display = candidate.display
				break
			}
		}
		if family != "" {
			break
		}
	}
	if family == "" {
		return inferredLanguage{ID: "unknown", DisplayName: "Unknown", Version: "unknown"}, "low"
	}
	version := "unknown"
	if m := versionRe.FindStringSubmatch(needle); m != nil {
		version = m[2]
	}
	confidence := "high"
	if version == "unknown" {
		confidence = "medium"
	}
	return inferredLanguage{ID: family, DisplayName: display, Version: version}, confidence
}

func containsToken(value, token string) bool {
	if token == "go" {
		return regexp.MustCompile(`(^|[^a-z0-9])go([0-9]|[^a-z0-9]|$)`).MatchString(value)
	}
	return strings.Contains(value, token)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
