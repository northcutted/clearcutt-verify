package estategraph

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/northcutted/clearcutt-verify/internal/catalog"
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
	seen := map[string]int{}
	for _, ref := range refs {
		spec, item, err := importedImageSpec(ref, defaultTier, defaultLifecycle, generatedAt, firstNonEmpty(opts.Owner, "unknown"), seen)
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
	defer file.Close()

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

func importedImageSpec(ref, defaultTier, lifecycleStatus, generatedAt, owner string, seen map[string]int) (ImageSpec, ImportImageSummary, error) {
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return ImageSpec{}, ImportImageSummary{}, fmt.Errorf("parse image ref %q: %w", ref, err)
	}
	id := stableIDForRef(parsed)
	if seen[id] > 0 {
		seen[id]++
		id = fmt.Sprintf("%s-%d", id, seen[id])
	} else {
		seen[id] = 1
	}
	lang, confidence := InferLanguage(path.Base(parsed.Context().RepositoryStr()), parsed.Identifier())
	spec := ImageSpec{
		ID:    id,
		Image: ref,
		Language: catalog.LanguageInfo{
			ID:          lang.ID,
			DisplayName: lang.DisplayName,
			Version:     lang.Version,
		},
		Tier: defaultTier,
		Lifecycle: &catalog.Lifecycle{
			Status:            lifecycleStatus,
			Support:           "unsupported",
			ProductionAllowed: false,
		},
		Origin: &catalog.ImageOrigin{
			Kind:               "imported",
			CreatedByClearCutt: false,
			SourceRef:          ref,
			ObservedAt:         generatedAt,
			ObservationMode:    "explicit-list",
			ProvenanceClaim:    "none",
		},
		Governance: &catalog.ImageGovernance{
			Imported:                 true,
			Owner:                    owner,
			ClassificationConfidence: confidence,
			ProductionIntent:         "unknown",
			Notes:                    []string{},
		},
		EvidencePolicy: &catalog.EvidencePolicy{
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

func stableIDForRef(ref name.Reference) string {
	base := sanitizeID(path.Base(ref.Context().RepositoryStr()))
	id := base
	switch identifier := ref.Identifier(); {
	case strings.HasPrefix(identifier, "sha256:"):
		id = base + "-" + sanitizeID(identifier[:19])
	case identifier != "latest":
		id = base + "-" + sanitizeID(identifier)
	}
	for _, suffix := range []string{"-runtime", "-base", "-image"} {
		if strings.HasSuffix(id, suffix) {
			return strings.TrimSuffix(id, suffix) + suffix
		}
	}
	return strings.Trim(id, "-")
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
