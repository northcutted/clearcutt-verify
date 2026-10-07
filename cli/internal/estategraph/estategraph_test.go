package estategraph

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func TestRegistryObservationAndRuntimeGapBranches(t *testing.T) {
	if _, err := (RegistryObserver{}).Observe(context.Background(), "not a valid ref %%%"); err == nil {
		t.Fatal("invalid registry reference should fail")
	}
	image, err := random.Image(256, 2)
	if err != nil {
		t.Fatal(err)
	}
	config, err := image.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	config = config.DeepCopy()
	config.Created.Time = time.Unix(1_700_000_000, 0)
	config.OS = "linux"
	config.Architecture = "amd64"
	config.Config.User = "10001:10001"
	config.Config.Entrypoint = []string{"/app"}
	config.Config.Cmd = []string{"serve"}
	config.Config.Labels = map[string]string{"example": "value"}
	config.History = append(config.History, v1.History{CreatedBy: "build", Comment: "test", EmptyLayer: true})
	image, err = mutate.ConfigFile(image, config)
	if err != nil {
		t.Fatal(err)
	}
	observation := baseObservation("sample", "example/sample:1")
	fillImageObservation(&observation, image)
	if observation.ConfigDigest == "" || observation.Created == "" || observation.User != "10001:10001" || len(observation.Layers) != 2 || !contains(observation.Platforms, "linux/amd64") {
		t.Fatalf("incomplete image observation: %#v", observation)
	}

	trueValue, falseValue := true, false
	gaps := runtimeContractGaps(ImageSpec{RuntimeContract: &catalog.RuntimeContract{
		ShellPresent:          &trueValue,
		PackageManagerPresent: &trueValue,
		CACertificatesPresent: &falseValue,
		TimezoneDataPresent:   &falseValue,
	}}, Observation{User: "root"})
	for _, want := range []string{"root user", "shell present", "package manager present", "no CA certificates", "no timezone data"} {
		if !contains(gaps, want) {
			t.Fatalf("runtime gaps %v missing %q", gaps, want)
		}
	}
	if got := observationPlatforms(Observation{}, []string{"amd64", "linux/arm64", ""}); !reflect.DeepEqual(got, []string{"linux/amd64", "linux/arm64"}) {
		t.Fatalf("platform fallback = %v", got)
	}
}

func TestImportRefsInfersLanguagesAndUnknowns(t *testing.T) {
	refsPath := filepath.Join(t.TempDir(), "refs.txt")
	if err := os.WriteFile(refsPath, []byte(strings.Join([]string{
		"registry.example.com/platform/java21-runtime:2026.07.01",
		"registry.example.com/platform/node24-runtime:2026.07.01",
		"registry.example.com/platform/mystery-box:latest",
	}, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	inventory, summary, err := ImportRefs(ImportOptions{
		RefsPath:         refsPath,
		Owner:            "acme",
		Repo:             "imported-fleet",
		RegistryBase:     "registry.example.com/platform/",
		DefaultTier:      "slim",
		DefaultLifecycle: "active",
		GeneratedAt:      "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("ImportRefs failed: %v", err)
	}
	if len(inventory.Images) != 3 || summary.ImageCount != 3 {
		t.Fatalf("unexpected image count: inventory=%d summary=%d", len(inventory.Images), summary.ImageCount)
	}
	if summary.LowConfidence != 1 {
		t.Fatalf("expected one low-confidence image, got %d", summary.LowConfidence)
	}
	if inventory.Owner != "acme" || inventory.Repo != "imported-fleet" || inventory.RegistryBase != "registry.example.com/platform" {
		t.Fatalf("import metadata was not preserved: %+v", inventory)
	}
	byID := map[string]ImageSpec{}
	for _, image := range inventory.Images {
		byID[image.ID] = image
		if image.Origin == nil || image.Origin.Kind != "imported" || image.Origin.CreatedByClearCutt {
			t.Fatalf("%s missing imported origin metadata", image.ID)
		}
		if image.Origin.ProvenanceClaim != "none" {
			t.Fatalf("%s should not claim provenance, got %q", image.ID, image.Origin.ProvenanceClaim)
		}
	}
	if byID["java21-runtime-2026-07-01"].Language.ID != "java" || byID["java21-runtime-2026-07-01"].Language.Version != "21" {
		t.Fatalf("java inference failed: %+v", byID["java21-runtime-2026-07-01"].Language)
	}
	if byID["mystery-box"].Language.ID != "unknown" || byID["mystery-box"].Governance.ClassificationConfidence != "low" {
		t.Fatalf("unknown classification failed: %+v", byID["mystery-box"])
	}
}

func TestObserveImagesRecordsFailuresUnlessStrict(t *testing.T) {
	inventory := ImagesFile{Images: []ImageSpec{
		{ID: "known", Image: "registry.example.com/known:1"},
		{ID: "missing", Image: "registry.example.com/missing:1"},
	}}
	fixture := Observations{Images: []Observation{{ID: "known", SourceRef: "registry.example.com/known:1", DigestRef: "registry.example.com/known@sha256:abc"}}}
	observations, _, err := ObserveImages(context.Background(), inventory, NewFixtureObserver(fixture), ObserveOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("ObserveImages failed: %v", err)
	}
	if len(observations.Images) != 2 {
		t.Fatalf("expected two observations, got %d", len(observations.Images))
	}
	if len(observations.Images[1].Warnings) == 0 {
		t.Fatalf("expected missing fixture warning: %+v", observations.Images[1])
	}
	if _, _, err := ObserveImages(context.Background(), inventory, NewFixtureObserver(fixture), ObserveOptions{Strict: true}); err == nil {
		t.Fatalf("strict observation should fail when a fixture is missing")
	}
}

func TestAssessDowngradesUnverifiedImportedClaims(t *testing.T) {
	inventory := ImagesFile{Images: []ImageSpec{{
		ID:       "java21",
		Image:    "registry.example.com/java21:1",
		Language: language("java", "Java", "21"),
		Tier:     "slim",
		Governance: &catalog.ImageGovernance{
			Imported:                 true,
			ClassificationConfidence: "low",
		},
	}}}
	observations := Observations{Images: []Observation{{
		ID:        "java21",
		SourceRef: "registry.example.com/java21:1",
		Evidence: EvidenceObservation{
			Signature:         EvidenceChannel{Status: "verified", Source: "cosign"},
			SBOM:              EvidenceChannel{Status: "observed", Source: "user-supplied"},
			Provenance:        EvidenceChannel{Status: "missing", Source: "none"},
			VulnerabilityScan: EvidenceChannel{Status: "missing", Source: "none"},
			Tests:             EvidenceChannel{Status: "missing", Source: "none"},
		},
	}}}
	assessment, err := Assess(inventory, observations, AssessOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}
	if assessment.Summary.VerifiedEvidenceByChannel["signature"] != 0 || assessment.Summary.ObservedEvidenceByChannel["signature"] != 1 {
		t.Fatalf("self-asserted signature must be observed, not verified: observed=%+v verified=%+v", assessment.Summary.ObservedEvidenceByChannel, assessment.Summary.VerifiedEvidenceByChannel)
	}
	if assessment.Summary.ObservedEvidenceByChannel["sbom"] != 1 || assessment.Summary.VerifiedEvidenceByChannel["sbom"] != 0 {
		t.Fatalf("sbom should be observed but not verified: observed=%+v verified=%+v", assessment.Summary.ObservedEvidenceByChannel, assessment.Summary.VerifiedEvidenceByChannel)
	}
	if assessment.Summary.MissingEvidenceByChannel["provenance"] != 1 {
		t.Fatalf("provenance should remain missing: %+v", assessment.Summary.MissingEvidenceByChannel)
	}
	if len(assessment.Images[0].Warnings) == 0 || !strings.Contains(assessment.Images[0].Warnings[0], "downgraded") {
		t.Fatalf("downgrade should be explicit in warnings: %+v", assessment.Images[0].Warnings)
	}
}

func TestAssessDoesNotCountAttestedSBOMAsVerified(t *testing.T) {
	inventory := ImagesFile{Images: []ImageSpec{{
		ID:       "java21",
		Image:    "registry.example.com/java21@sha256:abc",
		Language: language("java", "Java", "21"),
		Tier:     "slim",
		Governance: &catalog.ImageGovernance{
			Imported:                 true,
			ClassificationConfidence: "high",
		},
	}}}
	observations := Observations{Images: []Observation{{
		ID:        "java21",
		SourceRef: "registry.example.com/java21@sha256:abc",
		DigestRef: "registry.example.com/java21@sha256:abc",
		User:      "65532",
		Evidence: EvidenceObservation{
			Signature:         EvidenceChannel{Status: "verified", Source: "cosign"},
			SBOM:              EvidenceChannel{Status: "attested", Source: "sbom-attestation"},
			Provenance:        EvidenceChannel{Status: "missing", Source: "none"},
			VulnerabilityScan: EvidenceChannel{Status: "missing", Source: "none"},
			Tests:             EvidenceChannel{Status: "missing", Source: "none"},
		},
	}}}
	assessment, err := Assess(inventory, observations, AssessOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}
	if assessment.Summary.ObservedEvidenceByChannel["sbom"] != 1 {
		t.Fatalf("attested SBOM should count as observed evidence: %+v", assessment.Summary.ObservedEvidenceByChannel)
	}
	if assessment.Summary.VerifiedEvidenceByChannel["sbom"] != 0 {
		t.Fatalf("attested SBOM should not count as verified evidence: %+v", assessment.Summary.VerifiedEvidenceByChannel)
	}
}

func TestAssessPolicyTurnsMissingRequiredProvenanceIntoReview(t *testing.T) {
	baseSpec := ImageSpec{
		ID:       "java21",
		Image:    "registry.example.com/java21@sha256:abc",
		Language: language("java", "Java", "21"),
		Tier:     "slim",
		Governance: &catalog.ImageGovernance{
			Imported:                 true,
			ClassificationConfidence: "high",
		},
		EvidencePolicy: &catalog.EvidencePolicy{Provenance: "optional"},
	}
	observation := Observation{
		ID:        "java21",
		SourceRef: "registry.example.com/java21@sha256:abc",
		DigestRef: "registry.example.com/java21@sha256:abc",
		User:      "65532",
		Evidence: EvidenceObservation{
			Signature:         EvidenceChannel{Status: "missing", Source: "none"},
			SBOM:              EvidenceChannel{Status: "missing", Source: "none"},
			Provenance:        EvidenceChannel{Status: "missing", Source: "none"},
			VulnerabilityScan: EvidenceChannel{Status: "missing", Source: "none"},
			Tests:             EvidenceChannel{Status: "missing", Source: "none"},
		},
	}

	optional, err := Assess(ImagesFile{Images: []ImageSpec{baseSpec}}, Observations{Images: []Observation{observation}}, AssessOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("Assess optional failed: %v", err)
	}
	if got := optional.Images[0].PolicyPosture; got == "review-required" || got == "blocked" {
		t.Fatalf("optional missing provenance should not force review/blocked posture, got %q", got)
	}

	requiredSpec := baseSpec
	requiredSpec.EvidencePolicy = &catalog.EvidencePolicy{Provenance: "required"}
	required, err := Assess(ImagesFile{Images: []ImageSpec{requiredSpec}}, Observations{Images: []Observation{observation}}, AssessOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("Assess required failed: %v", err)
	}
	if got := required.Images[0].PolicyPosture; got != "review-required" {
		t.Fatalf("required missing provenance should force review-required posture, got %q", got)
	}

	observedRequired := observation
	observedRequired.Evidence.Provenance = EvidenceChannel{Status: "observed", Source: "fixture"}
	observed, err := Assess(ImagesFile{Images: []ImageSpec{requiredSpec}}, Observations{Images: []Observation{observedRequired}}, AssessOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("Assess observed required evidence failed: %v", err)
	}
	if got := observed.Images[0].PolicyPosture; got != "review-required" {
		t.Fatalf("observed required provenance must not satisfy policy, got %q", got)
	}

	blockedSpec := baseSpec
	blockedSpec.Governance = &catalog.ImageGovernance{Imported: true, ClassificationConfidence: "high", ProductionIntent: "blocked"}
	blocked, err := Assess(ImagesFile{Images: []ImageSpec{blockedSpec}}, Observations{Images: []Observation{observation}}, AssessOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("Assess blocked failed: %v", err)
	}
	if got := blocked.Images[0].PolicyPosture; got != "blocked" {
		t.Fatalf("blocked production intent should produce blocked posture, got %q", got)
	}
}

func TestPolicyPostureRequiresVerifiedCurrentEvidence(t *testing.T) {
	spec := ImageSpec{Governance: &catalog.ImageGovernance{Imported: true, ClassificationConfidence: "high"}}
	item := ImageAssessment{DigestRef: "registry.example.com/image@sha256:abc"}
	stale := map[string]EvidenceChannel{}
	verified := map[string]EvidenceChannel{}
	for _, channel := range []string{"signature", "sbom", "provenance", "vulnerabilityScan", "tests"} {
		stale[channel] = EvidenceChannel{Status: "stale"}
		verified[channel] = EvidenceChannel{Status: "verified"}
	}
	if got := policyPosture(item, spec, stale); got == "production-admissible" {
		t.Fatalf("stale evidence must not be production-admissible")
	}
	if got := policyPosture(item, spec, verified); got != "production-admissible" {
		t.Fatalf("all verified evidence should be production-admissible, got %q", got)
	}
}

func TestRootUserWithGroupIsRuntimeGap(t *testing.T) {
	for _, user := range []string{"0:0", "0:root", "root:root", " ROOT : users "} {
		gaps := runtimeContractGaps(ImageSpec{}, Observation{User: user})
		if len(gaps) == 0 || gaps[0] != "root user" {
			t.Fatalf("%q should be classified as root: %+v", user, gaps)
		}
	}
	if gaps := runtimeContractGaps(ImageSpec{}, Observation{User: "65532:65532"}); len(gaps) != 0 {
		t.Fatalf("non-root user should not be flagged: %+v", gaps)
	}
}

func TestAssessRejectsInvalidCatalogPath(t *testing.T) {
	_, err := Assess(ImagesFile{}, Observations{}, AssessOptions{CatalogPath: filepath.Join(t.TempDir(), "missing")})
	if err == nil || !strings.Contains(err.Error(), "load assessment catalog") {
		t.Fatalf("expected catalog load failure, got %v", err)
	}
}

func TestDiscoverRebaseCandidatesConfidence(t *testing.T) {
	bases := ImagesFile{Images: []ImageSpec{
		{ID: "java21-old", Image: "registry.example.com/java21:1", Language: language("java", "Java", "21"), Tier: "runtime"},
		{ID: "java21-new", Image: "registry.example.com/java21:2", Language: language("java", "Java", "21"), Tier: "runtime"},
		{ID: "node24", Image: "registry.example.com/node24:1", Language: language("node", "Node.js", "24")},
	}}
	observations := Observations{Images: []Observation{
		{ID: "java21-old", SourceRef: "registry.example.com/java21:1", DigestRef: "registry.example.com/java21@sha256:base", Platforms: []string{"linux/amd64"}, Layers: []LayerObservation{{Digest: "sha256:base1"}, {Digest: "sha256:base2"}}},
		{ID: "java21-new", SourceRef: "registry.example.com/java21:2", DigestRef: "registry.example.com/java21@sha256:new", Platforms: []string{"linux/amd64", "linux/arm64"}, Layers: []LayerObservation{{Digest: "sha256:new1"}, {Digest: "sha256:new2"}}},
		{ID: "node24", SourceRef: "registry.example.com/node24:1", DigestRef: "registry.example.com/node24@sha256:node", Platforms: []string{"linux/amd64"}, Layers: []LayerObservation{{Digest: "sha256:node1"}}},
		{ID: "verified-app", SourceRef: "registry.example.com/verified-app:1", DigestRef: "registry.example.com/verified-app@sha256:app", Platforms: []string{"linux/amd64"}, Layers: []LayerObservation{{Digest: "sha256:base1"}, {Digest: "sha256:base2"}, {Digest: "sha256:app"}}},
		{ID: "assisted-app", SourceRef: "registry.example.com/assisted-app:1", DigestRef: "registry.example.com/assisted-app@sha256:app2", Platforms: []string{"linux/amd64"}, Labels: map[string]string{"org.opencontainers.image.base.name": "java21-old"}},
		{ID: "unsafe-app", SourceRef: "registry.example.com/unsafe-app:1", DigestRef: "registry.example.com/unsafe-app@sha256:app3", Platforms: []string{"linux/amd64"}, Layers: []LayerObservation{{Digest: "sha256:other"}}},
	}}
	apps := AppInventory{Apps: []AppSpec{
		{ID: "verified-app", Image: "registry.example.com/verified-app:1", RuntimeFamily: "java", ExpectedBase: "java21-old"},
		{ID: "assisted-app", Image: "registry.example.com/assisted-app:1", RuntimeFamily: "java", ExpectedBase: "java21-old"},
		{ID: "unsafe-app", Image: "registry.example.com/unsafe-app:1", RuntimeFamily: "node", ExpectedBase: "java21-old"},
	}}
	candidates, err := DiscoverRebaseCandidates(apps, bases, observations, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("DiscoverRebaseCandidates failed: %v", err)
	}
	byID := map[string]RebaseCandidate{}
	for _, candidate := range candidates.Candidates {
		byID[candidate.ID] = candidate
	}
	if byID["verified-app"].Confidence != "verified" {
		t.Fatalf("expected verified candidate: %+v", byID["verified-app"])
	}
	if got, want := byID["verified-app"].NewBaseCandidates, []string{"java21-new@sha256:new"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("new base candidates = %v, want %v", got, want)
	}
	if byID["assisted-app"].Confidence != "assisted" {
		t.Fatalf("expected assisted candidate: %+v", byID["assisted-app"])
	}
	if byID["unsafe-app"].Confidence != "unsafe" {
		t.Fatalf("expected unsafe candidate: %+v", byID["unsafe-app"])
	}
	if _, err := PlanRebase(candidates, "unsafe-app", "node24@sha256:node", observations); err == nil {
		t.Fatalf("unsafe candidate should not produce a plan")
	}
	plan, err := PlanRebase(candidates, "verified-app", "java21-new@sha256:new", observations)
	if err != nil {
		t.Fatalf("verified replacement should produce a plan: %v", err)
	}
	if plan.OldBase.ID == plan.NewBase.ID || plan.OldBase.Digest == plan.NewBase.Digest {
		t.Fatalf("rebase plan did not select a replacement: %+v", plan)
	}
	if _, err := PlanRebase(candidates, "verified-app", "java21-old@sha256:base", observations); err == nil {
		t.Fatal("same base should not produce a plan")
	}
}

func TestDiscoverRebaseCandidatesExcludesIncompatibleReplacement(t *testing.T) {
	trueValue, falseValue := true, false
	bases := ImagesFile{Images: []ImageSpec{
		{ID: "old", Image: "example/old:1", Language: language("java", "Java", "21"), Tier: "runtime", RuntimeContract: &catalog.RuntimeContract{ShellPresent: &falseValue}},
		{ID: "wrong-contract", Image: "example/wrong:2", Language: language("java", "Java", "21"), Tier: "runtime", RuntimeContract: &catalog.RuntimeContract{ShellPresent: &trueValue}},
		{ID: "wrong-platform", Image: "example/arm:2", Language: language("java", "Java", "21"), Tier: "runtime", RuntimeContract: &catalog.RuntimeContract{ShellPresent: &falseValue}},
	}}
	observations := Observations{Images: []Observation{
		{ID: "old", SourceRef: "example/old:1", DigestRef: "example/old@sha256:old", Platforms: []string{"linux/amd64"}, Layers: []LayerObservation{{Digest: "sha256:old"}}},
		{ID: "wrong-contract", SourceRef: "example/wrong:2", DigestRef: "example/wrong@sha256:new1", Platforms: []string{"linux/amd64"}, Layers: []LayerObservation{{Digest: "sha256:new1"}}},
		{ID: "wrong-platform", SourceRef: "example/arm:2", DigestRef: "example/arm@sha256:new2", Platforms: []string{"linux/arm64"}, Layers: []LayerObservation{{Digest: "sha256:new2"}}},
		{ID: "app", SourceRef: "example/app:1", DigestRef: "example/app@sha256:app", Platforms: []string{"linux/amd64"}, Layers: []LayerObservation{{Digest: "sha256:old"}, {Digest: "sha256:app"}}},
	}}
	result, err := DiscoverRebaseCandidates(AppInventory{Apps: []AppSpec{{ID: "app", Image: "example/app:1", RuntimeFamily: "java", ExpectedBase: "old"}}}, bases, observations, "now")
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Candidates[0].NewBaseCandidates; len(got) != 0 {
		t.Fatalf("incompatible replacement candidates = %v, want none", got)
	}
}

func TestImportedFleetDocsClaimBoundaries(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/imported-fleets.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, required := range []string{
		"ClearCutt does not need to create an image to govern it",
		"It cannot infer SLSA provenance",
		"It does not require Nix",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("docs/imported-fleets.md missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"imported images have provenance by default",
		"imported-fleet mode requires Nix",
		"fork first",
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(forbidden)) {
			t.Fatalf("docs/imported-fleets.md contains forbidden claim %q", forbidden)
		}
	}
}

func language(id, display, version string) catalog.LanguageInfo {
	return catalog.LanguageInfo{ID: id, DisplayName: display, Version: version}
}
