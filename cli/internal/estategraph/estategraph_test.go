package estategraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

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
		Governance: &ImageGovernance{
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
		Governance: &ImageGovernance{
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
		Governance: &ImageGovernance{
			Imported:                 true,
			ClassificationConfidence: "high",
		},
		EvidencePolicy: &EvidencePolicy{Provenance: "optional"},
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
	requiredSpec.EvidencePolicy = &EvidencePolicy{Provenance: "required"}
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
	blockedSpec.Governance = &ImageGovernance{Imported: true, ClassificationConfidence: "high", ProductionIntent: "blocked"}
	blocked, err := Assess(ImagesFile{Images: []ImageSpec{blockedSpec}}, Observations{Images: []Observation{observation}}, AssessOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("Assess blocked failed: %v", err)
	}
	if got := blocked.Images[0].PolicyPosture; got != "blocked" {
		t.Fatalf("blocked production intent should produce blocked posture, got %q", got)
	}
}

func TestPolicyPostureRequiresVerifiedCurrentEvidence(t *testing.T) {
	spec := ImageSpec{Governance: &ImageGovernance{Imported: true, ClassificationConfidence: "high"}}
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

func TestImportedFleetDocsClaimBoundaries(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/imported-fleets.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, required := range []string{
		"ClearCutt Verify does not need to create an image to govern it",
		"It cannot infer SLSA provenance",
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

func language(id, display, version string) LanguageInfo {
	return LanguageInfo{ID: id, DisplayName: display, Version: version}
}

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
	gaps := runtimeContractGaps(ImageSpec{RuntimeContract: &RuntimeContract{
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
}

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
