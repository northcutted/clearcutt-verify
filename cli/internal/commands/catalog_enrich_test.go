package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
	"github.com/northcutted/clearcutt-verify/internal/oci"
	"github.com/northcutted/clearcutt-verify/internal/sign"
)

func TestCatalogEnrichTagSelection(t *testing.T) {
	old := catalogEnrichOpts
	t.Cleanup(func() { catalogEnrichOpts = old })

	catalogEnrichOpts.tags = " v2.0.0, ,v1.0.0 "
	tags, err := catalogEnrichTags("acme", "clearcutt")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tags, []string{"v2.0.0", "v1.0.0"}) {
		t.Fatalf("unexpected explicit tags: %#v", tags)
	}

	refresh := enrichTagSet(tags, false, "v1.0.0, v9.9.9")
	if !refresh["v1.0.0"] || !refresh["v9.9.9"] || refresh["v2.0.0"] {
		t.Fatalf("unexpected refresh set: %#v", refresh)
	}
	refresh = enrichTagSet(tags, true, "")
	if !refresh["v2.0.0"] || !refresh["v1.0.0"] {
		t.Fatalf("force-all did not mark every tag: %#v", refresh)
	}
}

func TestCatalogEnrichCommandUsesCachedRecordsOffline(t *testing.T) {
	outDir := t.TempDir()
	writeTestFile(t, filepath.Join(outDir, "v1.0.0", "python3.13-slim.json"), []byte(`{"manifestDigest":"sha256:cached","architectures":[],"attestations":[]}`))
	stdout, err := runCLI(t,
		"catalog", "enrich",
		"--owner", "acme",
		"--repo", "clearcutt",
		"--tags", "v1.0.0",
		"--targets", "python3.13-slim",
		"--out-dir", outDir,
		"--cosign-path", filepath.Join(t.TempDir(), "missing-cosign"),
	)
	if err != nil {
		t.Fatalf("cached enrich failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "[enrich] done fetched=0 cached=1") {
		t.Fatalf("expected cached enrich summary, got:\n%s", stdout)
	}
}

func TestCatalogEnrichmentArchitectureFromImageAndIndex(t *testing.T) {
	amd64 := commandTestImage(t, 101)
	manifest, err := amd64.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	var layerSum int64
	for _, layer := range manifest.Layers {
		layerSum += layer.Size
	}
	if layerSum == 0 {
		t.Fatal("test image has no layer bytes")
	}
	arch, err := enrichmentArchitecture("amd64", 1234, amd64)
	if err != nil {
		t.Fatal(err)
	}
	if arch.Arch != "amd64" || arch.Size == nil || *arch.Size != layerSum || len(arch.Layers) == 0 || len(arch.Labels) == 0 {
		t.Fatalf("expected image size %d (compressed layer sum): %#v", layerSum, arch)
	}
	if arch.ManifestDescriptorSize == nil || *arch.ManifestDescriptorSize != 1234 {
		t.Fatalf("expected manifest descriptor size 1234: %#v", arch)
	}
	if arch.Digest != nil {
		t.Fatalf("direct architecture helper should not set descriptor digest: %#v", arch)
	}

	noDesc, err := enrichmentArchitecture("amd64", 0, amd64)
	if err != nil {
		t.Fatal(err)
	}
	if noDesc.Size == nil || *noDesc.Size != layerSum {
		t.Fatalf("expected layer-sum image size without descriptor: %#v", noDesc)
	}
	if noDesc.ManifestDescriptorSize != nil {
		t.Fatalf("expected no manifest descriptor size when descriptor is absent: %#v", noDesc)
	}

	arm64 := commandTestImage(t, 202)
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd64, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}, Size: 111}},
		mutate.IndexAddendum{Add: arm64, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}, Size: 222}},
	)
	arches, err := enrichmentArchitectures(&oci.Resolved{IsIndex: true, Index: index})
	if err != nil {
		t.Fatal(err)
	}
	if len(arches) != 2 || arches[0].Digest == nil || arches[1].Digest == nil {
		t.Fatalf("expected two indexed architecture enrichments with digests: %#v", arches)
	}
	if arches[0].ManifestDescriptorSize == nil || *arches[0].ManifestDescriptorSize != 111 {
		t.Fatalf("expected first indexed enrichment to carry descriptor size 111: %#v", arches[0])
	}
	if arches[0].Size == nil || *arches[0].Size != layerSum {
		t.Fatalf("expected first indexed enrichment image size %d: %#v", layerSum, arches[0])
	}

	imageArches, err := enrichmentArchitectures(&oci.Resolved{Image: amd64})
	if err != nil {
		t.Fatal(err)
	}
	if len(imageArches) != 1 || imageArches[0].Digest == nil {
		t.Fatalf("expected single image enrichment with digest: %#v", imageArches)
	}
}

func TestCosignAttestationParsingAndNormalization(t *testing.T) {
	cert := testCertificate(t)
	certDER := cert.Raw
	provenancePayload := map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []any{map[string]any{
			"name":   "ghcr.io/acme/clearcutt/clearcutt-java21",
			"digest": map[string]any{"sha256": "abcd"},
		}},
		"predicate": map[string]any{
			"builder":   map[string]any{"id": "builder-id"},
			"buildType": "https://slsa.dev/container",
			"runDetails": map[string]any{
				"metadata": map[string]any{"invocationId": "https://github.com/acme/clearcutt/actions/runs/1/attempts/1"},
			},
			"materials": []any{map[string]any{
				"uri":    "https://github.com/acme/clearcutt",
				"digest": map[string]any{"gitCommit": "abc123"},
			}},
		},
	}
	testPayload := map[string]any{
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": []any{map[string]any{
			"name":   "ghcr.io/acme/clearcutt/clearcutt-java21",
			"digest": map[string]any{"sha512": "beef"},
		}},
		"predicate": map[string]any{
			"Data": `{"status":"passed","assertions":[{"name":"smoke","status":"passed"}]}`,
		},
	}

	line := bundleJSON(t, provenancePayload, certDER, 77)
	att, err := parseCosignAttestation(line)
	if err != nil {
		t.Fatal(err)
	}
	if att.PredicateType != "https://slsa.dev/provenance/v1" || att.Cert == nil {
		t.Fatalf("unexpected parsed attestation: %#v", att)
	}
	if got := att.dedupeKey(); !strings.Contains(got, "sha256:abcd") {
		t.Fatalf("dedupe key should include subject digest, got %q", got)
	}

	enricher := &registryCatalogEnricher{owner: "acme", repo: "clearcutt"}
	normalized := enricher.normalizeAttestation(*att, "oci", strPtr("https://api.github.com/users/acme/attestations/sha256:abcd"))
	if normalized == nil {
		t.Fatal("expected normalized attestation")
	}
	if normalized.Kind != "slsa-provenance" || normalized.SubjectDigest == nil || *normalized.SubjectDigest != "sha256:abcd" {
		t.Fatalf("unexpected normalized attestation: %#v", normalized)
	}
	if normalized.TransparencyLogIndex == nil || *normalized.TransparencyLogIndex != 77 || normalized.TransparencyURL == nil {
		t.Fatalf("expected transparency metadata: %#v", normalized)
	}
	if normalized.WorkflowURL == nil || !strings.Contains(*normalized.WorkflowURL, "release.yml") {
		t.Fatalf("expected workflow URL from signer identity: %#v", normalized)
	}

	prov := provenanceFromPayload(provenancePayload)
	if prov == nil || prov.Builder.ID != "builder-id" || prov.SourceRevision == nil || *prov.SourceRevision != "abc123" {
		t.Fatalf("unexpected provenance summary: %#v", prov)
	}
	tests := extractCosignTestResults(testPayload)
	if tests == nil || tests.Status != "passed" || len(tests.Assertions) != 1 {
		t.Fatalf("unexpected test result payload: %#v", tests)
	}
	for _, tc := range []struct {
		name string
		in   map[string]any
		want string
	}{
		{"provenance", provenancePayload, "slsa-provenance"},
		{"test results", testPayload, "test-results"},
		{"sbom", map[string]any{"predicateType": "https://spdx.dev/Document"}, "sbom"},
		{"custom", map[string]any{"predicateType": "https://example.invalid/custom"}, "custom"},
	} {
		if got := attestationKind(tc.in); got != tc.want {
			t.Fatalf("%s kind = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCatalogEnrichmentMergeAndCertificateMetadata(t *testing.T) {
	cert := testCertificate(t)
	logIndex := int64(88)
	runURL := "https://github.com/acme/clearcutt/actions/runs/1/attempts/1"
	workflowURL := "https://github.com/acme/clearcutt/actions/workflows/release.yml"
	subject := "sha256:abcd"
	apiURL := "https://api.github.com/users/acme/attestations/sha256:abcd"
	input := []catalogbuild.EnrichmentAttestation{
		{Kind: "test-results", PredicateType: "https://cosign.sigstore.dev/attestation/v1", SubjectDigest: &subject, Sources: []string{"oci"}},
		{Kind: "slsa-provenance", PredicateType: "https://slsa.dev/provenance/v1", SubjectDigest: &subject, RunURL: &runURL, TransparencyLogIndex: &logIndex, Sources: []string{"oci"}},
		{Kind: "slsa-provenance", PredicateType: "https://slsa.dev/provenance/v1", SubjectDigest: &subject, WorkflowURL: &workflowURL, GithubAPIURL: &apiURL, RunURL: &runURL, TransparencyLogIndex: &logIndex, Sources: []string{"github"}},
	}
	merged := mergeEnrichmentAttestations(input)
	if len(merged) != 2 {
		t.Fatalf("expected duplicate SLSA attestations to merge, got %#v", merged)
	}
	if merged[0].Kind != "slsa-provenance" || !catalogbuild.StringSliceContains(merged[0].Sources, "oci") || !catalogbuild.StringSliceContains(merged[0].Sources, "github") {
		t.Fatalf("unexpected merged order/sources: %#v", merged)
	}
	if merged[0].GithubAPIURL == nil || merged[0].WorkflowURL == nil {
		t.Fatalf("expected merged optional URLs: %#v", merged[0])
	}

	enricher := &registryCatalogEnricher{owner: "acme", repo: "clearcutt"}
	meta := enricher.signatureCertMetadata([]cosignAttestation{{
		Payload: map[string]any{"predicate": map[string]any{"runDetails": map[string]any{"metadata": map[string]any{"invocationId": runURL}}}},
		Cert:    cert,
	}})
	if meta == nil || meta.Subject == nil || !strings.Contains(*meta.Subject, "github.com/acme/clearcutt") || meta.RunInvocation == nil {
		t.Fatalf("unexpected signature cert metadata: %#v", meta)
	}
}

func TestCatalogEnrichmentGithubAndCosignSources(t *testing.T) {
	certDER := testCertificate(t).Raw
	payload := map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []any{map[string]any{
			"name":   "ghcr.io/acme/clearcutt/clearcutt-java21",
			"digest": map[string]any{"sha256": "abcd"},
		}},
		"predicate": map[string]any{"builder": map[string]any{"id": "builder-id"}},
	}
	bundleLine := bundleJSON(t, payload, certDER, 101)

	cosignPath := writeFakeCosign(t, []byte(`[{"optional":{"Bundle":{"Payload":{"logIndex":123}},"Subject":"https://github.com/acme/clearcutt/.github/workflows/release.yml@refs/heads/main","Issuer":"https://token.actions.githubusercontent.com"}}]`), bundleLine)
	cosign := sign.New(cosignPath, `^https://github\.com/acme/clearcutt/`, "https://token.actions.githubusercontent.com", out, errOut)
	enricher := &registryCatalogEnricher{
		owner:  "acme",
		repo:   "clearcutt",
		cosign: cosign,
		github: &githubReleaseSource{
			owner: "acme",
			repo:  "clearcutt",
			client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, "/users/acme/") {
					return textResponse(404, `{}`), nil
				}
				body := `{"attestations":[{"bundle":` + string(bundleLine) + `}]}`
				return textResponse(200, body), nil
			})},
		},
	}

	sig := enricher.verifySignature("ghcr.io/acme/clearcutt/clearcutt-java21:v1")
	if sig == nil || sig.RekorLogIndex == nil || *sig.RekorLogIndex != 123 || sig.Certificate == nil || sig.Certificate.Subject == nil {
		t.Fatalf("unexpected fake cosign signature: %#v", sig)
	}
	atts := enricher.downloadAttestations("ghcr.io/acme/clearcutt/clearcutt-java21:v1")
	if len(atts) != 1 || atts[0].PredicateType != "https://slsa.dev/provenance/v1" {
		t.Fatalf("unexpected downloaded attestations: %#v", atts)
	}
	gh := enricher.listGithubAttestations(strPtr("sha256:abcd"))
	if len(gh) != 1 || gh[0].GithubAPIURL == nil || !strings.Contains(*gh[0].GithubAPIURL, "/orgs/acme/") {
		t.Fatalf("unexpected GitHub attestations: %#v", gh)
	}

	if got := (&registryCatalogEnricher{}).listGithubAttestations(nil); got != nil {
		t.Fatalf("nil digest should not query GitHub: %#v", got)
	}
	if out, err := (&registryCatalogEnricher{}).Enrich("v1", "not-a-target"); err != nil || out != nil {
		t.Fatalf("invalid target should be ignored, got out=%#v err=%v", out, err)
	}
}

func TestRegistryCatalogEnricherPullsRegistryEvidenceAndMergesAttestations(t *testing.T) {
	client, host := commandTestRegistry(t)
	img := commandTestImage(t, 909)
	digest, err := client.PushImage(host+"/clearcutt-java21:v1.0.0-slim", img)
	if err != nil {
		t.Fatalf("push image: %v", err)
	}
	manifestHash := strings.TrimPrefix(digest, "sha256:")

	certDER := testCertificate(t).Raw
	provenancePayload := map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []any{map[string]any{
			"name":   host + "/clearcutt-java21",
			"digest": map[string]any{"sha256": manifestHash},
		}},
		"predicate": map[string]any{
			"builder":   map[string]any{"id": "https://github.com/actions/runner"},
			"buildType": "https://slsa.dev/container",
			"runDetails": map[string]any{
				"metadata": map[string]any{"invocationId": "https://github.com/acme/clearcutt/actions/runs/909/attempts/1"},
			},
		},
	}
	testPayload := map[string]any{
		"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		"subject": []any{map[string]any{
			"name":   host + "/clearcutt-java21",
			"digest": map[string]any{"sha256": manifestHash},
		}},
		"predicate": map[string]any{
			"Data": `{"status":"passed","timestamp":"2026-02-01T00:00:00Z","assertions":[{"name":"smoke","status":"passed"}]}`,
		},
	}
	provenanceBundle := bundleJSON(t, provenancePayload, certDER, 501)
	testBundle := bundleJSON(t, testPayload, certDER, 502)
	verifyJSON := []byte(`[{"optional":{"Bundle":{"payload":{"logIndex":"500"}},"Subject":"https://github.com/acme/clearcutt/.github/workflows/release.yml@refs/heads/main"}}]`)
	cosignPath := writeFakeCosign(t, verifyJSON, append(append(provenanceBundle, '\n'), testBundle...))
	cosign := sign.New(cosignPath, `^https://github\.com/acme/clearcutt/`, "https://token.actions.githubusercontent.com", out, errOut)

	enricher := &registryCatalogEnricher{
		owner:        "acme",
		repo:         "clearcutt",
		registryBase: host,
		oci:          client,
		cosign:       cosign,
		github: &githubReleaseSource{
			owner: "acme",
			repo:  "clearcutt",
			client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, "/users/acme/") {
					return textResponse(404, `{}`), nil
				}
				return textResponse(200, `{"attestations":[{"bundle":`+string(provenanceBundle)+`}]}`), nil
			})},
		},
	}

	enrichment, err := enricher.Enrich("v1.0.0", "java21-slim")
	if err != nil {
		t.Fatalf("enrich failed: %v", err)
	}
	if enrichment == nil || enrichment.ManifestDigest == nil || *enrichment.ManifestDigest != digest {
		t.Fatalf("unexpected enrichment digest: %#v", enrichment)
	}
	if len(enrichment.Architectures) != 1 || enrichment.Architectures[0].Digest == nil || enrichment.Architectures[0].Size == nil {
		t.Fatalf("expected one enriched architecture: %#v", enrichment.Architectures)
	}
	if enrichment.Signature == nil || enrichment.Signature.RekorLogIndex == nil || *enrichment.Signature.RekorLogIndex != 500 {
		t.Fatalf("expected signature evidence from fake cosign: %#v", enrichment.Signature)
	}
	if enrichment.Signature.Certificate == nil || enrichment.Signature.Certificate.Subject == nil ||
		!strings.Contains(*enrichment.Signature.Certificate.Subject, "github.com/acme/clearcutt") {
		t.Fatalf("expected release workflow certificate metadata: %#v", enrichment.Signature)
	}
	if enrichment.Provenance == nil || enrichment.Provenance.Builder.ID != "https://github.com/actions/runner" {
		t.Fatalf("expected SLSA provenance summary: %#v", enrichment.Provenance)
	}
	if enrichment.TestResults == nil || enrichment.TestResults.Status != "passed" || len(enrichment.TestResults.Assertions) != 1 {
		t.Fatalf("expected cosign test-results attestation: %#v", enrichment.TestResults)
	}
	if len(enrichment.Attestations) != 2 {
		t.Fatalf("expected merged SLSA and test attestations, got %#v", enrichment.Attestations)
	}
	if enrichment.Attestations[0].Kind != "slsa-provenance" ||
		!catalogbuild.StringSliceContains(enrichment.Attestations[0].Sources, "oci") ||
		!catalogbuild.StringSliceContains(enrichment.Attestations[0].Sources, "github") {
		t.Fatalf("expected merged OCI/GitHub SLSA sources first, got %#v", enrichment.Attestations)
	}
}

func TestRegistryCatalogEnricherUsesConfiguredImagePrefix(t *testing.T) {
	client, host := commandTestRegistry(t)
	img := commandTestImage(t, 707)
	digest, err := client.PushImage(host+"/platform-java21:v1.0.0-slim", img)
	if err != nil {
		t.Fatalf("push image: %v", err)
	}

	enricher := &registryCatalogEnricher{
		owner:        "acme",
		repo:         "platform",
		registryBase: host,
		imagePrefix:  "platform",
		oci:          client,
	}
	enrichment, err := enricher.Enrich("v1.0.0", "java21-slim")
	if err != nil {
		t.Fatalf("enrich failed: %v", err)
	}
	if enrichment == nil || enrichment.ManifestDigest == nil || *enrichment.ManifestDigest != digest {
		t.Fatalf("expected enrichment from configured image prefix, got %#v", enrichment)
	}
}

func TestRegistryCatalogEnricherPullsServiceEvidence(t *testing.T) {
	client, host := commandTestRegistry(t)
	img := commandTestImage(t, 808)
	digest, err := client.PushImage(host+"/clearcutt-postgres16:v1.0.0-service", img)
	if err != nil {
		t.Fatalf("push service image: %v", err)
	}
	verifyJSON := []byte(`[{"optional":{"Bundle":{"payload":{"logIndex":"700"}},"Subject":"https://github.com/acme/clearcutt/.github/workflows/release.yml@refs/heads/main"}}]`)
	cosignPath := writeFakeCosign(t, verifyJSON, []byte{})
	cosign := sign.New(cosignPath, `^https://github\.com/acme/clearcutt/`, "https://token.actions.githubusercontent.com", out, errOut)
	enricher := &registryCatalogEnricher{
		owner:        "acme",
		repo:         "clearcutt",
		registryBase: host,
		oci:          client,
		cosign:       cosign,
	}

	refs := enricher.catalogRefs("v1.0.0", "postgres16")
	if len(refs) != 1 || !strings.HasSuffix(refs[0], "/clearcutt-postgres16:v1.0.0-service") {
		t.Fatalf("unexpected service refs: %#v", refs)
	}
	targets := catalogbuild.Targets("java21-slim,postgres16")
	if len(targets) != 2 || targets[0] != "java21-slim" || targets[1] != "postgres16" {
		t.Fatalf("custom service target should survive target filtering: %#v", targets)
	}
	enrichment, err := enricher.Enrich("v1.0.0", "postgres16")
	if err != nil {
		t.Fatalf("service enrich failed: %v", err)
	}
	if enrichment == nil || enrichment.ManifestDigest == nil || *enrichment.ManifestDigest != digest {
		t.Fatalf("expected service enrichment digest, got %#v", enrichment)
	}
	if enrichment.Signature == nil || enrichment.Signature.RekorLogIndex == nil || *enrichment.Signature.RekorLogIndex != 700 {
		t.Fatalf("expected service signature evidence, got %#v", enrichment.Signature)
	}
}

func TestCatalogEnrichmentEdgeHelpers(t *testing.T) {
	rawPayload := map[string]any{
		"predicateType": "https://example.invalid/custom",
		"subject": []any{map[string]any{
			"name":   "fallback-subject",
			"digest": map[string]any{"sha384": "feedface"},
		}},
	}
	payloadRaw, err := json.Marshal(rawPayload)
	if err != nil {
		t.Fatal(err)
	}
	payloadBundle := map[string]any{"payload": base64.StdEncoding.EncodeToString(payloadRaw)}
	if got := payloadFromBundle(payloadBundle); got == nil || stringAt(got, "predicateType") != "https://example.invalid/custom" {
		t.Fatalf("payload fallback branch failed: %#v", got)
	}
	if payloadFromBundle(map[string]any{"payload": "not-base64"}) != nil {
		t.Fatal("invalid base64 payload should be ignored")
	}
	if certificateFromBundle(map[string]any{"verificationMaterial": map[string]any{"certificate": map[string]any{"rawBytes": "not-base64"}}}) != nil {
		t.Fatal("invalid certificate bytes should be ignored")
	}
	if certificateFromBundle(map[string]any{"verificationMaterial": map[string]any{"certificate": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString([]byte("not-a-cert"))}}}) != nil {
		t.Fatal("non-certificate DER should be ignored")
	}
	if (&registryCatalogEnricher{}).normalizeAttestation(cosignAttestation{}, "oci", nil) != nil {
		t.Fatal("attestations without payload should not normalize")
	}
	if attestationKind(map[string]any{"predicateType": "https://cosign.sigstore.dev/attestation/v1"}) != "custom" {
		t.Fatal("cosign attestations without structured test results should be custom")
	}
	if provenanceFromPayload(map[string]any{"bad": func() {}}) != nil {
		t.Fatal("unmarshalable provenance payload should be ignored")
	}
	if provenanceFromPayload(map[string]any{"predicate": "wrong-shape"}) != nil {
		t.Fatal("invalid provenance statement shape should be ignored")
	}
	if subjectDigestFromPayload(rawPayload) != "sha384:feedface" {
		t.Fatalf("expected fallback digest algorithm, got %q", subjectDigestFromPayload(rawPayload))
	}
	if subjectNameFromPayload(map[string]any{}) != "" || subjectDigestFromPayload(map[string]any{}) != "" {
		t.Fatal("missing subjects should not produce subject metadata")
	}
	if subjectDigestFromPayload(map[string]any{"subject": []any{map[string]any{}}}) != "" {
		t.Fatal("missing digest map should return empty digest")
	}
	if subjectDigestFromPayload(map[string]any{"subject": []any{map[string]any{"digest": map[string]any{}}}}) != "" {
		t.Fatal("empty digest map should return empty digest")
	}
	if certSubjectURI(nil) != "" || certSubjectURI(&x509.Certificate{}) != "" {
		t.Fatal("missing or non-GitHub certificates should not produce subject URI")
	}
	if certIssuer(nil) != "" || certIssuer(&x509.Certificate{Issuer: pkix.Name{CommonName: "ordinary ca"}}) != "" {
		t.Fatal("ordinary certificate should not produce GitHub signer metadata")
	}
	if transparencyLogIndex(map[string]any{}) != nil || transparencyURL(nil) != nil {
		t.Fatal("missing transparency metadata should be ignored")
	}
	if attestationWorkflowURL("") != "" {
		t.Fatal("empty workflow identity should not produce workflow URL")
	}
	if attestationWorkflowURL("not-a-github-workflow") != "" {
		t.Fatal("non-workflow identity should not produce workflow URL")
	}
	if got := numberAt(map[string]any{"n": json.Number("42")}, "n"); got == nil || *got != 42 {
		t.Fatalf("json.Number did not parse: %v", got)
	}
	if got := numberAt(map[string]any{"n": "43"}, "n"); got == nil || *got != 43 {
		t.Fatalf("string number did not parse: %v", got)
	}
	if numberAt(map[string]any{"n": json.Number("nope")}, "n") != nil {
		t.Fatal("invalid json.Number should return nil")
	}
	if stringPtrAt(map[string]any{"empty": ""}, "empty") != nil {
		t.Fatal("empty string pointer branch should return nil")
	}
	if _, err := parseCosignAttestation([]byte(`{"payload":""}`)); err == nil || !strings.Contains(err.Error(), "no payload") {
		t.Fatalf("expected no-payload attestation error, got %v", err)
	}
	if extractCosignTestResults(map[string]any{}) != nil {
		t.Fatal("payloads without test result data should be ignored")
	}
	if extractCosignTestResults(map[string]any{"predicate": map[string]any{"Data": `{not-json}`}}) != nil {
		t.Fatal("invalid test-results JSON should be ignored")
	}
	if extractCosignTestResults(map[string]any{"predicate": map[string]any{"Data": `{"status":"","assertions":[]}`}}) != nil {
		t.Fatal("empty test-results payload should be ignored")
	}
	if (&registryCatalogEnricher{owner: "acme", repo: "clearcutt"}).signatureCertMetadata([]cosignAttestation{{Cert: &x509.Certificate{}}}) != nil {
		t.Fatal("non-release certificate should not produce signature metadata")
	}
	if got := (&registryCatalogEnricher{}).listGithubAttestations(strPtr("")); got != nil {
		t.Fatalf("empty digest should not query GitHub: %#v", got)
	}
	enricher := &registryCatalogEnricher{
		owner: "acme",
		repo:  "clearcutt",
		github: &githubReleaseSource{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.Path, "/users/acme/") {
				return textResponse(200, `not-json`), nil
			}
			return textResponse(200, `{"attestations":[{"bundle":{}}]}`), nil
		})}},
	}
	if got := enricher.listGithubAttestations(strPtr("sha256:missing")); len(got) != 0 {
		t.Fatalf("invalid GitHub attestation payloads should be ignored: %#v", got)
	}
	if attestationSortOrder("custom") != 3 {
		t.Fatal("custom attestation sort order should be last")
	}
	if firstNonEmptyPtrFromPtrs(nil, strPtr("")) != nil {
		t.Fatal("empty pointer list should return nil")
	}
}

func bundleJSON(t *testing.T, payload map[string]any, certDER []byte, logIndex int64) []byte {
	t.Helper()
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	bundle := map[string]any{
		"dsseEnvelope": map[string]any{
			"payload": base64.StdEncoding.EncodeToString(payloadRaw),
		},
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{
				"rawBytes": base64.StdEncoding.EncodeToString(certDER),
			},
			"tlogEntries": []any{map[string]any{"logIndex": logIndex}},
		},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	u, err := url.Parse("https://github.com/acme/clearcutt/.github/workflows/release.yml@refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sigstore test"},
		Issuer:       pkix.Name{CommonName: "sigstore test"},
		URIs:         []*url.URL{u},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeFakeCosign(t *testing.T, verifyJSON, attestationJSONL []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cosign")
	script := `#!/bin/sh
set -eu
if [ "$1" = "verify" ]; then
  cat "$CLEARCUTT_FAKE_COSIGN_VERIFY"
  exit 0
fi
if [ "$1" = "download" ]; then
  cat "$CLEARCUTT_FAKE_COSIGN_ATTESTATIONS"
  exit 0
fi
exit 1
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	verifyPath := filepath.Join(t.TempDir(), "verify.json")
	if err := os.WriteFile(verifyPath, verifyJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	attPath := filepath.Join(t.TempDir(), "attestations.jsonl")
	if err := os.WriteFile(attPath, append(attestationJSONL, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLEARCUTT_FAKE_COSIGN_VERIFY", verifyPath)
	t.Setenv("CLEARCUTT_FAKE_COSIGN_ATTESTATIONS", attPath)
	return path
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func textResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
