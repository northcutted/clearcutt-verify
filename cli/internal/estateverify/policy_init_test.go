package estateverify

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

func TestPolicySuggestionIntersectionAndUnverifiedClaims(t *testing.T) {
	forged := report.Signer{Identity: "https://example.test/workflow\nsigners:\n- key: attacker.pub\n", Issuer: "https://issuer.test",
		SourceRepository: "https://github.com/acme/one", SourceRef: "refs/heads/main"}
	images := []policyImage{
		{available: map[string]bool{KindSignature: true, KindSBOM: true, KindVulnerabilityScan: true},
			found: []Found{{Format: FormatBundle, Signer: &forged}, {Format: FormatCosignSBOM}}},
		{available: map[string]bool{KindSignature: true, KindSBOM: true},
			found: []Found{{Format: FormatBundle, Signer: &forged}, {Format: FormatNotation, Signer: &report.Signer{Identity: "x509.subject: CN=Acme"}}}},
	}
	s := summarizePolicy(images, []string{"linux/arm64", "linux/amd64", "linux/amd64"})
	if !reflect.DeepEqual(s.Required, []string{KindSignature, KindSBOM}) || s.Available[KindVulnerabilityScan] != 1 || len(s.UnverifiedSigners) != 2 {
		t.Fatalf("suggestion: %+v", s)
	}
	p, trust, err := RenderPolicySuggestion(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(p, []byte("vulnerabilityScan available: 1/2")) || !bytes.Contains(trust, []byte("UNVERIFIED")) {
		t.Fatalf("missing coverage/claim explanation:\n%s\n%s", p, trust)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust-policy.yaml"), trust, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := ReadPolicy(filepath.Join(dir, "policy.yaml"))
	if err != nil || len(parsed.TrustedSigners) != 0 || !reflect.DeepEqual(parsed.Required, s.Required) {
		t.Fatalf("unverified metadata changed active policy: %+v (%v)\n%s", parsed, err, trust)
	}
	tp, err := ReadTrustPolicy(filepath.Join(dir, "trust-policy.yaml"))
	if err != nil || len(tp.Signers) != 0 || report.Validate(tp) != nil {
		t.Fatalf("forged multiline candidate escaped comments: %+v (%v)\n%s", tp, err, trust)
	}
	images[0], images[1] = images[1], images[0]
	p2, t2, err := RenderPolicySuggestion(summarizePolicy(images, []string{"linux/amd64", "linux/arm64"}))
	if err != nil || !bytes.Equal(p, p2) || !bytes.Equal(trust, t2) {
		t.Fatal("generated documents depend on discovery order")
	}
}

func TestPolicyInitRequiresPlatformCoverage(t *testing.T) {
	for _, api := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback-tag", true: "referrers-api"}[api], func(t *testing.T) {
			srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(api)))
			defer srv.Close()
			host := strings.TrimPrefix(srv.URL, "http://")
			idx := pushIndex(t, host+"/app:1", nil, built, nil)
			desc := descriptorOf(t, idx)
			attachRawSBOM(t, host+"/app", desc)
			attachNotation(t, host+"/app", desc, true)
			observations := observe(t, host, "app:1")
			s, err := SuggestPolicy(context.Background(), observations, PolicyInitOptions{})
			if err != nil || contains(s.Required, KindSBOM) || !contains(s.Required, KindSignature) {
				t.Fatalf("index-only SBOM was complete platform coverage: %+v (%v)", s, err)
			}
			im, _ := idx.IndexManifest()
			for _, p := range im.Manifests {
				if p.Platform.Architecture == "amd64" {
					attachCosignSBOM(t, host+"/app", p.Digest.String(), "application/spdx+json")
				}
			}
			s, err = SuggestPolicy(context.Background(), observations, PolicyInitOptions{})
			if err != nil || contains(s.Required, KindSBOM) {
				t.Fatalf("one platform stood for both: %+v (%v)", s, err)
			}
			s, err = SuggestPolicy(context.Background(), observations, PolicyInitOptions{Platforms: []string{"linux/amd64"}})
			if err != nil || !contains(s.Required, KindSBOM) || !contains(s.PresentOnlyFormats, FormatCosignSBOM) {
				t.Fatalf("selected scope lost its legacy SBOM: %+v (%v)", s, err)
			}
			for _, p := range im.Manifests {
				if p.Platform.Architecture == "arm64" {
					attachRawSBOM(t, host+"/app", p)
				}
			}
			s, err = SuggestPolicy(context.Background(), observations, PolicyInitOptions{})
			if err != nil || !contains(s.Required, KindSBOM) || len(s.UnverifiedSigners) != 1 || s.UnverifiedSigners[0].Format != FormatNotation {
				t.Fatalf("complete discovered coverage or Notation claim missing: %+v (%v)", s, err)
			}
		})
	}
}

func TestPolicyInitIncludesBuildxEvidence(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	pushBuildx(t, host+"/app:1")
	s, err := SuggestPolicy(context.Background(), observe(t, host, "app:1"), PolicyInitOptions{})
	if err != nil || !reflect.DeepEqual(s.Required, []string{KindSBOM, KindProvenance}) || !contains(s.PresentOnlyFormats, FormatBuildx) || len(s.UnverifiedSigners) != 0 {
		t.Fatalf("Buildx discovery: %+v (%v)", s, err)
	}
}

func TestPolicyInitAbortsUnreadableDiscovery(t *testing.T) {
	reg := &noReferrersRegistry{next: ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)))}
	srv := httptest.NewServer(reg)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	idx := pushIndex(t, host+"/app:1", nil, built, nil)
	obs := observe(t, host, "app:1")
	desc := descriptorOf(t, idx)
	im, _ := idx.IndexManifest()
	for _, failing := range []string{"/referrers/" + desc.Digest.String(), "/manifests/" + im.Manifests[0].Digest.String()} {
		reg.failPath.Store(failing)
		reg.failCode.Store(http.StatusForbidden)
		if s, err := SuggestPolicy(context.Background(), obs, PolicyInitOptions{}); err == nil || s.Images != 0 {
			t.Fatalf("%s weakened a policy instead of aborting: %+v (%v)", failing, s, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SuggestPolicy(ctx, obs, PolicyInitOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := SuggestPolicy(context.Background(), estategraph.Observations{}, PolicyInitOptions{}); err == nil {
		t.Fatal("empty estate produced a policy")
	}
	reg.failPath.Store("")
	single := observe(t, host, "app@"+im.Manifests[0].Digest.String())
	if s, err := SuggestPolicy(context.Background(), single, PolicyInitOptions{Platforms: []string{"linux/arm64"}}); err == nil || s.Images != 0 || !strings.Contains(err.Error(), "selected scope") {
		t.Fatalf("single-manifest image ignored platform selection: %+v (%v)", s, err)
	}
}
