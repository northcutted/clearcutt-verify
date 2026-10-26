package estateverify

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

func TestDependents(t *testing.T) {
	on := func(repo, strength string) *report.BaseLink {
		return &report.BaseLink{Repository: repo, Ref: repo + ":1", Strength: strength, Drift: "current"}
	}
	r := &report.Report{Images: []report.Image{
		{ID: "run-python", Repository: "ghcr.io/acme/platform/run-python", Base: on("cgr.dev/chainguard/wolfi-base", "proof")},
		{ID: "catalog", Repository: "ghcr.io/acme/apps/catalog", Base: on("ghcr.io/acme/platform/run-python", "proof"), Source: &report.SourceRef{URL: "https://github.com/acme/catalog", Basis: "provenance"}},
		{ID: "legacy", Repository: "ghcr.io/acme/apps/legacy", Base: on("ghcr.io/acme/platform/run-python", "declared")},
		{ID: "worker", Repository: "ghcr.io/acme/apps/worker", Base: on("ghcr.io/acme/apps/catalog", "proof")},
		{ID: "debian-app", Repository: "ghcr.io/acme/apps/d", Base: on("docker.io/library/debian", "proof")},
	}}
	ids := func(ds []Dependent) string {
		var out []string
		for _, d := range ds {
			out = append(out, d.ImageID)
		}
		return strings.Join(out, ",")
	}
	if got := Dependents(r, "ghcr.io/acme/platform/run-python:3.14", "proof", false); ids(got) != "catalog" || got[0].Source.URL != "https://github.com/acme/catalog" || got[0].Depth != 1 {
		t.Errorf("proven direct dependents: %+v", got)
	}
	if got := Dependents(r, "ghcr.io/acme/platform/run-python", "declared", false); ids(got) != "catalog,legacy" {
		t.Errorf("declared too: %s", ids(got))
	}
	if got := Dependents(r, "cgr.dev/chainguard/wolfi-base@sha256:"+strings.Repeat("a", 64), "proof", true); ids(got) != "run-python,catalog,worker" || got[2].Depth != 3 {
		t.Errorf("transitive: %+v", got)
	}
	if got := Dependents(r, "debian", "proof", false); ids(got) != "debian-app" {
		t.Errorf("Docker Hub short name: %s", ids(got))
	}
	if got := Dependents(r, "ghcr.io/acme/nothing", "proof", true); got == nil || len(got) != 0 {
		t.Errorf("no dependents: %#v", got)
	}
}

// TestBuildAttributesAppsToTheirRunImage is the showcase prototype's estate
// (V10): with the upstream base the platform builds on in the inventory, an
// app is built on its run image (the nearest base), not on the upstream
// base its layers also start with, and the run image's dependents are found.
func TestBuildAttributesAppsToTheirRunImage(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	// The upstream repository sorts before the run image's.
	upstream := pushIndex(t, host+"/chainguard/wolfi-base:latest", nil, built.Add(-48*time.Hour), nil)
	run := pushIndex(t, host+"/platform/run-python:1", upstream, built.Add(-24*time.Hour), nil)
	pushIndex(t, host+"/apps/catalog:1", run, built, nil)

	verifier := acmeVerifier()
	r, err := Build(context.Background(), observe(t, host, "chainguard/wolfi-base:latest", "platform/run-python:1", "apps/catalog:1"), Options{
		Name: "stacked", Version: "test", GeneratedAt: "2026-10-06T00:00:00Z", Verifier: verifier, Platforms: []string{"linux/amd64"},
		Policy: report.Policy{TrustedSigners: verifier.Signers},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateReport(t, r)
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[i.ID] = i
	}
	if b := img["apps-catalog"].Base; b == nil || b.Repository != host+"/platform/run-python" || b.Strength != "proof" || b.Drift != "current" || b.ImageID != "platform-run-python" {
		t.Fatalf("catalog base: %+v", b)
	}
	if b := img["platform-run-python"].Base; b == nil || b.Repository != host+"/chainguard/wolfi-base" || b.Strength != "proof" {
		t.Errorf("run image base: %+v", b)
	}
	if img["chainguard-wolfi-base"].Root == "" {
		t.Errorf("upstream base isn't a root: %+v", img["chainguard-wolfi-base"])
	}
	if got := Dependents(r, host+"/platform/run-python", "proof", false); len(got) != 1 || got[0].ImageID != "apps-catalog" {
		t.Errorf("run image dependents: %+v", got)
	}
	if got := Dependents(r, host+"/chainguard/wolfi-base", "proof", true); len(got) != 2 || got[0].ImageID != "platform-run-python" || got[1].Depth != 2 {
		t.Errorf("upstream base dependents: %+v", got)
	}
}
