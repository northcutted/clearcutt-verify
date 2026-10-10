package estateverify

import (
	"strings"
	"testing"

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
