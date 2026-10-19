package estateverify

import (
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
)

// Every image in a report has an ID that is unique and one URL path segment,
// whatever the observations it was built from say, and the same whatever
// order they come in.
func TestUniqueImages(t *testing.T) {
	obs := []estategraph.Observation{
		{ID: "app", SourceRef: "ghcr.io/acme/app:1"},
		{ID: "app", SourceRef: "ghcr.io/other/app:1"},
		{ID: "has/slash", SourceRef: "ghcr.io/acme/x:1"},
		{ID: "", SourceRef: "ghcr.io/acme/y:1"},
		{ID: "ok", SourceRef: "ghcr.io/acme/ok:1"},
		{ID: "ok", SourceRef: "ghcr.io/acme/ok:1"}, // the same image twice
		{ID: "ghcr-io-acme-y-1", SourceRef: "ghcr.io/acme/z:1"},
	}
	ids := func(in []estategraph.Observation) map[string]string {
		out := map[string]string{}
		seen := map[string]bool{}
		for _, o := range uniqueImages(in) {
			if seen[o.ID] || !idPattern.MatchString(o.ID) {
				t.Errorf("ID %q is a duplicate or not a path segment", o.ID)
			}
			seen[o.ID] = true
			out[o.SourceRef] = o.ID
		}
		if len(out) != 6 {
			t.Errorf("want 6 images (one listed twice), got %v", out)
		}
		return out
	}
	got := ids(obs)
	want := map[string]string{
		"ghcr.io/acme/app:1": "ghcr-io-acme-app-1", "ghcr.io/other/app:1": "ghcr-io-other-app-1",
		"ghcr.io/acme/x:1": "ghcr-io-acme-x-1", "ghcr.io/acme/ok:1": "ok", "ghcr.io/acme/z:1": "ghcr-io-acme-y-1",
	}
	for ref, id := range want {
		if got[ref] != id {
			t.Errorf("%s: ID %q, want %q", ref, got[ref], id)
		}
	}
	// y's own ID is taken by an image that named it first; it gets another.
	if y := got["ghcr.io/acme/y:1"]; !strings.HasPrefix(y, "ghcr-io-acme-y-1-") {
		t.Errorf("y: %q", y)
	}
	reversed := make([]estategraph.Observation, len(obs))
	for i := range obs {
		reversed[len(obs)-1-i] = obs[i]
	}
	for ref, id := range ids(reversed) {
		if got[ref] != id {
			t.Errorf("%s: %q in one order, %q in the other", ref, got[ref], id)
		}
	}
}
