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
		// One reference observed at two digests (the tag moved between
		// observations): the same ID from the reference, so one gets -2, by
		// digest, whichever order they come in.
		{ID: "dup", SourceRef: "ghcr.io/acme/dup:1", DigestRef: "ghcr.io/acme/dup@sha256:" + strings.Repeat("b", 64)},
		{ID: "dup", SourceRef: "ghcr.io/acme/dup:1", DigestRef: "ghcr.io/acme/dup@sha256:" + strings.Repeat("a", 64)},
	}
	// key names an observation in the test: its reference, and its digest
	// when it has one.
	key := func(o estategraph.Observation) string {
		if o.DigestRef == "" {
			return o.SourceRef
		}
		return o.SourceRef + "|" + o.DigestRef
	}
	ids := func(in []estategraph.Observation) map[string]string {
		out := map[string]string{}
		seen := map[string]bool{}
		for _, o := range uniqueImages(in) {
			if seen[o.ID] || !idPattern.MatchString(o.ID) {
				t.Errorf("ID %q is a duplicate or not a path segment", o.ID)
			}
			seen[o.ID] = true
			out[key(o)] = o.ID
		}
		if len(out) != 8 {
			t.Errorf("want 8 images (one listed twice), got %v", out)
		}
		return out
	}
	got := ids(obs)
	want := map[string]string{
		"ghcr.io/acme/app:1": "ghcr-io-acme-app-1", "ghcr.io/other/app:1": "ghcr-io-other-app-1",
		"ghcr.io/acme/x:1": "ghcr-io-acme-x-1", "ghcr.io/acme/ok:1": "ok", "ghcr.io/acme/z:1": "ghcr-io-acme-y-1",
		"ghcr.io/acme/dup:1|ghcr.io/acme/dup@sha256:" + strings.Repeat("a", 64): "ghcr-io-acme-dup-1",
		"ghcr.io/acme/dup:1|ghcr.io/acme/dup@sha256:" + strings.Repeat("b", 64): "ghcr-io-acme-dup-1-2",
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
	// The history rename reads each image's reference by the ID Build gives it.
	refs := SourceRefs(estategraph.Observations{Images: obs})
	for k, id := range got {
		if ref, _, _ := strings.Cut(k, "|"); refs[id] != ref {
			t.Errorf("SourceRefs[%s] = %q, want %q", id, refs[id], ref)
		}
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
