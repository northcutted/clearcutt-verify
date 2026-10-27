package estateverify

import (
	"context"
	"fmt"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
)

func TestProgressIncludesUnreadableImagesAndDeduplicates(t *testing.T) {
	var observations estategraph.Observations
	for i := range 20 {
		observations.Images = append(observations.Images, estategraph.Observation{
			ID: fmt.Sprintf("image-%d", i), SourceRef: fmt.Sprintf("example.test/app:%d", i),
		})
	}
	observations.Images = append(observations.Images, observations.Images[0])
	var calls []string // Build must serialize the callback even with concurrency.
	var invalid bool
	r, err := Build(context.Background(), observations, Options{Concurrency: 8,
		Progress: func(completed, total int, ref string) {
			calls = append(calls, ref)
			invalid = invalid || completed != len(calls) || total != 20 || ref == ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if invalid || len(calls) != 20 || len(r.Images) != 20 {
		t.Fatalf("progress=%v, invalid=%v, images=%d", calls, invalid, len(r.Images))
	}
	seen := map[string]bool{}
	for _, ref := range calls {
		if seen[ref] {
			t.Errorf("processed %s more than once", ref)
		}
		seen[ref] = true
	}
	for _, img := range r.Images {
		if img.Evidence.Signature.Status != "unknown" {
			t.Fatalf("progress changed unreadable evidence: %+v", img.Evidence)
		}
	}
}
