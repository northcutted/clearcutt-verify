package commands

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/config"
)

// These cover small pure functions that shape what an operator reads. They are
// deterministic and environment-independent, which matters here: coverage in CI
// runs about 1.5 points below local because tests that shell out take different
// branches on a runner with no container engine. Pure logic covers identically
// in both, so it is the honest place to close a gap.

func TestHumanSizeUnitBoundaries(t *testing.T) {
	cases := []struct {
		size int64
		want string
	}{
		{0, "0"},
		{-1, "0"}, // a negative size is nonsense, not "-0KB"
		{1024, "1KB"},
		{1024*1024 - 1, "1024KB"}, // just below the MB boundary stays KB
		{1024 * 1024, "1MB"},
		{1024*1024*1024 - 1, "1024MB"},
		{1024 * 1024 * 1024, "1.0GB"}, // GB gains a decimal; the others do not
		{3 * 1024 * 1024 * 1024, "3.0GB"},
	}
	for _, tc := range cases {
		if got := humanSize(tc.size); got != tc.want {
			t.Errorf("humanSize(%d) = %q, want %q", tc.size, got, tc.want)
		}
	}
}

func TestTruncateDigestKeepsEnoughToBeUnique(t *testing.T) {
	full := "sha256:22776bb048484801f7a107d45f54ac54b2187aaa64008f2987cf2162b2a3de3b"
	got := truncateDigest(full)
	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("the algorithm prefix must survive so a reader knows what they are looking at, got %q", got)
	}
	// 12 hex characters after the prefix identify a manifest by eye without
	// wrapping a table column.
	if want := full[:19] + "..."; got != want {
		t.Errorf("truncateDigest = %q, want %q", got, want)
	}
	// A bare hex digest with no prefix still truncates.
	if got := truncateDigest("22776bb048484801f7a107d45f54ac54"); got != "22776bb04848..." {
		t.Errorf("unprefixed digest = %q", got)
	}
	// Anything already short is returned untouched rather than padded.
	for _, short := range []string{"", "abc", "sha256:abc"} {
		if got := truncateDigest(short); got != short {
			t.Errorf("truncateDigest(%q) should be unchanged, got %q", short, got)
		}
	}
}

func TestEnvIntValueFallsBackRatherThanFailing(t *testing.T) {
	t.Setenv("CLEARCUTT_TEST_INT", "")
	if got := envIntValue("CLEARCUTT_TEST_INT", 10); got != 10 {
		t.Errorf("unset should use the fallback, got %d", got)
	}
	t.Setenv("CLEARCUTT_TEST_INT", "  42  ")
	if got := envIntValue("CLEARCUTT_TEST_INT", 10); got != 42 {
		t.Errorf("surrounding whitespace should be tolerated, got %d", got)
	}
	// A malformed value falls back instead of erroring: these tune scan depth
	// and release limits, where refusing to run is worse than a sane default.
	t.Setenv("CLEARCUTT_TEST_INT", "not-a-number")
	if got := envIntValue("CLEARCUTT_TEST_INT", 10); got != 10 {
		t.Errorf("malformed should use the fallback, got %d", got)
	}
	t.Setenv("CLEARCUTT_TEST_INT", "-5")
	if got := envIntValue("CLEARCUTT_TEST_INT", 10); got != -5 {
		t.Errorf("a negative value is still a value, got %d", got)
	}
}

func TestProductionTierUsesTheEffectivePolicy(t *testing.T) {
	// An empty policy must resolve through EffectiveRemediationPolicy rather
	// than matching nothing — otherwise an unconfigured fork would treat every
	// tier as non-production and skip the gates that matter.
	var empty config.RemediationPolicy
	effective := config.EffectiveRemediationPolicy(empty)
	if len(effective.ProductionTiers) == 0 {
		t.Fatal("test assumption broken: the default policy names production tiers")
	}
	for _, tier := range effective.ProductionTiers {
		if !productionTier(empty, tier) {
			t.Errorf("%q is a production tier under the default policy", tier)
		}
	}
	if productionTier(empty, "dev") {
		t.Error("dev must never be treated as a production tier")
	}
	if productionTier(empty, "") {
		t.Error("an empty tier must not match")
	}

	// An explicit policy overrides the default.
	custom := config.RemediationPolicy{ProductionTiers: []string{"hardened"}}
	if !productionTier(custom, "hardened") {
		t.Error("an explicitly configured tier should match")
	}
}

func TestImageRecordLabelPointsAtTheRecordOnDisk(t *testing.T) {
	got := imageRecordLabel(filepath.Join("site", "src", "data", "catalog"), "java25-distroless")
	want := filepath.Join("site", "src", "data", "catalog", "images", "java25-distroless.json")
	if got != want {
		t.Errorf("imageRecordLabel = %q, want %q", got, want)
	}
}
