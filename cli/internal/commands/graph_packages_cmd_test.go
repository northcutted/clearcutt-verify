package commands

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
)

func writeObservationsFile(t *testing.T, obs estategraph.Observations) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "observations.json")
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func nixObs(ref string, paths ...string) estategraph.Observation {
	obs := estategraph.Observation{SourceRef: ref, ManifestDigest: "sha256:" + ref}
	for _, p := range paths {
		obs.History = append(obs.History, estategraph.HistoryObservation{Comment: "store paths: ['" + p + "']"})
	}
	return obs
}

// TestGraphPackagesIsFreeForNix pins the property that makes first-class Nix
// support affordable: no registry access at all.
func TestGraphPackagesIsFreeForNix(t *testing.T) {
	path := writeObservationsFile(t, estategraph.Observations{Images: []estategraph.Observation{
		nixObs("reg/a:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2"),
		nixObs("reg/b:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-openssl-3.6.2"),
	}})
	// Any registry access would fail: this fetcher must never be called.
	restore := sbomFetcherOverride
	sbomFetcherOverride = nil
	t.Cleanup(func() { sbomFetcherOverride = restore })

	stdout, err := runCLI(t, "graph", "packages", "--observations", path)
	if err != nil {
		t.Fatalf("graph packages: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "nix-store-paths x2") {
		t.Errorf("evidence should be attributed to the free source:\n%s", stdout)
	}
	if !strings.Contains(stdout, "2 with a readable package set, 0 unknown") {
		t.Errorf("both images should resolve for free:\n%s", stdout)
	}
}

// TestGraphPackagesReportsTheCostBeforeSpendingIt: an operator should see the
// number of registry requests before they happen, not in a rate-limit graph
// afterwards.
func TestGraphPackagesReportsTheCostBeforeSpendingIt(t *testing.T) {
	images := []estategraph.Observation{nixObs("reg/nix:v1", "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-glibc-2.42")}
	for i := 0; i < 5; i++ {
		images = append(images, estategraph.Observation{
			SourceRef:      "reg/opaque:v" + string(rune('1'+i)),
			DigestRef:      "reg/opaque@sha256:same",
			ManifestDigest: "sha256:same",
		})
	}
	path := writeObservationsFile(t, estategraph.Observations{Images: images})

	stdout, err := runCLI(t, "graph", "packages", "--observations", path)
	if err != nil {
		t.Fatalf("graph packages: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "5 image(s) record no package set") {
		t.Errorf("the gap should be reported:\n%s", stdout)
	}
	// The estimate must reflect deduplication: five tags, one content, one fetch.
	if !strings.Contains(stdout, "1 registry fetch(es)") || !strings.Contains(stdout, "4 avoided") {
		t.Errorf("the cost estimate should account for deduplication:\n%s", stdout)
	}
}

// stubFetcher counts fetches. It is slow enough that workers fetching the
// same content concurrently would be counted, not hidden by timing.
type stubFetcher struct {
	mu    sync.Mutex
	calls int
}

func (s *stubFetcher) FetchSBOM(context.Context, string) ([]byte, error) {
	time.Sleep(20 * time.Millisecond)
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return []byte(`{"packages":[{"name":"openssl","versionInfo":"3.6.2"}]}`), nil
}

// TestGraphPackagesFetchSBOMsWarnsThenFetches: the expensive path must warn
// before it runs, and must deduplicate.
func TestGraphPackagesFetchSBOMsWarnsThenFetches(t *testing.T) {
	images := []estategraph.Observation{}
	for i := 0; i < 4; i++ {
		images = append(images, estategraph.Observation{
			SourceRef:      "reg/opaque:v" + string(rune('1'+i)),
			DigestRef:      "reg/opaque@sha256:same",
			ManifestDigest: "sha256:same",
		})
	}
	path := writeObservationsFile(t, estategraph.Observations{Images: images})

	stub := &stubFetcher{}
	restore := sbomFetcherOverride
	sbomFetcherOverride = stub
	t.Cleanup(func() { sbomFetcherOverride = restore })

	stdout, err := runCLI(t, "graph", "packages", "--observations", path, "--fetch-sboms")
	if err != nil {
		t.Fatalf("graph packages --fetch-sboms: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "WARNING") {
		t.Errorf("the expensive path must warn:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Nix images need none of this") {
		t.Errorf("the warning should say when the cost is avoidable:\n%s", stdout)
	}
	if stub.calls != 1 {
		t.Errorf("four tags on one content should cost one fetch, got %d", stub.calls)
	}
	if !strings.Contains(stdout, "4 with a readable package set") {
		t.Errorf("every tag should end up resolved from the single fetch:\n%s", stdout)
	}
}
