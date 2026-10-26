package commands

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func estateTestRegistry(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(registry.New())
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

// TestEstateRoundTripsTheRealPublicSnapshot pushes the committed public-estate
// fixture — 19 real images' worth of observations plus both graphs — into an
// in-process registry and pulls it back, byte for byte.
//
// Using the real fixture rather than toy JSON is the point: it exercises the
// actual sizes and shapes an operator will store, so a size limit or an
// encoding assumption that only holds for small hand-written files fails here.
func TestEstateRoundTripsTheRealPublicSnapshot(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	fixture := filepath.Join(root, "examples", "public-estate")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("public estate fixture not present: %v", err)
	}

	host := estateTestRegistry(t)
	ref := host + "/acme/clearcutt-estate:2026-08-31"

	stdout, err := runCLI(t, "estate", "push", ref,
		"--dir", fixture, "--generated-at", "2026-08-31T00:00:00Z", "--insecure")
	if err != nil {
		t.Fatalf("estate push: %v\n%s", err, stdout)
	}
	for _, want := range []string{"observations.json", "graph.json", "layers.json", "[estate] digest sha256:"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("push output missing %q:\n%s", want, stdout)
		}
	}

	outDir := t.TempDir()
	pullOut, err := runCLI(t, "estate", "pull", ref, "--output", outDir, "--insecure", "--allow-unverified")
	if err != nil {
		t.Fatalf("estate pull: %v\n%s", err, pullOut)
	}
	if !strings.Contains(pullOut, "snapshot generated at 2026-08-31T00:00:00Z") {
		t.Errorf("pull should report the snapshot timestamp:\n%s", pullOut)
	}

	for _, fileName := range []string{"observations.json", "graph.json", "layers.json"} {
		original, err := os.ReadFile(filepath.Join(fixture, fileName))
		if err != nil {
			t.Fatal(err)
		}
		pulled, err := os.ReadFile(filepath.Join(outDir, fileName))
		if err != nil {
			t.Fatalf("expected %s to be pulled: %v", fileName, err)
		}
		if sha256.Sum256(original) != sha256.Sum256(pulled) {
			t.Errorf("%s did not round-trip byte for byte (%d bytes out, %d back)", fileName, len(original), len(pulled))
		}
	}
}

// TestEstatePullAllowMissing: a scheduled job's first run has no bundle to
// pull, and says so with --allow-missing; every other failure still fails,
// so a job never starts a new history over one it couldn't read.
func TestEstatePullAllowMissing(t *testing.T) {
	host := estateTestRegistry(t)
	dir := t.TempDir()
	if stdout, err := runCLI(t, "estate", "pull", host+"/acme/estate:latest", "--output", dir, "--insecure", "--allow-unverified"); err == nil {
		t.Fatalf("pulling nothing succeeded without --allow-missing:\n%s", stdout)
	}
	stdout, err := runCLI(t, "estate", "pull", host+"/acme/estate:latest", "--output", dir, "--insecure", "--allow-missing", "--allow-unverified")
	if err != nil || !strings.Contains(stdout, "nothing at") {
		t.Fatalf("--allow-missing on a first run: %v\n%s", err, stdout)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("wrote %d files", len(entries))
	}

	// Something that isn't an estate artifact is a failure, not a first run.
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := name.ParseReference(host + "/acme/other:latest")
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	if stdout, err := runCLI(t, "estate", "pull", ref.String(), "--output", dir, "--insecure", "--allow-missing", "--allow-unverified"); err == nil {
		t.Fatalf("a foreign artifact passed as missing:\n%s", stdout)
	}
	// So is a stored bundle whose files can't be read: its manifest is
	// there, so a job must not start a fresh history over it.
	var blobsGone atomic.Bool
	reg := registry.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if blobsGone.Load() && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"errors":[{"code":"BLOB_UNKNOWN","message":"blob unknown to registry"}]}`)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()
	stored := strings.TrimPrefix(srv.URL, "http://") + "/acme/estate:latest"
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "estate-report.json"), []byte(`{"kind":"EstateReport"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if stdout, err := runCLI(t, "estate", "push", stored, "--dir", src, "--file", "estate-report.json", "--insecure"); err != nil {
		t.Fatalf("estate push: %v\n%s", err, stdout)
	}
	blobsGone.Store(true)
	if stdout, err := runCLI(t, "estate", "pull", stored, "--output", dir, "--insecure", "--allow-missing", "--allow-unverified"); err == nil {
		t.Fatalf("a bundle with unreadable files passed as missing:\n%s", stdout)
	}
	// So is a registry that can't be reached.
	if stdout, err := runCLI(t, "estate", "pull", "127.0.0.1:1/acme/estate:latest", "--output", dir, "--insecure", "--allow-missing", "--allow-unverified"); err == nil {
		t.Fatalf("an unreachable registry passed as missing:\n%s", stdout)
	}
}

// TestEstatePushIsStableAcrossRuns is the operational property: a scheduled job
// that re-pushes an unchanged estate must not mint a new version every run.
func TestEstatePushIsStableAcrossRuns(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	fixture := filepath.Join(root, "examples", "public-estate")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("public estate fixture not present: %v", err)
	}
	host := estateTestRegistry(t)
	ref := host + "/acme/clearcutt-estate:latest"

	digestOf := func() string {
		t.Helper()
		stdout, err := runCLI(t, "estate", "push", ref, "--dir", fixture,
			"--generated-at", "2026-08-31T00:00:00Z", "--insecure")
		if err != nil {
			t.Fatalf("estate push: %v\n%s", err, stdout)
		}
		for _, line := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(line, "[estate] digest ") {
				return strings.TrimSpace(strings.TrimPrefix(line, "[estate] digest "))
			}
		}
		t.Fatalf("no digest in push output:\n%s", stdout)
		return ""
	}
	if first, second := digestOf(), digestOf(); first != second {
		t.Fatalf("re-pushing an unchanged estate minted a new version: %s then %s", first, second)
	}
}

// TestEstatePushWithoutSnapshotFilesExplainsItself: an operator who runs this
// before generating a snapshot should be told what to run, not handed an
// empty-artifact error from the registry layer.
func TestEstatePushWithoutSnapshotFilesExplainsItself(t *testing.T) {
	host := estateTestRegistry(t)
	stdout, err := runCLI(t, "estate", "push", host+"/acme/empty:latest",
		"--dir", t.TempDir(), "--insecure")
	if err == nil {
		t.Fatalf("pushing an empty directory should fail:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "import observe") || !strings.Contains(err.Error(), "graph build") {
		t.Fatalf("error should say which commands produce a snapshot, got: %v", err)
	}
}

// TestEstateHistoryCommandRendersTheTrend drives the user-facing trend output,
// which is the reason the history index exists.
func TestEstateHistoryCommandRendersTheTrend(t *testing.T) {
	host := estateTestRegistry(t)
	historyRef := host + "/acme/estate:history"

	for i, day := range []struct {
		at                              string
		images, resolved, proven, stale int
	}{
		{"2026-08-31T00:00:00Z", 19, 3, 2, 6},
		{"2026-09-01T00:00:00Z", 19, 9, 7, 1},
	} {
		dir := t.TempDir()
		graph := fmt.Sprintf(`{"summary":{"observedImages":%d,"resolvedConsumers":%d,"unresolvedConsumers":%d,
		  "staleConsumers":%d,"rootImages":2,"edgesByMethod":{"layer-prefix":%d}}}`,
			day.images, day.resolved, day.images-day.resolved, day.stale, day.proven)
		if err := os.WriteFile(filepath.Join(dir, "graph.json"), []byte(graph), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "layers.json"),
			[]byte(`{"summary":{"distinctLayers":96,"sharedLayers":12,"storedBytes":703594496}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		ref := fmt.Sprintf("%s/acme/estate:day-%d", host, i)
		if _, err := runCLI(t, "estate", "push", ref, "--dir", dir,
			"--generated-at", day.at, "--history", historyRef, "--insecure"); err != nil {
			t.Fatalf("push %s: %v", day.at, err)
		}
	}

	// Nobody signed the index: reading it takes --allow-unverified, and the
	// output says so.
	if _, err := runCLI(t, "estate", "history", historyRef, "--insecure"); err == nil || !strings.Contains(err.Error(), "role estate") {
		t.Fatalf("history without a signer: %v", err)
	}
	stdout, err := runCLI(t, "estate", "history", historyRef, "--insecure", "--allow-unverified")
	if err != nil {
		t.Fatalf("history: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "WARNING") || !strings.Contains(stdout, "NOT verified") {
		t.Errorf("an unverified index read without a warning:\n%s", stdout)
	}
	for _, want := range []string{
		"2026-08-31T00:00:00Z",
		"2026-09-01T00:00:00Z",
		"provenance resolved",
		"proven by layer digests",
		"stale consumers",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("trend output missing %q:\n%s", want, stdout)
		}
	}
	// Direction matters more than the numbers: fewer stale consumers is an
	// improvement, and the output must not call it a regression.
	if !strings.Contains(stdout, "improved") {
		t.Errorf("a fleet that resolved more and went less stale should read as improved:\n%s", stdout)
	}
	if strings.Contains(stdout, "stale consumers             6 -> 1     -5 (regressed)") {
		t.Errorf("falling stale count must be an improvement, not a regression:\n%s", stdout)
	}
}

func TestEstateHistoryOnAnEmptySeriesSaysSo(t *testing.T) {
	host := estateTestRegistry(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "graph.json"), []byte(`{"summary":{"observedImages":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	historyRef := host + "/acme/estate:history"
	if _, err := runCLI(t, "estate", "push", host+"/acme/estate:one", "--dir", dir,
		"--generated-at", "2026-09-01T00:00:00Z", "--history", historyRef, "--insecure"); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t, "estate", "history", historyRef, "--insecure", "--allow-unverified")
	if err != nil {
		t.Fatalf("history: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "a trend needs at least two") {
		t.Errorf("a one-entry series should say a trend is not possible yet:\n%s", stdout)
	}
}

// TestEnvironmentCredentialsReachOnlyTheirRegistry: estate and evidence
// commands offer GITHUB_TOKEN to ghcr.io alone, and REGISTRY_USER and
// REGISTRY_TOKEN only to the registry the command names. Before, whichever
// pair was set went to any registry named on the command line, so a job's
// GitHub token reached a third-party registry the moment one was named.
func TestEnvironmentCredentialsReachOnlyTheirRegistry(t *testing.T) {
	for _, key := range []string{"REGISTRY_USER", "REGISTRY_TOKEN", "CLEARCUTT_REGISTRY_USER", "CLEARCUTT_REGISTRY_TOKEN"} {
		t.Setenv(key, "")
	}
	t.Setenv("DOCKER_CONFIG", t.TempDir()) // no docker login
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_TOKEN", "ghs_job_token")

	// A registry that asks for basic auth, and records what it is offered.
	var mu sync.Mutex
	var offered []string
	reg := registry.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		mu.Lock()
		if auth != "" {
			offered = append(offered, auth)
		}
		mu.Unlock()
		if auth != "Basic "+basic("ci-bot", "s3cret") {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()
	ref := strings.TrimPrefix(srv.URL, "http://") + "/acme/estate:history"
	seen := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(offered, " ")
	}

	for _, args := range [][]string{{"estate", "history", ref, "--allow-unverified"}, {"evidence", "list", ref}} {
		if stdout, err := runCLI(t, args...); err == nil {
			t.Fatalf("%v: authenticated without credentials:\n%s", args, stdout)
		}
	}
	if strings.Contains(seen(), basic("octocat", "ghs_job_token")) {
		t.Fatalf("GITHUB_TOKEN was offered to %s: %s", ref, seen())
	}

	// The explicit pair is for the registry the command names.
	t.Setenv("REGISTRY_USER", "ci-bot")
	t.Setenv("REGISTRY_TOKEN", "s3cret")
	_, _ = runCLI(t, "estate", "history", ref, "--allow-unverified")
	if !strings.Contains(seen(), basic("ci-bot", "s3cret")) {
		t.Errorf("the explicit credentials weren't offered to the named registry: %q", seen())
	}
}

func basic(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}
