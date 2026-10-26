package commands

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// TestEstateVerifyFetchesTheTrustedRootOnce: with a keyless signer trusted,
// the run fetches Sigstore's trusted root once (cosign initialize) before
// verifying anything, says which file it is, and stops when the fetch
// fails; with --trusted-root it fetches nothing.
func TestEstateVerifyFetchesTheTrustedRootOnce(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := name.ParseReference(host + "/acme/app:1")
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	rootFile := filepath.Join(cache, "tuf-repo-cdn.sigstore.dev", "targets", "trusted_root.json")
	if err := os.MkdirAll(filepath.Dir(rootFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUF_ROOT", cache)
	t.Setenv("TUF_MIRROR", "")
	t.Setenv("SIGSTORE_ROOT_FILE", "")
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(host+"/acme/app:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "estate")
	args := []string{"estate", "verify", "--refs", refs, "--name", "acme", "--out", out, "--require", "signature",
		"--trusted-identity-regexp", `^https://github\.com/acme/`, "--trusted-issuer", "https://token.actions.githubusercontent.com", "--generated-at", "2026-10-26T00:00:00Z"}

	var calls []string
	old := cosignRunner
	t.Cleanup(func() { cosignRunner = old })
	cosignRunner = func(_ context.Context, _ string, a ...string) ([]byte, error) {
		calls = append(calls, a[0])
		switch a[0] {
		case "version":
			return []byte(`{"gitVersion":"v3.1.4"}`), nil
		case "initialize":
			return nil, nil
		}
		return nil, errors.New("error during command execution: no matching signatures")
	}
	stdout, err := runCLI(t, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if strings.Join(calls, ",") != "version,initialize" || !strings.Contains(stdout, "Sigstore evidence is verified against "+rootFile) {
		t.Errorf("cosign calls %v\n%s", calls, stdout)
	}
	// A root given: nothing fetched.
	calls = nil
	if stdout, err := runCLI(t, append(args, "--trusted-root", rootFile)...); err != nil || strings.Join(calls, ",") != "version" || strings.Contains(stdout, "cosign initialize") {
		t.Errorf("--trusted-root: %v, calls %v\n%s", err, calls, stdout)
	}
	// The root fetched but not found where cosign caches it: the run goes on
	// as before, and says so loudly, in the report too.
	t.Setenv("TUF_ROOT", t.TempDir())
	t.Setenv("GITHUB_ACTIONS", "true")
	calls = nil
	_ = os.RemoveAll(out)
	stdout, err = runCLI(t, args...)
	if err != nil || strings.Join(calls, ",") != "version,initialize" || !strings.Contains(stdout, "[verify-estate] WARNING: cosign initialize fetched Sigstore's trusted root, but") ||
		!strings.Contains(stdout, "::warning title=estate verify: no single trusted root::") {
		t.Errorf("no cached root: %v, calls %v\n%s", err, calls, stdout)
	}
	var r report.Report
	readJSON(t, filepath.Join(out, report.ReportFile), &r)
	if !strings.Contains(strings.Join(r.Warnings, ";"), "isn't in the TUF cache") {
		t.Errorf("report warnings: %v", r.Warnings)
	}
	t.Setenv("TUF_ROOT", cache)
	t.Setenv("GITHUB_ACTIONS", "")
	// The fetch failing stops the run before it reads anything.
	cosignRunner = func(_ context.Context, _ string, a ...string) ([]byte, error) {
		if a[0] == "version" {
			return []byte(`{"gitVersion":"v3.1.4"}`), nil
		}
		return nil, errors.New(`Get "https://tuf-repo-cdn.sigstore.dev/timestamp.json": dial tcp: i/o timeout`)
	}
	_ = os.RemoveAll(out)
	if _, err := runCLI(t, args...); err == nil || errors.Is(err, ErrCheckFailed) || !strings.Contains(err.Error(), "cosign initialize") {
		t.Errorf("fetch failing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "estate-report.json")); err == nil {
		t.Error("a report was written without a trusted root")
	}
}
