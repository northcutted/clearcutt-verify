package commands

import (
	"encoding/json"
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

func TestEstateVerify(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0)), registry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	for _, ref := range []string{"acme/base:latest", "acme/app:1"} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := name.ParseReference(host + "/" + ref)
		if err := remote.Write(r, img); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte("# the estate\n"+host+"/acme/base:latest\n\n"+host+"/acme/app:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "estate")
	args := []string{"estate", "verify", "--refs", refs, "--name", "acme", "--out", out, "--require", "signature",
		"--trusted-identity-regexp", `^https://github\.com/acme/`, "--trusted-issuer", "https://token.actions.githubusercontent.com"}

	// Unsigned images fail the policy, and --fail-on failed says so.
	stdout, err := runCLI(t, append(args, "--fail-on", "failed", "--generated-at", "2026-10-05T00:00:00Z")...)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("want ErrCheckFailed, got %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "2 images: 0 verified, 2 failed") || !strings.Contains(stdout, "IMAGE") {
		t.Errorf("summary:\n%s", stdout)
	}
	var r report.Report
	readJSON(t, filepath.Join(out, report.ReportFile), &r)
	if r.Metadata.Name != "acme" || len(r.Images) != 2 || len(r.Metadata.Sources) != 1 || strings.Join(r.Metadata.Sources[0].Repositories, ",") != "acme/app,acme/base" {
		t.Errorf("report metadata %+v, %d images", r.Metadata, len(r.Images))
	}

	// A second run extends the history kept in the bundle.
	if stdout, err := runCLI(t, append(args, "--fail-on", "never", "--generated-at", "2026-10-06T00:00:00Z")...); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	var h report.History
	readJSON(t, filepath.Join(out, report.HistoryFile), &h)
	if len(h.Entries) != 2 || h.Entries[0].GeneratedAt != "2026-10-06T00:00:00Z" {
		t.Errorf("history %+v", h.Entries)
	}

	for _, bad := range [][]string{
		{"estate", "verify", "--refs", refs},
		{"estate", "verify", "--out", out},
		{"estate", "verify", "--refs", refs, "--observations", refs, "--out", out},
		{"estate", "verify", "--refs", refs, "--out", out, "--fail-on", "sometimes"},
		{"estate", "verify", "--refs", refs, "--out", out, "--policy", refs, "--require", "sbom"},
		{"estate", "verify", "--refs", refs, "--out", out, "--trusted-identity-regexp", ".*", "--trusted-issuer", "x"},
	} {
		if _, err := runCLI(t, bad...); err == nil || errors.Is(err, ErrCheckFailed) {
			t.Errorf("%v: got %v, want a usage error", bad[2:], err)
		}
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func TestEstateDependents(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "contract", "fixtures", "northcutted-images", "estate-report.json")
	stdout, err := runCLI(t, "estate", "dependents", "--report", fixture, "--base", "debian:trixie-slim")
	if err != nil || !strings.Contains(stdout, "debian-tools") || !strings.Contains(stdout, "stale, 17d behind") {
		t.Fatalf("table: %v\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "--format", "json", "estate", "dependents", "--report", fixture, "--base", "cgr.dev/chainguard/wolfi-base")
	var res DependentsResult
	if err != nil || json.Unmarshal([]byte(stdout), &res) != nil || len(res.Dependents) != 1 || res.Dependents[0].ImageID != "platform-tools" {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	if stdout, err := runCLI(t, "estate", "dependents", "--report", fixture, "--base", "ghcr.io/acme/none"); err != nil || !strings.Contains(stdout, "no images") {
		t.Errorf("none: %v\n%s", err, stdout)
	}
	for _, bad := range [][]string{
		{"estate", "dependents", "--report", fixture},
		{"estate", "dependents", "--report", fixture, "--base", "x", "--min-strength", "strong"},
		{"estate", "dependents", "--report", filepath.Join(t.TempDir(), "missing.json"), "--base", "x"},
	} {
		if _, err := runCLI(t, bad...); err == nil {
			t.Errorf("%v: want an error", bad[2:])
		}
	}
}

func TestEstateVerifyTrustPolicyFlag(t *testing.T) {
	dir := t.TempDir()
	trust := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trust, []byte("apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - identity: https://github.com/acme/images/.github/workflows/release.yml@refs/heads/main\n    issuer: https://token.actions.githubusercontent.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := estateVerifyOpts
	t.Cleanup(func() { estateVerifyOpts = saved })
	estateVerifyOpts = saved
	estateVerifyOpts.policy, estateVerifyOpts.trustPolicy, estateVerifyOpts.require = "", trust, []string{"signature"}
	p, err := estatePolicy()
	if err != nil || len(p.TrustedSigners) != 1 || p.TrustedSigners[0].Identity == "" {
		t.Fatalf("policy %+v, %v", p, err)
	}
	estateVerifyOpts.trustPolicy = filepath.Join(dir, "missing.yaml")
	if _, err := estatePolicy(); err == nil {
		t.Error("read a missing trust policy")
	}
}
