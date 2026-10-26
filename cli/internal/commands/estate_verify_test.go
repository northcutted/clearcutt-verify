package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
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
	withCosign(t, "", nil)
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
	if rows := h.Entries[0].Images; len(rows) != 2 || rows[0].Verdict != "failed" || rows[0].Digest == "" {
		t.Errorf("history rows %+v", rows)
	}

	// --verbose says why; --quiet says nothing; --format prints the report.
	stdout, err = runCLI(t, append(args, "--fail-on", "never", "--generated-at", "2026-10-06T00:00:00Z", "--verbose")...)
	if err != nil || !strings.Contains(stdout, "signature is missing") || !strings.Contains(stdout, "IMAGE") {
		t.Errorf("--verbose: %v\n%s", err, stdout)
	}
	if stdout, err = runCLI(t, append(args, "--fail-on", "never", "--generated-at", "2026-10-06T00:00:00Z", "--quiet")...); err != nil || strings.TrimSpace(stdout) != "" {
		t.Errorf("--quiet printed %q (%v)", stdout, err)
	}
	stdout, err = runCLI(t, append(args, "--fail-on", "never", "--generated-at", "2026-10-06T00:00:00Z", "--format", "json", "--quiet")...)
	var printed report.Report
	if err != nil || json.Unmarshal([]byte(stdout), &printed) != nil || printed.Kind != report.KindReport || len(printed.Images) != 2 {
		t.Errorf("--format json: %v\n%s", err, stdout)
	}
	if stdout, err = runCLI(t, append(args, "--fail-on", "never", "--generated-at", "2026-10-06T00:00:00Z", "--format", "yaml", "--quiet")...); err != nil || !strings.Contains(stdout, "kind: EstateReport") {
		t.Errorf("--format yaml: %v\n%s", err, stdout)
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
	if err != nil || !strings.Contains(stdout, "debian-tools") || !strings.Contains(stdout, "current") || !strings.Contains(stdout, "proof") {
		t.Fatalf("table: %v\n%s", err, stdout)
	}
	stdout, err = runCLI(t, "--format", "json", "estate", "dependents", "--report", fixture, "--base", "cgr.dev/chainguard/wolfi-base")
	var res DependentsResult
	if err != nil || json.Unmarshal([]byte(stdout), &res) != nil || len(res.Dependents) != 1 || res.Dependents[0].ImageID != "ghcr-io-northcutted-images-platform-tools" {
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
	estateVerifyOpts.identityRegexp, estateVerifyOpts.issuer, estateVerifyOpts.sourceOwner, estateVerifyOpts.sourceMatches = "", "", "", false
	p, _, err := estatePolicy()
	if err != nil || len(p.TrustedSigners) != 1 || p.TrustedSigners[0].Identity == "" {
		t.Fatalf("policy %+v, %v", p, err)
	}
	estateVerifyOpts.trustPolicy = filepath.Join(dir, "missing.yaml")
	if _, _, err := estatePolicy(); err == nil {
		t.Error("read a missing trust policy")
	}
}

var updateFixtures = flag.Bool("update", false, "rewrite the fixture history's rows from its report")

// TestFixtureHistoryRows: the northcutted-images fixture's newest history
// rows are what this run's code makes of its report (go test -update
// rewrites them), and they list fixable high and critical findings and a
// package-set digest only from what the report verified.
func TestFixtureHistoryRows(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "contract", "fixtures", "northcutted-images")
	var r report.Report
	var h report.History
	readJSON(t, filepath.Join(dir, "estate-report.json"), &r)
	readJSON(t, filepath.Join(dir, "estate-history.json"), &h)
	if len(h.Entries) == 0 || h.Entries[0].GeneratedAt != r.Metadata.GeneratedAt {
		t.Fatalf("the history's newest entry isn't the report's run")
	}
	rows := historyImages(&r)
	if *updateFixtures {
		h.Entries[0].Images = rows
		if err := writeReportJSON(filepath.Join(dir, "estate-history.json"), h); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := json.Marshal(rows)
	want, _ := json.Marshal(h.Entries[0].Images)
	if string(got) != string(want) {
		t.Fatalf("fixture history rows are stale; run go test ./internal/commands -run TestFixtureHistoryRows -update")
	}
	byID := map[string]report.HistoryImage{}
	for _, row := range rows {
		byID[row.ID] = row
	}
	// debian-tools has 25 critical and 116 high findings, 12 of them fixable.
	if row := byID["ghcr-io-northcutted-images-debian-tools"]; len(row.FixableFindings) == 0 || len(row.FixableFindings) > 12 || !strings.HasPrefix(row.PackagesDigest, "sha256:") {
		t.Errorf("debian-tools row: %+v", row)
	}
	// hello-app has no findings; Docker Hub's debian has no verified scan or SBOM.
	if row := byID["ghcr-io-northcutted-images-hello-app"]; row.Vulnerabilities == nil || row.FixableFindings != nil || row.PackagesDigest == "" {
		t.Errorf("hello-app row: %+v", row)
	}
	if row := byID["docker-io-library-debian-trixie-slim"]; row.Vulnerabilities != nil || row.FixableFindings != nil || row.PackagesDigest != "" {
		t.Errorf("debian-trixie-slim row: %+v", row)
	}
}

func TestPackagesDigest(t *testing.T) {
	a := packagesDigest([]string{"apk zlib 1.3\n", "apk busybox 1.37\n"})
	if a != packagesDigest([]string{"apk busybox 1.37\n", "apk zlib 1.3\n"}) || a == packagesDigest([]string{"apk busybox 1.37\n", "apk zlib 1.3.1\n"}) {
		t.Errorf("digest depends on order, or not on versions")
	}
	// sha256 of "apk busybox 1.37\napk zlib 1.3\n", which readers can recompute.
	if a != "sha256:"+sha256Hex("apk busybox 1.37\napk zlib 1.3\n") {
		t.Errorf("digest %s", a)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestEstateVerifyNeedsItsTools: a missing or unusable cosign (or, with
// --reproduce, clearcutt-factory) stops the run before anything is read, as
// an operational error (exit 1), never as images that failed the policy
// (exit 2).
func TestEstateVerifyNeedsItsTools(t *testing.T) {
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte("127.0.0.1:1/acme/app:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"estate", "verify", "--refs", refs, "--out", filepath.Join(dir, "estate"), "--require", "signature", "--fail-on", "failed",
		"--trusted-identity-regexp", `^https://github\.com/acme/`, "--trusted-issuer", "https://token.actions.githubusercontent.com"}
	check := func(name, want string, extra ...string) {
		t.Helper()
		stdout, err := runCLI(t, append(append([]string{}, args...), extra...)...)
		if err == nil || errors.Is(err, ErrCheckFailed) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an operational error saying %q\n%s", name, err, want, stdout)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "estate", report.ReportFile)); statErr == nil {
			t.Errorf("%s: wrote a report", name)
		}
	}
	check("no cosign", "cosign is not available", "--cosign-path", filepath.Join(dir, "no-such-cosign"))

	withCosign(t, "v2.5.2", nil)
	check("cosign v2", "too old")
	withCosign(t, "v4.0.0", nil)
	check("cosign v4", "newer than this clearcutt-verify reads")
	withCosign(t, "devel", nil)
	check("unversioned cosign", "couldn't tell which cosign")

	withCosign(t, "v3.1.3", nil)
	check("no clearcutt-factory", "clearcutt-factory, which is not available", "--reproduce", "--factory-path", filepath.Join(dir, "no-such-factory"))
}

// Rows of earlier runs keyed by the IDs images had before v0.17.0 carry on
// under the IDs they have now, when that is certain.
func TestHistoryKeepsImagesAcrossTheIDChange(t *testing.T) {
	r := &report.Report{Metadata: report.Metadata{Name: "acme", GeneratedAt: "2026-10-18T00:00:00Z"}, Images: []report.Image{
		{ID: "ghcr-io-acme-billing-1-2", Repository: "ghcr.io/acme/billing", Tags: []string{"1.2"}},
		{ID: "ghcr-io-acme-web", Repository: "ghcr.io/acme/web", Tags: []string{"latest"}},
		// Two images with the same old ID: neither inherits its rows.
		{ID: "ghcr-io-acme-api-1", Repository: "ghcr.io/acme/api", Tags: []string{"1"}},
		{ID: "ghcr-io-other-api-1", Repository: "ghcr.io/other/api", Tags: []string{"1"}},
	}}
	dir := t.TempDir()
	prev := report.History{APIVersion: report.APIVersion, Kind: report.KindHistory, Name: "acme", Entries: []report.HistoryEntry{{
		GeneratedAt: "2026-10-17T00:00:00Z",
		Images:      []report.HistoryImage{{ID: "billing-1-2"}, {ID: "web"}, {ID: "api-1"}, {ID: "gone"}},
	}}}
	path := filepath.Join(dir, "history.json")
	if err := writeReportJSON(path, &prev); err != nil {
		t.Fatal(err)
	}
	h, err := extendHistory(r, path, dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, row := range h.Entries[1].Images {
		ids = append(ids, row.ID)
	}
	if strings.Join(ids, ",") != "ghcr-io-acme-billing-1-2,ghcr-io-acme-web,api-1,gone" {
		t.Errorf("earlier rows: %v", ids)
	}
}

// A bundle that breaks the contract is never written: the report and the
// history are checked against the schemas first.
func TestEstateVerifyWritesNothingInvalid(t *testing.T) {
	withCosign(t, "", nil)
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0)), registry.WithReferrersSupport(true)))
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
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(host+"/acme/app:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A history whose summary has no evidence counts (null) isn't one.
	history := filepath.Join(dir, "old-history.json")
	if err := os.WriteFile(history, []byte(`{"apiVersion":"clearcutt.dev/v1","kind":"EstateHistory","name":"acme","entries":[{"generatedAt":"2026-10-01T00:00:00Z","summary":{"images":1}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "estate")
	_, err = runCLI(t, "estate", "verify", "--refs", refs, "--name", "acme", "--out", out, "--history", history, "--generated-at", "2026-10-06T00:00:00Z")
	if err == nil || errors.Is(err, ErrCheckFailed) || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("want an operational error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, report.ReportFile)); err == nil {
		t.Error("a report was written beside an invalid history")
	}
	// The run's own documents are valid.
	if _, err := runCLI(t, "estate", "verify", "--refs", refs, "--name", "acme", "--out", out, "--generated-at", "2026-10-06T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	var r report.Report
	readJSON(t, filepath.Join(out, report.ReportFile), &r)
	if len(r.Images) != 1 || r.Images[0].ID != strings.NewReplacer(".", "-", ":", "-", "/", "-").Replace(host)+"-acme-app-1" {
		t.Errorf("IDs: %+v", r.Images)
	}
}
