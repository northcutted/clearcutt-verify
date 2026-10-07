package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scanengine "github.com/northcutted/clearcutt-verify/internal/scan"
)

func TestSelectScanTagsUsesDepthWindowAndExplicitPrecedence(t *testing.T) {
	old := scanOpts
	t.Cleanup(func() { scanOpts = old })

	scanOpts = scanFlags{depth: "2"}
	selected, err := selectScanTags([]string{"v1.0.0", "v1.0.1", "v1.0.2", "v1.0.3"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(selected, ",") != "v1.0.3,v1.0.2" {
		t.Fatalf("unexpected depth selection: %v", selected)
	}

	scanOpts = scanFlags{depth: "1", all: true, tags: "v1.0.0,v1.0.3"}
	selected, err = selectScanTags([]string{"v1.0.0", "v1.0.1", "v1.0.2", "v1.0.3"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(selected, ",") != "v1.0.0,v1.0.3" {
		t.Fatalf("explicit tags should override all/depth, got: %v", selected)
	}
}

func TestCommandEnvAndFormattingHelpers(t *testing.T) {
	t.Setenv("CLEARCUTT_TEST_ENV", "custom")
	if got := envOr("CLEARCUTT_TEST_ENV", "fallback"); got != "custom" {
		t.Fatalf("envOr should prefer env value, got %q", got)
	}
	if got := envOr("CLEARCUTT_TEST_ENV_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("envOr should fall back, got %q", got)
	}
	if parseScanBool(" yes ") != true || parseScanBool("off") != false {
		t.Fatal("parseScanBool did not handle yes/off branches")
	}
	if joinOrNone(nil) != "(none)" {
		t.Fatal("joinOrNone should render empty lists")
	}
}

func TestSelectScanTagsCoversAllDefaultAndInvalidDepth(t *testing.T) {
	old := scanOpts
	t.Cleanup(func() { scanOpts = old })

	allTags := []string{"v1.0.0", "v1.0.1"}
	scanOpts = scanFlags{all: true}
	selected, err := selectScanTags(allTags, true)
	if err != nil || strings.Join(selected, ",") != strings.Join(allTags, ",") {
		t.Fatalf("all-tags selection = %v err=%v", selected, err)
	}

	scanOpts = scanFlags{depth: "10"}
	selected, err = selectScanTags(allTags, true)
	if err != nil || len(selected) != len(allTags) {
		t.Fatalf("depth covering all tags = %v err=%v", selected, err)
	}

	scanOpts = scanFlags{}
	selected, err = selectScanTags(allTags, true)
	if err != nil || len(selected) != len(allTags) {
		t.Fatalf("default selection = %v err=%v", selected, err)
	}

	scanOpts = scanFlags{depth: "invalid"}
	selected, err = selectScanTags(allTags, false)
	if err != nil || len(selected) != len(allTags) {
		t.Fatalf("non-strict invalid depth should scan all tags, got %v err=%v", selected, err)
	}
	if _, err = selectScanTags(allTags, true); err == nil || !strings.Contains(err.Error(), "invalid tag window depth") {
		t.Fatalf("strict invalid depth should fail, got %v", err)
	}
}

func TestScanCommandUsesFakeGrypeAndWritesReports(t *testing.T) {
	sbomDir := filepath.Join(t.TempDir(), "sboms")
	outDir := filepath.Join(t.TempDir(), "vulns")
	writeTestFile(t, filepath.Join(sbomDir, "v1.0.0", "python3.13-slim-amd64.sbom.json"), []byte(`{"spdxVersion":"SPDX-2.3"}`))
	writeTestFile(t, filepath.Join(sbomDir, "v1.0.0", "ignored.txt"), []byte(`ignored`))
	writeTestFile(t, filepath.Join(sbomDir, "v0.9.0", "python3.13-slim-amd64.sbom.json"), []byte(`{"spdxVersion":"SPDX-2.3"}`))

	grype := writeFakeGrype(t, `{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2026-0001",
        "severity": "Critical",
        "dataSource": "https://example.invalid/cve",
        "namespace": "nvd:cpe",
        "description": "runtime vuln",
        "fix": { "versions": ["3.13.2"], "state": "fixed" },
        "cvss": [
          { "type": "secondary", "version": "3.1", "vector": "CVSS:3.1/LOW", "metrics": { "baseScore": 4.0 } },
          { "type": "primary", "version": "3.1", "vector": "CVSS:3.1/HIGH", "metrics": { "baseScore": 9.8 } }
        ],
        "epss": [
          { "date": "2026-01-01", "epss": 0.1, "percentile": 0.2 },
          { "date": "2026-02-01", "epss": 0.3, "percentile": 0.4 }
        ],
        "risk": 88.5
      },
      "artifact": {
        "name": "python3.13",
        "version": "3.13.1",
        "purl": "pkg:generic/python@3.13.1",
        "sourceInfo": ""
      }
    },
    {
      "vulnerability": {
        "id": "CVE-2026-0002",
        "severity": "Low",
        "fix": { "versions": [], "state": "" }
      },
      "artifact": {
        "name": "openssl",
        "version": "3.5.0",
        "purl": ["pkg:nix/openssl@3.5.0"],
        "sourceInfo": "/nix/store/openssl"
      }
    },
    {
      "vulnerability": {
        "id": "",
        "severity": "",
        "fix": { "versions": [], "state": "" }
      },
      "artifact": {
        "name": "basepkg",
        "version": "1.0.0",
        "purl": [],
        "sourceInfo": ""
      }
    }
  ]
}`)
	t.Setenv("GRYPE_BIN", grype)

	stdout, err := runCLI(t,
		"scan",
		"--mode", "release",
		"--sbom-dir", sbomDir,
		"--out-dir", outDir,
		"--tags", "v1.0.0",
		"--concurrency", "1",
	)
	if err != nil {
		t.Fatalf("scan failed: %v\n%s", err, stdout)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "v1.0.0", "python3.13-slim-amd64.json"))
	if err != nil {
		t.Fatalf("expected scan report: %v", err)
	}
	var report scanengine.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("failed to decode scan report: %v\n%s", err, raw)
	}
	if report.Scanner != "grype-0.99.0-test" || report.DBBuiltAt == nil || *report.DBBuiltAt != "2026-02-01T00:00:00Z" {
		t.Fatalf("unexpected scanner metadata: %#v", report)
	}
	if report.CountsBySeverity.Critical != 1 || report.CountsBySeverity.Low != 1 || report.CountsBySeverity.Unknown != 1 {
		t.Fatalf("unexpected severity counts: %#v", report.CountsBySeverity)
	}
	if len(report.Findings) != 3 || report.Findings[0].ID != "CVE-2026-0001" || report.Findings[0].Remediation.Status != "eligible" {
		t.Fatalf("unexpected normalized findings: %#v", report.Findings)
	}
	if report.Findings[2].ID != "UNKNOWN" || report.Findings[2].Layer != "base" {
		t.Fatalf("expected unknown base finding last, got %#v", report.Findings[2])
	}
	if _, err := os.Stat(filepath.Join(outDir, "v0.9.0", "python3.13-slim-amd64.json")); !os.IsNotExist(err) {
		t.Fatalf("explicit tag scan should not write older tag, stat err=%v", err)
	}
}

func TestScanUpdateDBWarnsAndContinuesInStrictMode(t *testing.T) {
	sbomDir := filepath.Join(t.TempDir(), "sboms")
	outDir := filepath.Join(t.TempDir(), "vulns")
	writeTestFile(t, filepath.Join(sbomDir, "v1.0.0", "python3.13-slim-amd64.sbom.json"), []byte(`{"spdxVersion":"SPDX-2.3"}`))

	resultPath := filepath.Join(t.TempDir(), "result.json")
	writeTestFile(t, resultPath, []byte(`{"matches":[]}`))
	logPath := filepath.Join(t.TempDir(), "grype.log")
	grype := writeScript(t, "grype", `#!/bin/sh
set -eu
if [ "$1" = "db" ] && [ "$2" = "update" ]; then
  printf '%s\n' db-update-attempted >> "$CLEARCUTT_FAKE_GRYPE_LOG"
  printf '%s\n' 'db temporarily unavailable' >&2
  exit 9
fi
if [ "$1" = "version" ]; then
  printf '%s\n' '{"version":"0.99.0-test","db":{"built":"2026-02-01T00:00:00Z"}}'
  exit 0
fi
cat "$CLEARCUTT_FAKE_GRYPE_RESULT"
`)
	t.Setenv("GRYPE_BIN", grype)
	t.Setenv("CLEARCUTT_FAKE_GRYPE_RESULT", resultPath)
	t.Setenv("CLEARCUTT_FAKE_GRYPE_LOG", logPath)

	stdout, err := runCLI(t,
		"scan",
		"--mode", "remediation",
		"--update-db",
		"--sbom-dir", sbomDir,
		"--out-dir", outDir,
		"--concurrency", "1",
	)
	if err != nil {
		t.Fatalf("scan should continue after db update failure: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Grype database update failed") {
		t.Fatalf("expected db update warning, got:\n%s", stdout)
	}
	rawLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake grype log: %v", err)
	}
	if strings.TrimSpace(string(rawLog)) != "db-update-attempted" {
		t.Fatalf("expected db update attempt, got %q", rawLog)
	}
	if _, err := os.Stat(filepath.Join(outDir, "v1.0.0", "python3.13-slim-amd64.json")); err != nil {
		t.Fatalf("expected scan report after db update warning: %v", err)
	}
}

func TestScanUsesNixDevelopWhenCoreDirIsSet(t *testing.T) {
	old := scanOpts
	t.Cleanup(func() { scanOpts = old })

	sbomDir := filepath.Join(t.TempDir(), "sboms")
	outDir := filepath.Join(t.TempDir(), "vulns")
	writeTestFile(t, filepath.Join(sbomDir, "v1.0.0", "python3.13-slim-amd64.sbom.json"), []byte(`{"spdxVersion":"SPDX-2.3"}`))

	resultPath := filepath.Join(t.TempDir(), "result.json")
	writeTestFile(t, resultPath, []byte(`{"matches":[]}`))
	logPath := filepath.Join(t.TempDir(), "nix.log")
	binDir := t.TempDir()
	nix := filepath.Join(binDir, "nix")
	if err := os.WriteFile(nix, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$CLEARCUTT_FAKE_NIX_LOG"
while [ "$#" -gt 0 ] && [ "$1" != "--command" ]; do
  shift
done
if [ "$#" -gt 0 ] && [ "$1" = "--command" ]; then
  shift
fi
if [ "${1:-}" = "grype" ]; then
  shift
fi
if [ "${1:-}" = "version" ]; then
  printf '%s\n' '{"version":"0.99.0-nix","db":{"built":"2026-02-01T00:00:00Z"}}'
  exit 0
fi
if [ "${1:-}" = "db" ] && [ "${2:-}" = "update" ]; then
  printf '%s\n' db-updated >> "$CLEARCUTT_FAKE_NIX_LOG"
  exit 0
fi
cat "$CLEARCUTT_FAKE_GRYPE_RESULT"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CLEARCUTT_FAKE_GRYPE_RESULT", resultPath)
	t.Setenv("CLEARCUTT_FAKE_NIX_LOG", logPath)

	coreDir := t.TempDir()
	stdout, err := runCLI(t,
		"scan",
		"--mode", "release",
		"--core-dir", coreDir,
		"--update-db",
		"--sbom-dir", sbomDir,
		"--out-dir", outDir,
		"--concurrency", "1",
	)
	if err != nil {
		t.Fatalf("scan through nix develop failed: %v\n%s", err, stdout)
	}
	if _, err := os.Stat(filepath.Join(outDir, "v1.0.0", "python3.13-slim-amd64.json")); err != nil {
		t.Fatalf("expected scan report through nix develop: %v", err)
	}
	rawLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake nix log: %v", err)
	}
	log := string(rawLog)
	for _, want := range []string{
		"--command grype version -o json",
		"--command grype db update",
		"--command grype sbom:",
		"db-updated",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("nix log missing %q:\n%s", want, log)
		}
	}
}

// TestScanThroughNixResolvesRelativePathsAbsolutely guards the release/nightly
// regression where the catalog scan handed grype repo-root-RELATIVE paths
// (core/.grype.yaml, site/src/data/sboms/...) while grype ran through
// `nix develop` with cwd=core/. grype resolved them under core/ and aborted
// every scan with "invalid application config: file does not exist", so the
// catalog gained zero vulnerability coverage and catalog build failed. With
// relative --sbom-dir and --grype-config the -c and sbom: args grype receives
// must be absolute.
func TestScanThroughNixResolvesRelativePathsAbsolutely(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	// Relative layout mirroring the workflow: core/.grype.yaml + sboms/<tag>/.
	if err := os.MkdirAll(filepath.Join(root, "core"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "core", ".grype.yaml"), []byte("ignore: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tagDir := filepath.Join(root, "sboms", "v1.0.0")
	if err := os.MkdirAll(tagDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tagDir, "python3.13-slim-amd64.sbom.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	logPath := filepath.Join(root, "nix.log")
	resultPath := filepath.Join(root, "grype-result.json")
	if err := os.WriteFile(resultPath, []byte(`{"matches":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	nix := filepath.Join(binDir, "nix")
	if err := os.WriteFile(nix, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$CLEARCUTT_FAKE_NIX_LOG"
while [ "$#" -gt 0 ] && [ "$1" != "--command" ]; do shift; done
[ "$#" -gt 0 ] && [ "$1" = "--command" ] && shift
[ "${1:-}" = "grype" ] && shift
if [ "${1:-}" = "version" ]; then printf '%s\n' '{"version":"0.99.0-nix","db":{"built":"2026-02-01T00:00:00Z"}}'; exit 0; fi
if [ "${1:-}" = "db" ]; then exit 0; fi
# Faithfully reproduce grype's cwd-relative resolution: it runs with cwd=core/
# (nix develop dir), so any relative -c/sbom path must fail here.
for a in "$@"; do
  case "$a" in
    -c) expect_cfg=1 ;;
    sbom:*) p=${a#sbom:}; [ -f "$p" ] || { echo "sbom not found: $p" >&2; exit 1; } ;;
    *) if [ "${expect_cfg:-}" = "1" ]; then [ -f "$a" ] || { echo "config not found: $a" >&2; exit 1; }; expect_cfg=0; fi ;;
  esac
done
cat "$CLEARCUTT_FAKE_GRYPE_RESULT"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CLEARCUTT_FAKE_GRYPE_RESULT", resultPath)
	t.Setenv("CLEARCUTT_FAKE_NIX_LOG", logPath)

	stdout, err := runCLI(t,
		"scan", "--mode", "release",
		"--core-dir", "core",
		"--sbom-dir", "sboms",
		"--grype-config", filepath.Join("core", ".grype.yaml"),
		"--out-dir", filepath.Join(root, "out"),
		"--concurrency", "1",
	)
	if err != nil {
		t.Fatalf("scan failed (relative paths not absolutized?): %v\n%s", err, stdout)
	}
	if _, err := os.Stat(filepath.Join(root, "out", "v1.0.0", "python3.13-slim-amd64.json")); err != nil {
		t.Fatalf("scan produced no report — grype rejected the relative paths: %v\n%s", err, stdout)
	}
	rawLog, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range strings.Fields(string(rawLog)) {
		if sbom, ok := strings.CutPrefix(tok, "sbom:"); ok && !filepath.IsAbs(sbom) {
			t.Fatalf("grype SBOM source must be absolute, got %q", tok)
		}
	}
}

func TestScanRefreshKEVWritesCatalogAndStatus(t *testing.T) {
	old := scanRefreshKEVOpts
	t.Cleanup(func() { scanRefreshKEVOpts = old })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); !strings.Contains(got, "clearcutt/") {
			t.Fatalf("missing ClearCutt user agent: %q", got)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{
  "catalogVersion": "2026.07.01",
  "dateReleased": "2026-07-01",
  "count": 1,
  "vulnerabilities": [{"cveID": "CVE-2026-0001"}]
}`))
	}))
	t.Cleanup(server.Close)

	outPath := filepath.Join(t.TempDir(), "known_exploited_vulnerabilities.json")
	statusPath := filepath.Join(t.TempDir(), "kev-status.json")
	stdout, err := runCLI(t,
		"scan", "refresh-kev",
		"--url", server.URL,
		"--out", outPath,
		"--status-out", statusPath,
	)
	if err != nil {
		t.Fatalf("refresh-kev failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "KEV refresh available") {
		t.Fatalf("expected availability log, got:\n%s", stdout)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected KEV catalog: %v", err)
	}
	if !strings.Contains(string(raw), "CVE-2026-0001") {
		t.Fatalf("unexpected KEV catalog: %s", raw)
	}
	var status kevRefreshStatus
	rawStatus, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("expected KEV status: %v", err)
	}
	if err := json.Unmarshal(rawStatus, &status); err != nil {
		t.Fatalf("decode status: %v\n%s", err, rawStatus)
	}
	if status.Status != "available" || status.CatalogVersion == nil || *status.CatalogVersion != "2026.07.01" || status.Count == nil || *status.Count != 1 {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestScanRefreshKEVUnavailableRemovesStaleCatalog(t *testing.T) {
	old := scanRefreshKEVOpts
	t.Cleanup(func() { scanRefreshKEVOpts = old })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary outage", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	outPath := filepath.Join(t.TempDir(), "known_exploited_vulnerabilities.json")
	statusPath := filepath.Join(t.TempDir(), "kev-status.json")
	writeTestFile(t, outPath, []byte(`{"stale":true}`))
	stdout, err := runCLI(t,
		"scan", "refresh-kev",
		"--url", server.URL,
		"--out", outPath,
		"--status-out", statusPath,
	)
	if err != nil {
		t.Fatalf("refresh-kev should be non-fatal by default: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "KEV refresh unavailable") {
		t.Fatalf("expected unavailable warning, got:\n%s", stdout)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("stale KEV catalog should be removed, stat err=%v", err)
	}
	var status kevRefreshStatus
	rawStatus, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("expected unavailable status: %v", err)
	}
	if err := json.Unmarshal(rawStatus, &status); err != nil {
		t.Fatalf("decode status: %v\n%s", err, rawStatus)
	}
	if status.Status != "unavailable" || status.Error == nil || !strings.Contains(*status.Error, "503") {
		t.Fatalf("unexpected unavailable status: %#v", status)
	}

	stdout, err = runCLI(t,
		"scan", "refresh-kev",
		"--url", server.URL,
		"--out", outPath,
		"--status-out", statusPath,
		"--fail-on-unavailable",
	)
	if err == nil {
		t.Fatalf("refresh-kev --fail-on-unavailable should fail:\n%s", stdout)
	}
}

func TestScanBestEffortWarningsAndScanSBOMFailures(t *testing.T) {
	t.Setenv("GRYPE_BIN", filepath.Join(t.TempDir(), "missing-grype"))
	stdout, err := runCLI(t, "scan", "--mode", "catalog", "--sbom-dir", t.TempDir())
	if err != nil {
		t.Fatalf("best-effort missing grype should not fail: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "not on PATH") {
		t.Fatalf("expected warning for missing grype, got:\n%s", stdout)
	}

	grype := writeScript(t, "grype", `#!/bin/sh
set -eu
if [ "$1" = "version" ]; then
  printf '%s\n' '{"application":"grype-test"}'
  exit 0
fi
printf 'not-json'
`)
	outPath := filepath.Join(t.TempDir(), "report.json")
	_, err = scanSBOM(grype, nil, scanWorkItem{target: "java21-slim", sbomPath: filepath.Join(t.TempDir(), "sbom.json"), outPath: outPath}, "grype-test", nil, scanengine.NormalizeOptions{})
	if err == nil || !strings.Contains(err.Error(), "unparseable JSON") {
		t.Fatalf("expected unparseable JSON error, got %v", err)
	}

	failing := writeScript(t, "grype", `#!/bin/sh
set -eu
if [ "$1" = "version" ]; then
  printf '%s\n' '{'
  exit 0
fi
printf 'scan failed loudly' >&2
exit 7
`)
	version, db := grypeVersionProbe(failing)
	if version != "grype" || db != nil {
		t.Fatalf("malformed version probe should fall back, got %q %v", version, db)
	}
	_, err = scanSBOM(failing, []string{"--add-cpes-if-none"}, scanWorkItem{target: "java21-slim", sbomPath: "missing.sbom.json", outPath: outPath}, "bad", nil, scanengine.NormalizeOptions{})
	if err == nil || !strings.Contains(err.Error(), "grype failed") || !strings.Contains(err.Error(), "scan failed loudly") {
		t.Fatalf("expected grype failure with stderr snippet, got %v", err)
	}
}

func TestScanKEVCatalogLoaderBranches(t *testing.T) {
	if ptr := strPtrOrNil(""); ptr != nil {
		t.Fatalf("empty string should not produce pointer: %v", *ptr)
	}
	if ptr := strPtrOrNil("2026.06.09"); ptr == nil || *ptr != "2026.06.09" {
		t.Fatalf("expected string pointer, got %v", ptr)
	}

	catalog, status, version := loadScanKEVCatalog("")
	if catalog != nil || status != "unavailable" || version != nil {
		t.Fatalf("blank KEV path should be unavailable, got catalog=%v status=%q version=%v", catalog, status, version)
	}

	missingPath := filepath.Join(t.TempDir(), "missing-kev.json")
	catalog, status, version = loadScanKEVCatalog(missingPath)
	if catalog != nil || status != "unavailable" || version != nil {
		t.Fatalf("missing KEV path should be unavailable, got catalog=%v status=%q version=%v", catalog, status, version)
	}

	invalidPath := filepath.Join(t.TempDir(), "invalid-kev.json")
	writeTestFile(t, invalidPath, []byte(`not-json`))
	catalog, status, version = loadScanKEVCatalog(invalidPath)
	if catalog != nil || status != "unavailable" || version != nil {
		t.Fatalf("invalid KEV path should be unavailable, got catalog=%v status=%q version=%v", catalog, status, version)
	}

	validPath := filepath.Join(t.TempDir(), "kev.json")
	writeTestFile(t, validPath, []byte(`{
  "catalogVersion": "2026.06.09",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-2026-0001",
      "vendorProject": "Python",
      "product": "Python",
      "knownRansomwareCampaignUse": "Known",
      "dateAdded": "2026-06-09"
    }
  ]
}`))
	catalog, status, version = loadScanKEVCatalog(validPath)
	if catalog == nil || status != "available" || version == nil || *version != "2026.06.09" || catalog.Count != 1 {
		t.Fatalf("valid KEV path should load catalog, got catalog=%#v status=%q version=%v", catalog, status, version)
	}
}

func TestScanStrictModeFailsWhenGrypeMissing(t *testing.T) {
	t.Setenv("GRYPE_BIN", filepath.Join(t.TempDir(), "missing-grype"))
	stdout, err := runCLI(t, "scan", "--mode", "release", "--sbom-dir", t.TempDir())
	if err == nil {
		t.Fatalf("expected strict scan failure, got success:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "not on PATH") {
		t.Fatalf("expected missing grype failure, got %v", err)
	}
}

func writeScript(t *testing.T, name, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFakeGrype(t *testing.T, resultJSON string) string {
	t.Helper()
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "result.json")
	if err := os.WriteFile(resultPath, []byte(resultJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "grype")
	script := `#!/bin/sh
set -eu
if [ "$1" = "version" ]; then
  printf '%s\n' '{"version":"0.99.0-test","db":{"built":"2026-02-01T00:00:00Z"}}'
  exit 0
fi
cat "$CLEARCUTT_FAKE_GRYPE_RESULT"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLEARCUTT_FAKE_GRYPE_RESULT", resultPath)
	return path
}
