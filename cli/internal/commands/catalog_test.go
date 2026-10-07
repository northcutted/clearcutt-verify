package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
)

type fakeCatalogReleaseSource struct {
	releases  []catalogbuild.Release
	assets    map[string][]byte
	downloads []string
}

func (f *fakeCatalogReleaseSource) ListReleases(limit int) ([]catalogbuild.Release, error) {
	if limit > 0 && len(f.releases) > limit {
		return append([]catalogbuild.Release(nil), f.releases[:limit]...), nil
	}
	return append([]catalogbuild.Release(nil), f.releases...), nil
}

func (f *fakeCatalogReleaseSource) DownloadAsset(asset catalogbuild.Asset) ([]byte, error) {
	f.downloads = append(f.downloads, asset.Name)
	data, ok := f.assets[asset.Name]
	if !ok {
		return nil, fmt.Errorf("missing asset fixture %s", asset.Name)
	}
	return data, nil
}

// Exercises the full gather command through Cobra with an injected release
// source, then runs the catalog verifier against the generated files. This keeps
// the GitHub release seam honest without touching api.github.com.
func TestCatalogGatherCommandWritesVerifiableCatalogOffline(t *testing.T) {
	const target = "python3.13-slim"
	const tag = "v1.0.0"
	const publishedAt = "2026-05-29T13:44:59Z"

	temp := t.TempDir()
	outDir := filepath.Join(temp, "catalog")
	sbomDir := filepath.Join(temp, "sboms")
	enrichmentDir := filepath.Join(temp, "enrichment")
	vulnDir := filepath.Join(temp, "vulnerabilities")

	writeTestFile(t, filepath.Join(enrichmentDir, tag, target+".json"), []byte(`{
  "manifestDigest": "sha256:manifest-command",
  "architectures": [
    {
      "arch": "amd64",
      "digest": "sha256:image-amd64",
      "size": 11,
      "layers": [],
      "labels": {}
    }
  ],
  "signature": {
    "cosignBundlePresent": true
  },
  "provenance": {
    "predicateType": "https://slsa.dev/provenance/v1",
    "builder": { "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml" },
    "slsaLevel": 3
  },
  "attestations": [
    {
      "kind": "slsa-provenance",
      "predicateType": "https://slsa.dev/provenance/v1",
      "sources": ["oci", "github"]
    }
  ]
}`))
	writeTestFile(t, filepath.Join(vulnDir, tag, target+"-amd64.json"), []byte(`{"scannedAt":"2026-05-29T15:00:00Z","scanner":"grype-test","dbBuiltAt":null,"countsBySeverity":{"critical":0,"high":0,"medium":0,"low":0,"negligible":0,"unknown":0},"findings":[]}`))

	spdxRaw, err := os.ReadFile(filepath.Join("testdata", "catalog", "spdx-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeCatalogReleaseSource{
		releases: []catalogbuild.Release{{
			Tag:         tag,
			Name:        "v1.0.0",
			PublishedAt: publishedAt,
			Assets: []catalogbuild.Asset{
				{Name: target + "-amd64.sbom.json", URL: "https://example.invalid/" + target + "-amd64.sbom.json"},
				{Name: target + "-amd64.test-results.json", URL: "https://example.invalid/" + target + "-amd64.test-results.json"},
			},
		}},
		assets: map[string][]byte{
			target + "-amd64.sbom.json":         spdxRaw,
			target + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-05-29T13:59:00Z","assertions":[{"name":"Syft SBOM Generation","status":"passed"}]}`),
		},
	}

	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		if owner != "northcutted" || repo != "clearcutt" {
			t.Fatalf("unexpected release source request for %s/%s", owner, repo)
		}
		return source
	}

	stdout, err := runCLI(t,
		"catalog", "gather",
		"--owner", "northcutted",
		"--repo", "clearcutt",
		"--registry-base", "ghcr.io/northcutted/clearcutt",
		"--out-dir", outDir,
		"--enrichment-dir", enrichmentDir,
		"--sbom-cache-dir", sbomDir,
		"--vuln-dir", vulnDir,
		"--targets", target,
		"--limit", "1",
		"--force-refresh-all",
		"--generated-at", "2026-05-29T16:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog gather failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[gather] wrote python3.13-slim (1 releases)",
		"[gather] wrote index.json with 1 images",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected gather output %q, got:\n%s", want, stdout)
		}
	}
	for _, path := range []string{
		filepath.Join(outDir, "index.json"),
		filepath.Join(outDir, "images", target+".json"),
		filepath.Join(sbomDir, tag, target+"-amd64.sbom.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated file %s: %v", path, err)
		}
	}
	for _, want := range []string{target + "-amd64.sbom.json", target + "-amd64.test-results.json"} {
		if !contains(source.downloads, want) {
			t.Fatalf("expected offline fake to download %s, got %v", want, source.downloads)
		}
	}

	verifyOut, err := runCLI(t, "--catalog", outDir, "verify", "catalog")
	if err != nil {
		t.Fatalf("generated catalog did not verify: %v\n%s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, "ok: 1 latest images") {
		t.Fatalf("expected verifier ok summary, got:\n%s", verifyOut)
	}
}

func TestGithubReleaseSourceListsDownloadsAndReportsErrors(t *testing.T) {
	var requested []string
	source := &githubReleaseSource{
		owner: "acme",
		repo:  "clearcutt",
		token: "token-123",
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requested = append(requested, req.URL.String())
			if req.Header.Get("Authorization") != "Bearer token-123" {
				t.Fatalf("expected bearer token, got %q", req.Header.Get("Authorization"))
			}
			switch {
			case strings.Contains(req.URL.Path, "/releases"):
				return textResponse(200, `[
  {
    "tag_name": "v2.0.0",
    "name": "Release 2",
    "published_at": "2026-02-01T00:00:00Z",
    "draft": false,
    "prerelease": false,
    "assets": [
      {
        "name": "python3.13-slim-amd64.sbom.json",
        "browser_download_url": "https://downloads.example/sbom",
        "size": 42,
        "digest": "sha256:asset"
      }
    ]
  },
  {
    "tag_name": "v1.0.0",
    "name": "Draft",
    "created_at": "2026-01-01T00:00:00Z",
    "draft": true,
    "assets": []
  },
  {
    "tag_name": "v0.9.0",
    "name": "Old",
    "created_at": "2025-12-01T00:00:00Z",
    "draft": false,
    "prerelease": true,
    "assets": []
  }
]`), nil
			case req.URL.Host == "downloads.example":
				return textResponse(200, `asset-bytes`), nil
			default:
				return textResponse(500, strings.Repeat("x", 260)), nil
			}
		})},
	}

	releases, err := source.ListReleases(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 1 || releases[0].Tag != "v2.0.0" || len(releases[0].Assets) != 1 {
		t.Fatalf("unexpected releases: %#v", releases)
	}
	if releases[0].Assets[0].Digest == nil || *releases[0].Assets[0].Digest != "sha256:asset" {
		t.Fatalf("expected asset digest: %#v", releases[0].Assets[0])
	}
	data, err := source.DownloadAsset(releases[0].Assets[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "asset-bytes" {
		t.Fatalf("unexpected asset download: %q", data)
	}
	if len(requested) < 2 {
		t.Fatalf("expected release and asset requests, got %v", requested)
	}

	_, err = (&githubReleaseSource{client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return textResponse(500, strings.Repeat("x", 260)), nil
	})}}).get("https://api.example/error", "application/json")
	if err == nil || !strings.Contains(err.Error(), "failed: 500") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

func TestCatalogRepoDetectionAndExistingIndexRebuild(t *testing.T) {
	t.Setenv("GH_OWNER", "env-owner")
	t.Setenv("GH_REPO", "env-repo")
	owner, repo, err := detectCatalogRepo("", "")
	if err != nil {
		t.Fatal(err)
	}
	if owner != "env-owner" || repo != "env-repo" {
		t.Fatalf("unexpected env repo: %s/%s", owner, repo)
	}
	if owner, repo, err = detectCatalogRepo("flag-owner", "flag-repo"); err != nil || owner != "flag-owner" || repo != "flag-repo" {
		t.Fatalf("unexpected flag repo: %s/%s err=%v", owner, repo, err)
	}
	t.Setenv("GH_OWNER", "")
	t.Setenv("GH_REPO", "")
	t.Setenv("GITHUB_REPOSITORY", "repo-owner/repo-name")
	if owner, repo, err = detectCatalogRepo("", ""); err != nil || owner != "repo-owner" || repo != "repo-name" {
		t.Fatalf("unexpected GITHUB_REPOSITORY repo: %s/%s err=%v", owner, repo, err)
	}
	for _, tc := range []struct {
		remote string
		owner  string
		repo   string
	}{
		{"git@github.com:acme/clearcutt.git", "acme", "clearcutt"},
		{"https://github.com/acme/clearcutt.git", "acme", "clearcutt"},
		{"acme/clearcutt", "acme", "clearcutt"},
		{"not-a-github-remote", "", ""},
	} {
		gotOwner, gotRepo := parseGitHubRemote(tc.remote)
		if gotOwner != tc.owner || gotRepo != tc.repo {
			t.Fatalf("parseGitHubRemote(%q) = %s/%s, want %s/%s", tc.remote, gotOwner, gotRepo, tc.owner, tc.repo)
		}
	}

	outDir := writeCommandSmokeCatalog(t)
	ok, err := catalogbuild.RebuildIndexFromExistingImages("acme", "clearcutt", "ghcr.io/acme/clearcutt", outDir, "", "2026-02-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected existing image records to rebuild index")
	}
	var rebuilt catalog.CatalogIndex
	raw, err := os.ReadFile(filepath.Join(outDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &rebuilt); err != nil {
		t.Fatal(err)
	}
	if rebuilt.Owner != "acme" || rebuilt.LatestTag != "v2.0.0" || len(rebuilt.Images) != 1 || !rebuilt.Releases[0].IsLatest {
		t.Fatalf("unexpected rebuilt index: %#v", rebuilt)
	}
	ok, err = catalogbuild.RebuildIndexFromExistingImages("acme", "clearcutt", "ghcr.io/acme/clearcutt", filepath.Join(t.TempDir(), "missing"), "", "now")
	if err != nil || ok {
		t.Fatalf("missing image dir should not rebuild, ok=%v err=%v", ok, err)
	}
}

func TestCatalogRepoDetectionUsesGitRemoteAndReportsFailures(t *testing.T) {
	t.Setenv("GH_OWNER", "")
	t.Setenv("GH_REPO", "")
	t.Setenv("GITHUB_REPOSITORY", "")

	binDir := t.TempDir()
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", binDir); err != nil {
		t.Fatal(err)
	}

	gitPath := filepath.Join(binDir, "git")
	writeExecutable(t, gitPath, "#!/bin/sh\nprintf '%s\\n' 'git@github.com:remote-owner/remote-repo.git'\n")
	owner, repo, err := detectCatalogRepo("", "")
	if err != nil {
		t.Fatalf("expected fake git remote detection, got %v", err)
	}
	if owner != "remote-owner" || repo != "remote-repo" {
		t.Fatalf("unexpected fake git remote repo: %s/%s", owner, repo)
	}

	writeExecutable(t, gitPath, "#!/bin/sh\nexit 2\n")
	if _, _, err := detectCatalogRepo("", ""); err == nil || !strings.Contains(err.Error(), "unable to detect GitHub repo") {
		t.Fatalf("expected git detection failure, got %v", err)
	}

	writeExecutable(t, gitPath, "#!/bin/sh\nprintf '%s\\n' 'not-a-github-remote'\n")
	if _, _, err := detectCatalogRepo("", ""); err == nil || !strings.Contains(err.Error(), "unable to parse GitHub repo") {
		t.Fatalf("expected git parse failure, got %v", err)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
