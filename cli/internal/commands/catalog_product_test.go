package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/northcutted/clearcutt-verify/internal/estategraph"
)

func TestGenericImageBundleDefaultsToImportedGovernance(t *testing.T) {
	bundle, err := genericImageBundle(estategraph.ImageSpec{
		ID:            "sample",
		Image:         "registry.example.com/sample:1",
		Language:      catalog.LanguageInfo{ID: "sample", DisplayName: "Sample", Version: "1"},
		Tier:          "slim",
		Architectures: []string{"amd64"},
	}, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Record.Origin == nil || bundle.Record.Origin.Kind != "imported" || bundle.Record.Origin.CreatedByClearCutt || bundle.Record.Origin.ProvenanceClaim != "none" {
		t.Fatalf("generic record origin = %#v", bundle.Record.Origin)
	}
	if bundle.Summary.Governance == nil || !bundle.Summary.Governance.Imported || bundle.Summary.Governance.ProductionIntent != "unassessed" {
		t.Fatalf("generic summary governance = %#v", bundle.Summary.Governance)
	}
}

func TestCatalogValidateSummarizeAndInspectNamespace(t *testing.T) {
	validateOut, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "validate")
	if err != nil {
		t.Fatalf("catalog validate should pass with warnings: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "0 error(s)") || !strings.Contains(validateOut, "layerDigest mapping is unavailable") {
		t.Fatalf("expected validation warning output, got:\n%s", validateOut)
	}

	strictOut, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "validate", "--warnings-as-errors")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("warnings-as-errors should return ErrCheckFailed, got %v\n%s", err, strictOut)
	}

	schemaOut, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "validate", "--schema-version", catalog.ImageRecordSchemaVersion)
	if err != nil {
		t.Fatalf("fixture records declare %s and should satisfy it, got err=%v\n%s", catalog.ImageRecordSchemaVersion, err, schemaOut)
	}

	schemaOut, err = runCLI(t, "--catalog", fixtureCatalog(), "catalog", "validate", "--schema-version", catalog.ImageRecordSchemaVersionV2)
	if !errors.Is(err, ErrCheckFailed) || !strings.Contains(schemaOut, "does not match requested") {
		t.Fatalf("schema-version should reject records declaring a different version, got err=%v\n%s", err, schemaOut)
	}

	summaryOut, err := runCLI(t, "--catalog", fixtureCatalog(), "--format", "json", "catalog", "summarize")
	if err != nil {
		t.Fatalf("catalog summarize failed: %v\n%s", err, summaryOut)
	}
	var summary catalogSummaryReport
	if err := json.Unmarshal([]byte(summaryOut), &summary); err != nil {
		t.Fatalf("failed to decode summary JSON: %v\n%s", err, summaryOut)
	}
	if summary.ImageCount != 1 || summary.SignedCount != 1 || summary.SBOMCount != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}

	inspectOut, err := runCLI(t, "--catalog", fixtureCatalog(), "catalog", "inspect", "java21-distroless")
	if err != nil {
		t.Fatalf("catalog inspect failed: %v\n%s", err, inspectOut)
	}
	if !strings.Contains(inspectOut, "Digest Reference:") || !strings.Contains(inspectOut, "SPDX SBOMs:") {
		t.Fatalf("catalog inspect did not delegate to image inspector:\n%s", inspectOut)
	}
}

func TestMixedServiceCatalogFixtureValidatesAndInspectsStrictly(t *testing.T) {
	validateOut, err := runCLI(t, "--catalog", mixedFixtureCatalog(), "catalog", "validate")
	if err != nil {
		t.Fatalf("mixed service catalog fixture should validate: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "[catalog-validate] ok: 2 image record(s)") {
		t.Fatalf("expected successful validation, got:\n%s", validateOut)
	}

	inspectOut, err := runCLI(t, "--catalog", mixedFixtureCatalog(), "inspect", "postgres16", "--strict")
	if err != nil {
		t.Fatalf("strict service inspect failed: %v\n%s", err, inspectOut)
	}
	for _, want := range []string{"postgres16", "Ports:", "Supply Chain Evidence"} {
		if !strings.Contains(inspectOut, want) {
			t.Fatalf("expected service inspect output to contain %q, got:\n%s", want, inspectOut)
		}
	}
}

func TestCatalogDirectoryDiffReportsIndexLevelChanges(t *testing.T) {
	oldDir := copyFixtureCatalog(t)
	newDir := copyFixtureCatalog(t)

	indexPath := filepath.Join(newDir, "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index catalog.CatalogIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	newDigest := "sha256:changed"
	index.Images[0].LatestManifestDigest = &newDigest
	index.Images[0].LatestPackageCount++
	if index.Images[0].VulnSummary == nil {
		index.Images[0].VulnSummary = &catalog.VulnSummary{}
	}
	index.Images[0].VulnSummary.High = 7
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, err := runCLI(t, "--format", "json", "catalog", "diff", "--old", oldDir, "--new", newDir)
	if err != nil {
		t.Fatalf("catalog diff failed: %v\n%s", err, stdout)
	}
	var diff catalogDirectoryDiff
	if err := json.Unmarshal([]byte(stdout), &diff); err != nil {
		t.Fatalf("failed to decode diff JSON: %v\n%s", err, stdout)
	}
	if len(diff.ChangedImages) != 1 || diff.ChangedImages[0].ManifestDigest == nil || diff.ChangedImages[0].HighFindings == nil {
		t.Fatalf("expected digest and high CVE changes, got %#v", diff)
	}
}

func TestCatalogSiteScaffoldCopiesTemplateAndCatalog(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "site")
	stdout, err := runCLI(t, "catalog", "site", "scaffold", "--catalog", fixtureCatalog(), "--output", outDir)
	if err != nil {
		t.Fatalf("catalog site scaffold failed: %v\n%s", err, stdout)
	}
	for _, path := range []string{
		filepath.Join(outDir, "package.json"),
		filepath.Join(outDir, "astro.config.mjs"),
		filepath.Join(outDir, "README.md"),
		filepath.Join(outDir, "clearcutt.site.yaml"),
		filepath.Join(outDir, "src", "lib", "catalog.ts"),
		filepath.Join(outDir, "public", "catalog", "index.json"),
		filepath.Join(outDir, "public", "catalog", "images", "java21-distroless.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected scaffolded file %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "src", "data", "catalog", "index.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scaffold should not copy repo-local src/data/catalog, stat err=%v", err)
	}
	configRaw, err := os.ReadFile(filepath.Join(outDir, "clearcutt.site.yaml"))
	if err != nil {
		t.Fatalf("expected scaffolded site config: %v", err)
	}
	for _, want := range []string{
		"kyvernoPolicies: false",
		"sourceRepo:",
		"registry:",
		"support:",
		"terminology:",
	} {
		if !strings.Contains(string(configRaw), want) {
			t.Fatalf("expected scaffolded site config to contain %q, got:\n%s", want, configRaw)
		}
	}
	readmeRaw, err := os.ReadFile(filepath.Join(outDir, "README.md"))
	if err != nil {
		t.Fatalf("expected scaffolded README: %v", err)
	}
	for _, want := range []string{
		"clearcutt.site.yaml",
		"site-overrides",
		"site.features",
		"site.terminology",
		"source repository",
		"registry",
	} {
		if !strings.Contains(string(readmeRaw), want) {
			t.Fatalf("expected scaffolded README to contain %q, got:\n%s", want, readmeRaw)
		}
	}
	assertRawEvidenceDirs(t, filepath.Join(outDir, "public", "catalog"))
	if !strings.Contains(stdout, "npm run dev") {
		t.Fatalf("expected next-step output, got:\n%s", stdout)
	}

	stdout, err = runCLI(t, "catalog", "site", "scaffold", "--catalog", fixtureCatalog(), "--output", outDir)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("expected non-empty output protection, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteScaffoldWritesReadmeForTemplateWithoutOne(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	outDir := filepath.Join(t.TempDir(), "site")

	stdout, err := runCLI(t,
		"catalog", "site", "scaffold",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
	)
	if err != nil {
		t.Fatalf("catalog site scaffold failed: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "README.md"))
	if err != nil {
		t.Fatalf("expected generated README: %v", err)
	}
	for _, want := range []string{
		"ClearCutt Catalog Site",
		"public/catalog",
		"clearcutt.site.yaml",
		"site-overrides",
		"Kyverno",
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("expected generated README to contain %q, got:\n%s", want, raw)
		}
	}
}

func TestCatalogSiteScaffoldPreservesTemplateReadme(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	const customReadme = "# Custom Catalog Template\n\nInternal docs stay here.\n"
	if err := os.WriteFile(filepath.Join(templateDir, "README.md"), []byte(customReadme), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "site")

	stdout, err := runCLI(t,
		"catalog", "site", "scaffold",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
	)
	if err != nil {
		t.Fatalf("catalog site scaffold failed: %v\n%s", err, stdout)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "README.md"))
	if err != nil {
		t.Fatalf("expected copied README: %v", err)
	}
	if string(raw) != customReadme {
		t.Fatalf("expected custom template README to be preserved, got:\n%s", raw)
	}
}

func TestCatalogSiteScaffoldAppliesSiteOverrides(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	if err := os.MkdirAll(filepath.Join(templateDir, "src", "pages"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(templateDir, "src", "pages", "index.astro"), []byte("<h1>Template home</h1>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	overridesDir := filepath.Join(t.TempDir(), "site-overrides")
	for _, dir := range []string{
		filepath.Join(overridesDir, "components"),
		filepath.Join(overridesDir, "pages"),
		filepath.Join(overridesDir, "styles"),
		filepath.Join(overridesDir, "public", "branding"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(overridesDir, "components", "ImageHeader.astro"): "<section>Custom image header</section>\n",
		filepath.Join(overridesDir, "pages", "index.md"):               "# Custom home\n",
		filepath.Join(overridesDir, "styles", "theme.css"):             ":root { --brand: #123456; }\n",
		filepath.Join(overridesDir, "public", "branding", "logo.svg"):  "<svg viewBox=\"0 0 1 1\"></svg>\n",
	}
	for path, contents := range files {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	outDir := filepath.Join(t.TempDir(), "site")
	stdout, err := runCLI(t,
		"catalog", "site", "scaffold",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--overrides", overridesDir,
		"--output", outDir,
	)
	if err != nil {
		t.Fatalf("catalog site scaffold --overrides failed: %v\n%s", err, stdout)
	}
	for rel, want := range map[string]string{
		filepath.Join("src", "components", "ImageHeader.astro"): "<section>Custom image header</section>\n",
		filepath.Join("src", "styles", "theme.css"):             ":root { --brand: #123456; }\n",
		filepath.Join("public", "branding", "logo.svg"):         "<svg viewBox=\"0 0 1 1\"></svg>\n",
	} {
		raw, err := os.ReadFile(filepath.Join(outDir, rel))
		if err != nil {
			t.Fatalf("expected override file %s: %v", rel, err)
		}
		if string(raw) != want {
			t.Fatalf("override file %s = %q, want %q", rel, raw, want)
		}
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "src", "pages", "index.md"))
	if err != nil {
		t.Fatalf("expected markdown page override: %v", err)
	}
	if !strings.Contains(string(raw), "layout: ../layouts/Base.astro") || !strings.Contains(string(raw), "# Custom home") {
		t.Fatalf("markdown page override should get the default layout, got:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(outDir, "public", "catalog", "index.json")); err != nil {
		t.Fatalf("expected scaffolded catalog to remain present after overrides: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "src", "pages", "index.astro")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("page override should remove conflicting index.astro, stat err=%v", err)
	}
	if !strings.Contains(stdout, "[site] applied overrides from "+overridesDir) {
		t.Fatalf("expected override output, got:\n%s", stdout)
	}
}

func TestCatalogSiteScaffoldRejectsUnsupportedOverrideRoot(t *testing.T) {
	overridesDir := filepath.Join(t.TempDir(), "site-overrides")
	if err := os.MkdirAll(filepath.Join(overridesDir, "layouts"), 0o755); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "site")
	stdout, err := runCLI(t,
		"catalog", "site", "scaffold",
		"--catalog", fixtureCatalog(),
		"--overrides", overridesDir,
		"--output", outDir,
	)
	if err == nil || !strings.Contains(err.Error(), `unsupported site override directory "layouts"`) {
		t.Fatalf("expected unsupported override root error, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteEjectCopiesTemplateWithoutCatalogData(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	outDir := filepath.Join(t.TempDir(), "ejected")

	stdout, err := runCLI(t,
		"catalog", "site", "eject",
		"--template", templateDir,
		"--output", outDir,
	)
	if err != nil {
		t.Fatalf("catalog site eject failed: %v\n%s", err, stdout)
	}
	for _, path := range []string{
		filepath.Join(outDir, "package.json"),
		filepath.Join(outDir, "astro.config.mjs"),
		filepath.Join(outDir, "clearcutt.site.yaml"),
		filepath.Join(outDir, "src", "lib", "catalog.ts"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected ejected file %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "public", "catalog", "index.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("eject should not copy catalog data, stat err=%v", err)
	}
	if !strings.Contains(stdout, "Ejected catalog site template") || !strings.Contains(stdout, "add catalog data under public/catalog") {
		t.Fatalf("expected eject next-step output, got:\n%s", stdout)
	}

	stdout, err = runCLI(t,
		"catalog", "site", "eject",
		"--template", templateDir,
		"--output", outDir,
	)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("expected non-empty output protection, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteBuildRequiresInstallWhenDependenciesMissing(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	outDir := filepath.Join(t.TempDir(), "dist")

	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
	)
	if err == nil || !strings.Contains(err.Error(), "dependencies are not installed") {
		t.Fatalf("expected missing dependency error, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteBuildReportsMissingDetectedPackageManager(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	if err := os.WriteFile(filepath.Join(templateDir, "package-lock.json"), []byte(`{"lockfileVersion":3}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())

	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", filepath.Join(t.TempDir(), "dist"),
		"--install",
	)
	if err == nil || !strings.Contains(err.Error(), "npm was not found on PATH") || !strings.Contains(err.Error(), "package-lock.json") {
		t.Fatalf("expected missing npm error tied to package-lock, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSiteBuildRunsInstallAndCopiesStaticOutput(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "npm.log")
	fakeNPM := filepath.Join(binDir, "npm")
	if err := os.WriteFile(fakeNPM, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_NPM_LOG"
if [ "$1" = "install" ] || [ "$1" = "ci" ]; then
  mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "build" ]; then
  mkdir -p dist
  printf 'base=%s\nsite=%s\n' "${BASE_PATH:-}" "${SITE_URL:-}" > dist/index.html
  cp -R public/catalog dist/catalog
  if [ -d public/vex ]; then
    cp -R public/vex dist/vex
  fi
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_NPM_LOG", logPath)

	outDir := filepath.Join(t.TempDir(), "dist")
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
		"--install",
		"--base-path", "/docs",
		"--site-url", "https://acme.github.io",
		"--generate-vex",
	)
	if err != nil {
		t.Fatalf("catalog site build failed: %v\n%s", err, stdout)
	}
	index, err := os.ReadFile(filepath.Join(outDir, "index.html"))
	if err != nil {
		t.Fatalf("expected built index: %v", err)
	}
	if string(index) != "base=/docs\nsite=https://acme.github.io\n" {
		t.Fatalf("build env was not passed through: %q", index)
	}
	if _, err := os.Stat(filepath.Join(outDir, "catalog", "index.json")); err != nil {
		t.Fatalf("expected catalog assets in built output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "vex", "java21-distroless.json")); err != nil {
		t.Fatalf("expected generated OpenVEX assets in built output: %v", err)
	}
	logRaw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logRaw)
	if !strings.Contains(log, "install") || !strings.Contains(log, "run build") {
		t.Fatalf("expected install and build npm calls, got:\n%s", log)
	}
	if !strings.Contains(stdout, "Built catalog site at") {
		t.Fatalf("expected build success output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[site-build] generated ") || !strings.Contains(stdout, " OpenVEX document(s)") {
		t.Fatalf("expected VEX generation output, got:\n%s", stdout)
	}
}

func TestCatalogSiteBuildUsesPnpmLockWhenPresent(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	if err := os.WriteFile(filepath.Join(templateDir, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "pm.log")
	fakePNPM := filepath.Join(binDir, "pnpm")
	if err := os.WriteFile(fakePNPM, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_PM_LOG"
if [ "$1" = "install" ]; then
  /bin/mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "build" ]; then
  /bin/mkdir -p dist
  printf 'pnpm build\n' > dist/index.html
  /bin/cp -R public/catalog dist/catalog
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("FAKE_PM_LOG", logPath)

	outDir := filepath.Join(t.TempDir(), "dist")
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--output", outDir,
		"--install",
	)
	if err != nil {
		t.Fatalf("catalog site build with pnpm failed: %v\n%s", err, stdout)
	}
	logRaw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logRaw)
	for _, want := range []string{"install --frozen-lockfile", "run build"} {
		if !strings.Contains(log, want) {
			t.Fatalf("expected pnpm log to contain %q, got:\n%s", want, log)
		}
	}
}

func TestCatalogSiteBuildCanGenerateCatalogFromFleetConfig(t *testing.T) {
	const target = "python3.13-slim"
	const tag = "v1.0.0"
	const publishedAt = "2026-05-29T13:44:59Z"

	templateDir := writeMinimalSiteTemplate(t)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "npm.log")
	fakeNPM := filepath.Join(binDir, "npm")
	if err := os.WriteFile(fakeNPM, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_NPM_LOG"
if [ "$1" = "install" ] || [ "$1" = "ci" ]; then
  mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "build" ]; then
  mkdir -p dist
  printf 'generated\n' > dist/index.html
  cp -R public/catalog dist/catalog
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_NPM_LOG", logPath)
	t.Setenv("SBOM_CACHE_DIR", filepath.Join(t.TempDir(), "sboms"))
	t.Setenv("ENRICHMENT_DIR", filepath.Join(t.TempDir(), "missing-enrichment"))
	t.Setenv("VULN_DIR", filepath.Join(t.TempDir(), "missing-vulns"))

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
			},
		}},
		assets: map[string][]byte{
			target + "-amd64.sbom.json": spdxRaw,
		},
	}
	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		if owner != "acme" || repo != "platform" {
			t.Fatalf("unexpected release source request for %s/%s", owner, repo)
		}
		return source
	}

	cfg := config.DefaultConfig("acme", "platform")
	cfg.Matrix.Languages = []string{"python3.13"}
	cfg.Matrix.Tiers = []string{"slim"}
	cfg.Catalog.ReleaseLimit = 1
	configRaw, err := config.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), config.DefaultConfigPath)
	if err := os.WriteFile(configPath, configRaw, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "site-dist")
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--config", configPath,
		"--template", templateDir,
		"--output", outDir,
		"--install",
	)
	if err != nil {
		t.Fatalf("catalog site build --config failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[gather] wrote python3.13-slim (1 releases)",
		"[generate] wrote summary.json",
		"[site-build] generated catalog data from " + configPath,
		"Built catalog site at " + outDir,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected one-shot build output to contain %q, got:\n%s", want, stdout)
		}
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "catalog", "index.json"))
	if err != nil {
		t.Fatalf("expected built catalog index: %v", err)
	}
	var index catalog.CatalogIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatalf("failed to decode built catalog index: %v\n%s", err, raw)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersion || len(index.Images) != 1 || index.Images[0].ID != target {
		t.Fatalf("unexpected generated index in built site: %#v", index)
	}
	if _, err := os.Stat(filepath.Join(outDir, "catalog", "schemas", "image-record.v1.schema.json")); err != nil {
		t.Fatalf("expected generated schema assets in built site: %v", err)
	}
	if !contains(source.downloads, target+"-amd64.sbom.json") {
		t.Fatalf("expected one-shot build to download SBOM asset, got %v", source.downloads)
	}
}

func TestCatalogSiteBuildCanGenerateCatalogFromImagesInventory(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "npm.log")
	fakeNPM := filepath.Join(binDir, "npm")
	if err := os.WriteFile(fakeNPM, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_NPM_LOG"
if [ "$1" = "install" ] || [ "$1" = "ci" ]; then
  mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "build" ]; then
  mkdir -p dist
  printf 'generated\n' > dist/index.html
  cp -R public/catalog dist/catalog
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_NPM_LOG", logPath)

	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte(`images:
  - id: java21-distroless
    image: ghcr.io/acme/base/java21:v1.2.3
    language:
      id: java
      displayName: Java
      version: "21"
    tier: distroless
    architectures:
      - amd64
`), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "site-dist")
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--images", inventoryPath,
		"--template", templateDir,
		"--output", outDir,
		"--install",
		"--owner", "acme",
		"--repo", "base-images",
		"--generated-at", "2026-06-04T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog site build --images failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[generate] wrote 1 generic OCI image record(s)",
		"[site-build] generated catalog data from " + inventoryPath,
		"Built catalog site at " + outDir,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected one-shot images build output to contain %q, got:\n%s", want, stdout)
		}
	}
	index, err := catalog.LoadCatalogIndex(filepath.Join(outDir, "catalog"))
	if err != nil {
		t.Fatalf("expected built catalog index: %v", err)
	}
	if index.Owner != "acme" || index.Repo != "base-images" || len(index.Images) != 1 || index.Images[0].ID != "java21-distroless" {
		t.Fatalf("unexpected one-shot images catalog index: %#v", index)
	}
	assertRawEvidenceDirs(t, filepath.Join(outDir, "catalog"))
}

func TestCatalogSiteBuildRejectsConflictingGeneratedCatalogInputs(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte("images: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, err := runCLI(t,
		"catalog", "site", "build",
		"--config", config.DefaultConfigPath,
		"--images", inventoryPath,
		"--output", filepath.Join(t.TempDir(), "site"),
	)
	if err == nil || !strings.Contains(err.Error(), "--config and --images are mutually exclusive") {
		t.Fatalf("expected conflicting input error, got err=%v\n%s", err, stdout)
	}
}

func TestCatalogSitePreviewPrintsFallbackWhenDependenciesMissing(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	workDir := filepath.Join(t.TempDir(), "preview")

	stdout, err := runCLI(t,
		"catalog", "site", "preview",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--work-dir", workDir,
	)
	if err != nil {
		t.Fatalf("preview fallback should not fail: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"Catalog preview was not started",
		"npm install",
		"npm run dev -- --host 127.0.0.1 --port 4321",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected fallback output to contain %q, got:\n%s", want, stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(workDir, "public", "catalog", "index.json")); err != nil {
		t.Fatalf("preview fallback should leave reusable work-dir materialized: %v", err)
	}
}

func TestCatalogSitePreviewRunsInstallAndDevServerCommand(t *testing.T) {
	templateDir := writeMinimalSiteTemplate(t)
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "npm.log")
	fakeNPM := filepath.Join(binDir, "npm")
	if err := os.WriteFile(fakeNPM, []byte(`#!/bin/sh
set -eu
printf '%s BASE_PATH=%s\n' "$*" "${BASE_PATH:-}" >> "$FAKE_NPM_LOG"
if [ "$1" = "install" ] || [ "$1" = "ci" ]; then
  mkdir -p node_modules
  exit 0
fi
if [ "$1" = "run" ] && [ "${2:-}" = "dev" ]; then
  exit 0
fi
exit 2
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_NPM_LOG", logPath)

	workDir := filepath.Join(t.TempDir(), "preview")
	stdout, err := runCLI(t,
		"catalog", "site", "preview",
		"--catalog", fixtureCatalog(),
		"--template", templateDir,
		"--work-dir", workDir,
		"--install",
		"--base-path", "/catalog",
		"--host", "0.0.0.0",
		"--port", "4567",
	)
	if err != nil {
		t.Fatalf("catalog site preview failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "http://0.0.0.0:4567") {
		t.Fatalf("expected preview URL output, got:\n%s", stdout)
	}
	logRaw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logRaw)
	for _, want := range []string{
		"install BASE_PATH=",
		"run dev -- --host 0.0.0.0 --port 4567 BASE_PATH=/catalog",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("expected npm log to contain %q, got:\n%s", want, log)
		}
	}
}

func TestCatalogGenerateWritesSummaryJSONFromExistingRecords(t *testing.T) {
	outDir := copyFixtureCatalog(t)
	orphanPath := filepath.Join(outDir, "images", "python3.13-dev.json")
	if err := os.WriteFile(orphanPath, []byte(`{"id":"python3.13-dev"}`), 0o644); err != nil {
		t.Fatalf("write orphan image record: %v", err)
	}
	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		return &fakeCatalogReleaseSource{}
	}

	stdout, err := runCLI(t,
		"catalog", "generate",
		"--owner", "northcutted",
		"--repo", "clearcutt",
		"--registry-base", "ghcr.io/northcutted/clearcutt",
		"--output", outDir,
		"--vuln-dir", filepath.Join(t.TempDir(), "missing-vulns"),
		"--generated-at", "2026-06-03T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog generate failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{"[generate] wrote summary.json", "[generate] wrote evidence-manifest.json"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected generate output %q, got:\n%s", want, stdout)
		}
	}
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatalf("catalog generate should remove orphan image records, stat err=%v", err)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "summary.json"))
	if err != nil {
		t.Fatalf("expected generated summary.json: %v", err)
	}
	var summary catalogSummaryReport
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatalf("failed to decode generated summary: %v\n%s", err, raw)
	}
	if summary.ImageCount != 1 || summary.LatestTag == "" {
		t.Fatalf("unexpected generated summary: %#v", summary)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(outDir, evidenceManifestFilename))
	if err != nil {
		t.Fatalf("expected generated evidence manifest: %v", err)
	}
	var manifest evidenceManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("failed to decode generated evidence manifest: %v\n%s", err, manifestRaw)
	}
	if manifest.SchemaVersion != catalog.EvidenceManifestSchemaVersion || manifest.Summary.ImageReleases != 1 || manifest.Summary.Complete != 1 {
		t.Fatalf("unexpected generated evidence manifest summary: %#v", manifest)
	}
	if got := manifest.Releases[0].ImageRef; got != "ghcr.io/test-owner/test-repo/clearcutt-java:v1.0.0-distroless" {
		t.Fatalf("unexpected manifest image ref %q", got)
	}
	if manifest.Releases[0].ImmutableRef == nil || !strings.Contains(*manifest.Releases[0].ImmutableRef, "@sha256:") {
		t.Fatalf("expected immutable ref in manifest release: %#v", manifest.Releases[0])
	}
	for _, schemaName := range []string{"catalog-index.v1.schema.json", "evidence-manifest.v1.schema.json", "evidence-manifest.v2.schema.json", "image-record.v1.schema.json"} {
		schemaRaw, err := os.ReadFile(filepath.Join(outDir, "schemas", schemaName))
		if err != nil {
			t.Fatalf("expected generated schema %s: %v", schemaName, err)
		}
		if !strings.Contains(string(schemaRaw), "schemaVersion") {
			t.Fatalf("expected generated schema %s to describe schemaVersion", schemaName)
		}
		if schemaName == "image-record.v1.schema.json" && !strings.Contains(string(schemaRaw), "catalog-index.v1.schema.json#/definitions/Lifecycle") {
			t.Fatalf("expected image schema to reference versioned catalog index schema:\n%s", schemaRaw)
		}
	}
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("expected generated index: %v", err)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersion {
		t.Fatalf("expected generated index schemaVersion %q, got %q", catalog.CatalogIndexSchemaVersion, index.SchemaVersion)
	}
	wantGeneratorVersion, wantGeneratorCommit := generatorIdentity()
	if index.Generator == nil || index.Generator.Name != "clearcutt" || index.Generator.Version != wantGeneratorVersion || index.Generator.Commit != wantGeneratorCommit {
		t.Fatalf("unexpected generated index generator metadata: %#v", index.Generator)
	}
	if index.Source == nil || index.Source.Owner != "northcutted" || index.Source.Repo != "clearcutt" || index.Source.RegistryBase != "ghcr.io/northcutted/clearcutt" {
		t.Fatalf("unexpected generated index source metadata: %#v", index.Source)
	}
	if index.Summary == nil || index.Summary.ImageCount != 1 || index.Summary.ReleaseCount != 1 || index.Summary.SBOMCount != 1 || index.Summary.ScanCount != 1 {
		t.Fatalf("unexpected generated index summary: %#v", index.Summary)
	}
	assertRawEvidenceDirs(t, outDir)
	if len(index.Images) != 1 {
		t.Fatalf("expected one generated image summary, got %d", len(index.Images))
	}
	record, err := catalog.LoadImageRecord(outDir, index.Images[0].ID)
	if err != nil {
		t.Fatalf("expected generated image record: %v", err)
	}
	if record.SchemaVersion != catalog.ImageRecordSchemaVersion {
		t.Fatalf("expected generated image schemaVersion %q, got %q", catalog.ImageRecordSchemaVersion, record.SchemaVersion)
	}
	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.CatalogIndexSchemaVersion)
	if err != nil {
		t.Fatalf("generated catalog should satisfy index schema version: %v\n%s", err, validateOut)
	}
	validateOut, err = runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.ImageRecordSchemaVersion)
	if err != nil {
		t.Fatalf("generated catalog should satisfy image schema version: %v\n%s", err, validateOut)
	}
	validateOut, err = runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.EvidenceManifestSchemaVersion)
	if err != nil {
		t.Fatalf("generated catalog should satisfy evidence manifest schema version: %v\n%s", err, validateOut)
	}
}

func TestEvidenceManifestHelperAndErrorBranches(t *testing.T) {
	partial := countedChannelStatus(true, catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "test"}, 1, 2, "architecture SBOMs")
	if partial.Status != catalog.EvidenceStatusObserved || partial.Detail != "1/2 architecture SBOMs" {
		t.Fatalf("expected partial counted channel, got %#v", partial)
	}

	exceptionStatus := exceptionsChannelStatus(catalog.ExceptionSummary{Total: 3, Active: 2, Expired: 1})
	if exceptionStatus.Status != "present" || !exceptionStatus.Expected || !exceptionStatus.Observed || !strings.Contains(exceptionStatus.Detail, "3 total exceptions") {
		t.Fatalf("expected present exception channel, got %#v", exceptionStatus)
	}

	vexStatus := vexChannelStatus("java21-distroless", "v1.2.3", catalog.ExceptionSummary{Total: 1})
	if vexStatus.Status != "on_demand" || vexStatus.Expected || vexStatus.Observed || !strings.Contains(vexStatus.Detail, "clearcutt-verify vex java21-distroless --tag v1.2.3") {
		t.Fatalf("expected on-demand VEX channel, got %#v", vexStatus)
	}

	missing := missingEvidenceChannels(evidenceManifestChannels{
		Signature:       evidenceManifestChannel{Expected: true, Observed: false},
		Provenance:      evidenceManifestChannel{Expected: true, Observed: true},
		SBOM:            evidenceManifestChannel{Expected: true, Observed: false},
		Tests:           evidenceManifestChannel{Expected: false, Observed: false},
		Vulnerabilities: evidenceManifestChannel{Expected: true, Observed: false},
		Exceptions:      evidenceManifestChannel{Expected: true, Observed: false},
	})
	if got := strings.Join(missing, ","); got != "signature,sbom,vulnerabilities,exceptions" {
		t.Fatalf("unexpected missing channel list %q", got)
	}

	badDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(badDir, evidenceManifestFilename), []byte("{"), 0o644); err != nil {
		t.Fatalf("write invalid manifest: %v", err)
	}
	if _, err := loadEvidenceManifest(badDir); err == nil {
		t.Fatal("expected invalid evidence manifest JSON to fail")
	}
	if err := writeEvidenceManifestFile(t.TempDir()); err == nil {
		t.Fatal("expected writing evidence manifest without catalog index to fail")
	}
}

func TestValidateEvidenceManifestBranches(t *testing.T) {
	var errors []string
	addError := func(format string, args ...any) {
		errors = append(errors, fmt.Sprintf(format, args...))
	}

	missingRequiredDir := copyFixtureCatalog(t)
	if err := os.Remove(filepath.Join(missingRequiredDir, evidenceManifestFilename)); err != nil {
		t.Fatalf("remove evidence manifest: %v", err)
	}
	validateEvidenceManifest(missingRequiredDir, catalog.EvidenceManifestSchemaVersion, addError)
	if len(errors) != 1 || !strings.Contains(errors[0], "missing required schemaVersion") {
		t.Fatalf("expected required missing manifest error, got %#v", errors)
	}

	errors = nil
	validateEvidenceManifest(missingRequiredDir, "", addError)
	if len(errors) != 0 {
		t.Fatalf("missing manifest should be optional unless schemaVersion is requested, got %#v", errors)
	}

	invalidDir := copyFixtureCatalog(t)
	if err := os.WriteFile(filepath.Join(invalidDir, evidenceManifestFilename), []byte("{"), 0o644); err != nil {
		t.Fatalf("write invalid evidence manifest: %v", err)
	}
	errors = nil
	validateEvidenceManifest(invalidDir, "", addError)
	if len(errors) != 1 || !strings.Contains(errors[0], "unexpected end of JSON input") {
		t.Fatalf("expected invalid manifest JSON error, got %#v", errors)
	}

	staleDir := copyFixtureCatalog(t)
	manifest, err := buildEvidenceManifest(staleDir)
	if err != nil {
		t.Fatalf("build evidence manifest: %v", err)
	}
	manifest.SchemaVersion = "clearcutt.catalog.evidence-manifest/v0"
	if err := writeJSONFile(filepath.Join(staleDir, evidenceManifestFilename), manifest); err != nil {
		t.Fatalf("write stale evidence manifest: %v", err)
	}
	errors = nil
	validateEvidenceManifest(staleDir, "", addError)
	if got := strings.Join(errors, "\n"); !strings.Contains(got, "unsupported schemaVersion") || !strings.Contains(got, "does not match catalog image records") {
		t.Fatalf("expected stale manifest errors, got %#v", errors)
	}

	rebuildFailureDir := t.TempDir()
	if err := writeJSONFile(filepath.Join(rebuildFailureDir, evidenceManifestFilename), evidenceManifest{SchemaVersion: catalog.EvidenceManifestSchemaVersion}); err != nil {
		t.Fatalf("write manifest without catalog: %v", err)
	}
	errors = nil
	validateEvidenceManifest(rebuildFailureDir, "", addError)
	if len(errors) != 1 || !strings.Contains(errors[0], "failed to rebuild expected manifest") {
		t.Fatalf("expected rebuild failure error, got %#v", errors)
	}
}

func TestCatalogValidateRejectsOrphanImageRecords(t *testing.T) {
	outDir := copyFixtureCatalog(t)
	orphanPath := filepath.Join(outDir, "images", "python3.13-dev.json")
	if err := os.WriteFile(orphanPath, []byte(`{"id":"python3.13-dev"}`), 0o644); err != nil {
		t.Fatalf("write orphan image record: %v", err)
	}

	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate")
	if err == nil {
		t.Fatalf("expected orphan image validation to fail:\n%s", validateOut)
	}
	if !strings.Contains(validateOut, "images/python3.13-dev.json: image record is not referenced by index.json") {
		t.Fatalf("expected orphan image error, got err=%v\n%s", err, validateOut)
	}
}

func TestCatalogValidateRejectsStaleEvidenceManifest(t *testing.T) {
	outDir := copyFixtureCatalog(t)
	if err := writeEvidenceManifestFile(outDir); err != nil {
		t.Fatalf("write evidence manifest: %v", err)
	}

	manifest, err := loadEvidenceManifest(outDir)
	if err != nil {
		t.Fatalf("load evidence manifest: %v", err)
	}
	manifest.Releases[0].Channels.Signature.Observed = false
	manifest.Releases[0].Channels.Signature.Status = "missing"
	if err := writeJSONFile(filepath.Join(outDir, evidenceManifestFilename), manifest); err != nil {
		t.Fatalf("write stale evidence manifest: %v", err)
	}

	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate")
	if err == nil {
		t.Fatalf("expected stale manifest validation to fail:\n%s", validateOut)
	}
	if !strings.Contains(validateOut, "evidence-manifest.json: does not match catalog image records") {
		t.Fatalf("expected stale manifest error, got err=%v\n%s", err, validateOut)
	}
}

func TestCatalogGenerateIncludeServicesEmitsV2ServiceRecords(t *testing.T) {
	outDir := copyFixtureCatalog(t)
	root := t.TempDir()
	cfg := config.DefaultConfig("acme", "platform")
	cfg.Services = []config.ServiceImage{{
		ID:       "postgres16",
		Template: "postgres",
		Version:  "16",
	}}
	raw, err := config.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	configPath := filepath.Join(root, config.DefaultConfigPath)
	if err := os.WriteFile(configPath, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}

	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		return &fakeCatalogReleaseSource{}
	}

	stdout, err := runCLI(t,
		"catalog", "generate",
		"--config", configPath,
		"--output", outDir,
		"--vuln-dir", filepath.Join(t.TempDir(), "missing-vulns"),
		"--generated-at", "2026-06-04T12:00:00Z",
		"--include-services",
	)
	if err != nil {
		t.Fatalf("catalog generate --include-services failed: %v\n%s", err, stdout)
	}
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("load generated index: %v", err)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersionV2 {
		t.Fatalf("expected v2 index schema, got %q", index.SchemaVersion)
	}
	if index.Summary == nil || index.Summary.ImageCount != 2 {
		t.Fatalf("expected runtime plus service summary, got %#v", index.Summary)
	}
	service, err := catalog.LoadImageRecord(outDir, "postgres16")
	if err != nil {
		t.Fatalf("load service record: %v", err)
	}
	if service.SchemaVersion != catalog.ImageRecordSchemaVersionV2 || service.Kind != "service" || service.Service == nil {
		t.Fatalf("unexpected service record: %#v", service)
	}
	if service.Service.Template != "postgres" || service.Service.Ports[0].Port != 5432 || !service.Service.Stateful {
		t.Fatalf("unexpected service metadata: %#v", service.Service)
	}
	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate")
	if err != nil {
		t.Fatalf("mixed service catalog should validate with warnings only: %v\n%s", err, validateOut)
	}
	for _, schemaName := range []string{"catalog-index.v2.schema.json", "evidence-manifest.v1.schema.json", "evidence-manifest.v2.schema.json", "image-record.v2.schema.json"} {
		if _, err := os.Stat(filepath.Join(outDir, "schemas", schemaName)); err != nil {
			t.Fatalf("expected generated v2 schema %s: %v", schemaName, err)
		}
	}
}

func TestCatalogGenerateIncludeServicesFoldsServiceReleaseAssets(t *testing.T) {
	const target = "postgres16"
	const tag = "v1.0.0"
	const publishedAt = "2026-06-05T12:00:00Z"

	outDir := filepath.Join(t.TempDir(), "catalog")
	sbomDir := filepath.Join(t.TempDir(), "sboms")
	enrichmentDir := filepath.Join(t.TempDir(), "enrichment")
	writeTestFile(t, filepath.Join(enrichmentDir, tag, target+".json"), []byte(`{
  "manifestDigest": "sha256:service-manifest",
  "architectures": [
    {
      "arch": "amd64",
      "digest": "sha256:service-amd64",
      "size": 42,
      "layers": [],
      "labels": {
        "dev.clearcutt.image.kind": "service",
        "dev.clearcutt.service.id": "postgres16"
      }
    }
  ],
  "signature": {
    "cosignBundlePresent": true
  },
  "provenance": {
    "predicateType": "https://slsa.dev/provenance/v1",
    "builder": { "id": "service-builder" },
    "slsaLevel": 3
  }
}`))

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
			target + "-amd64.test-results.json": []byte(`{"status":"passed","timestamp":"2026-06-05T12:05:00Z","assertions":[{"name":"Syft SBOM Generation","status":"passed"}]}`),
		},
	}
	oldNewReleaseSource := newReleaseSource
	t.Cleanup(func() { newReleaseSource = oldNewReleaseSource })
	newReleaseSource = func(owner, repo, token string) catalogbuild.ReleaseSource {
		return source
	}

	root := t.TempDir()
	cfg := config.DefaultConfig("acme", "platform")
	cfg.Matrix.Languages = []string{"java21"}
	cfg.Matrix.Tiers = []string{"distroless"}
	cfg.Catalog.ReleaseLimit = 1
	cfg.Services = []config.ServiceImage{{
		ID:       target,
		Template: "postgres",
		Version:  "16",
	}}
	raw, err := config.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	configPath := filepath.Join(root, config.DefaultConfigPath)
	if err := os.WriteFile(configPath, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}

	stdout, err := runCLI(t,
		"catalog", "generate",
		"--config", configPath,
		"--output", outDir,
		"--sbom-cache-dir", sbomDir,
		"--enrichment-dir", enrichmentDir,
		"--vuln-dir", filepath.Join(t.TempDir(), "missing-vulns"),
		"--generated-at", "2026-06-05T12:30:00Z",
		"--include-services",
	)
	if err != nil {
		t.Fatalf("catalog generate --include-services failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "[gather] wrote service postgres16 (1 releases)") {
		t.Fatalf("expected service gather output, got:\n%s", stdout)
	}
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("load generated index: %v", err)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersionV2 || len(index.Images) != 1 {
		t.Fatalf("expected service-only v2 index, got %#v", index)
	}
	serviceSummary := index.Images[0]
	if serviceSummary.ID != target || serviceSummary.Kind != "service" || len(serviceSummary.Architectures) != 1 || serviceSummary.Architectures[0] != "amd64" {
		t.Fatalf("unexpected service index summary: %#v", serviceSummary)
	}
	if serviceSummary.Evidence == nil || !serviceSummary.Evidence.SBOM || !serviceSummary.Evidence.Tests || !serviceSummary.Evidence.Signature || !serviceSummary.Evidence.Provenance {
		t.Fatalf("expected complete service evidence summary: %#v", serviceSummary.Evidence)
	}
	record, err := catalog.LoadImageRecord(outDir, target)
	if err != nil {
		t.Fatalf("load service record: %v", err)
	}
	if len(record.Releases) != 1 || len(record.Releases[0].Architectures) != 1 {
		t.Fatalf("expected service release architecture evidence, got %#v", record.Releases)
	}
	if record.Releases[0].Architectures[0].SBOM.PackageCount == 0 || record.Releases[0].Architectures[0].TestResults == nil {
		t.Fatalf("expected service SBOM and test evidence, got %#v", record.Releases[0].Architectures[0])
	}
	if !contains(source.downloads, target+"-amd64.sbom.json") {
		t.Fatalf("expected service SBOM download, got %v", source.downloads)
	}
	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate")
	if err != nil {
		t.Fatalf("service evidence catalog should validate with warnings only: %v\n%s", err, validateOut)
	}
}

func TestServiceCatalogMetadataOverlayAndSummaries(t *testing.T) {
	cfg := config.DefaultConfig("acme", "platform")
	cfg.Registry.ImagePrefix = "platform"
	service := config.ServiceImage{
		ID:         "postgres16",
		Template:   "postgres",
		Version:    "16",
		Ports:      []config.ServicePort{{Name: "postgres", Port: 5432, Protocol: "tcp"}},
		Stateful:   true,
		DataDirs:   []string{"/var/lib/postgresql/data"},
		Entrypoint: []string{"clearcutt-postgres-entrypoint"},
		Smoke:      []string{"postgres --version"},
		Lifecycle:  config.ServiceLifecycle{Status: "preview", Support: "current"},
	}
	record := serviceCatalogRecord(cfg, service, "v1.0.0", "2026-06-05T20:00:00Z")
	record.Releases[0].ManifestDigest = strPtr("sha256:service")
	record.Releases[0].Signature = &catalog.SignatureInfo{CosignBundlePresent: true}
	record.Releases[0].Provenance = &catalog.ProvenanceInfo{PredicateType: "https://slsa.dev/provenance/v1", Builder: catalog.BuilderInfo{ID: "builder"}, SlsaLevel: 3}
	record.Releases[0].Architectures = []catalog.ArchPayload{{
		Arch:        "amd64",
		OS:          "linux",
		SBOM:        catalog.SBOMInfo{PackageCount: 5},
		TestResults: &catalog.TestResultsInfo{Status: "passed"},
		Vulnerabilities: &catalog.VulnerabilitiesInfo{
			ScannedAt: "2026-06-05T21:00:00Z",
			Findings: []catalog.FindingInfo{
				{ID: "CVE-1", Severity: "Critical", PackageName: "postgresql", PackageVersion: "16.9", Layer: "runtime", FixedIn: strPtr("16.10")},
				{ID: "CVE-2", Severity: "High", PackageName: "openssl", PackageVersion: "3.5.0", Layer: "base"},
				{ID: "CVE-3", Severity: "High", PackageName: "zlib", PackageVersion: "1.3.1", Layer: "runtime"},
				{ID: "CVE-4", Severity: "Medium", PackageName: "icu", PackageVersion: "75", Layer: "runtime", FixedIn: strPtr("76")},
				{ID: "CVE-5", Severity: "High", PackageName: "curl", PackageVersion: "8.8.0", Layer: "runtime", Remediation: &catalog.RemediationInfo{Reason: "custom_reason"}},
			},
		},
	}}
	record.Releases[0].Evidence = nil

	overlaid := serviceCatalogRecordFromExisting(cfg, service, record)
	if overlaid.SchemaVersion != catalog.ImageRecordSchemaVersionV2 || overlaid.Kind != "service" || overlaid.Service == nil {
		t.Fatalf("unexpected service overlay: %#v", overlaid)
	}
	if overlaid.Releases[0].Evidence == nil || !overlaid.Releases[0].Evidence.Signature || !overlaid.Releases[0].Evidence.SBOM || !overlaid.Releases[0].Evidence.Tests {
		t.Fatalf("expected recomputed service evidence, got %#v", overlaid.Releases[0].Evidence)
	}

	summary := serviceCatalogSummary(overlaid)
	if summary.LatestManifestDigest == nil || *summary.LatestManifestDigest != "sha256:service" || summary.LatestPackageCount != 5 || !summary.Passed {
		t.Fatalf("unexpected service summary basics: %#v", summary)
	}
	if summary.VulnSummary == nil || summary.VulnSummary.Critical != 1 || summary.VulnSummary.High != 3 || summary.VulnSummary.Medium != 1 {
		t.Fatalf("unexpected service vulnerability summary: %#v", summary.VulnSummary)
	}
	remediation := summary.VulnSummary.Remediation
	if remediation == nil || remediation.Eligible != 1 || remediation.BaseLayer != 1 || remediation.NoFixedVersion != 1 || remediation.OtherDeferred != 1 {
		t.Fatalf("unexpected service remediation buckets: %#v", remediation)
	}

	if got := serviceInspectPorts(serviceCatalogInfo(service).Ports); got != "postgres:5432/tcp" {
		t.Fatalf("unexpected service port label: %q", got)
	}
	if got := serviceInspectPorts([]catalog.ServicePortInfo{{Port: 4180}}); got != "4180/tcp" {
		t.Fatalf("unexpected unnamed service port label: %q", got)
	}
	if got := serviceInspectPorts(nil); got != "none" {
		t.Fatalf("unexpected empty service port label: %q", got)
	}
	if got := serviceDefaultEntrypoint(service); got != "/bin/clearcutt-postgres-entrypoint" {
		t.Fatalf("unexpected generated service entrypoint: %q", got)
	}
	service.Entrypoint = []string{"/custom/entrypoint", "arg"}
	if got := serviceDefaultEntrypoint(service); got != "/custom/entrypoint /bin/arg" {
		t.Fatalf("unexpected mixed service entrypoint: %q", got)
	}

	oauth := config.ServiceImage{Template: "oauth2-proxy", Entrypoint: []string{"oauth2-proxy"}}
	contract := serviceCatalogBuildRuntimeContract(oauth)
	if contract.User != "10001:10001" || contract.ShellPresent || !contract.CACertificatesPresent || contract.DefaultEntrypoint == nil || *contract.DefaultEntrypoint != "/bin/oauth2-proxy" {
		t.Fatalf("unexpected service build runtime contract: %#v", contract)
	}
	if serviceRemediationBucket("below_priority_threshold") != "belowPriorityThreshold" || serviceRemediationBucket("unknown") != "otherDeferred" {
		t.Fatal("service remediation bucket branches drifted")
	}
}

func TestCatalogGenerateFromGenericOCIImagesInventory(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte(`images:
  - id: java21-distroless
    image: ghcr.io/acme/base/java21:v1.2.3
    language:
      id: java
      displayName: Java
      version: "21"
    tier: distroless
    architectures:
      - amd64
      - arm64
    origin:
      kind: imported
      createdByClearCutt: false
      provenanceClaim: none
    governance:
      imported: true
      classificationConfidence: high
    evidencePolicy:
      provenance: optional
`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "catalog")

	stdout, err := runCLI(t,
		"catalog", "generate",
		"--images", inventoryPath,
		"--output", outDir,
		"--owner", "acme",
		"--repo", "base-images",
		"--generated-at", "2026-06-04T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog generate --images failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		"[generate] wrote 1 generic OCI image record(s)",
		"[generate] wrote summary.json",
		"[generate] wrote evidence-manifest.json",
		"[generate] wrote schemas/",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected generic generate output to contain %q, got:\n%s", want, stdout)
		}
	}

	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("expected generated index: %v", err)
	}
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersion {
		t.Fatalf("expected index schemaVersion %q, got %q", catalog.CatalogIndexSchemaVersion, index.SchemaVersion)
	}
	if index.Owner != "acme" || index.Repo != "base-images" || index.RegistryBase != "ghcr.io" {
		t.Fatalf("unexpected generic index identity: %#v", index)
	}
	wantGeneratorVersion, wantGeneratorCommit := generatorIdentity()
	if index.Generator == nil || index.Generator.Name != "clearcutt" || index.Generator.Version != wantGeneratorVersion || index.Generator.Commit != wantGeneratorCommit {
		t.Fatalf("unexpected generic generator metadata: %#v", index.Generator)
	}
	if index.Source == nil || index.Source.Owner != "acme" || index.Source.Repo != "base-images" || index.Source.RegistryBase != "ghcr.io" {
		t.Fatalf("unexpected generic source metadata: %#v", index.Source)
	}
	if index.Summary == nil || index.Summary.ImageCount != 1 || index.Summary.ReleaseCount != 1 || index.Summary.SignedCount != 0 || index.Summary.SBOMCount != 0 {
		t.Fatalf("unexpected generic index summary: %#v", index.Summary)
	}
	assertRawEvidenceDirs(t, outDir)
	if len(index.Images) != 1 {
		t.Fatalf("expected one image summary, got %d", len(index.Images))
	}
	summary := index.Images[0]
	if summary.ID != "java21-distroless" || summary.LatestTag != "v1.2.3" || summary.Language != "java" || summary.Tier != "distroless" {
		t.Fatalf("unexpected generic image summary: %#v", summary)
	}
	if summary.Origin == nil || summary.Origin.Kind != "imported" || summary.Origin.CreatedByClearCutt || summary.Origin.ProvenanceClaim != "none" {
		t.Fatalf("generic summary should preserve imported origin metadata: %#v", summary.Origin)
	}
	if summary.Governance == nil || !summary.Governance.Imported || summary.Governance.ClassificationConfidence != "high" {
		t.Fatalf("generic summary should preserve imported governance metadata: %#v", summary.Governance)
	}
	if summary.EvidencePolicy == nil || summary.EvidencePolicy.Provenance != "optional" {
		t.Fatalf("generic summary should preserve evidence policy metadata: %#v", summary.EvidencePolicy)
	}
	if !contains(summary.Architectures, "amd64") || !contains(summary.Architectures, "arm64") {
		t.Fatalf("expected amd64 and arm64 summary architectures, got %v", summary.Architectures)
	}
	if summary.Signed || summary.Provenance || summary.Passed {
		t.Fatalf("generic inventory should preserve unavailable evidence as false states: %#v", summary)
	}
	if summary.Evidence == nil || summary.Evidence.ArchCount != 2 || summary.Evidence.Signature || summary.Evidence.Provenance || summary.Evidence.SBOM {
		t.Fatalf("unexpected generic summary evidence: %#v", summary.Evidence)
	}
	if summary.Evidence.Statuses == nil || summary.Evidence.Statuses.Provenance.Status != catalog.EvidenceStatusMissing || summary.Evidence.Statuses.SBOM.Status != catalog.EvidenceStatusMissing {
		t.Fatalf("generic summary should emit missing evidence statuses: %#v", summary.Evidence.Statuses)
	}

	record, err := catalog.LoadImageRecord(outDir, "java21-distroless")
	if err != nil {
		t.Fatalf("expected generated image record: %v", err)
	}
	if record.SchemaVersion != catalog.ImageRecordSchemaVersion {
		t.Fatalf("expected image schemaVersion %q, got %q", catalog.ImageRecordSchemaVersion, record.SchemaVersion)
	}
	if record.Registry != "ghcr.io" || record.ImageName != "java21" || record.FullName != "ghcr.io/acme/base/java21" {
		t.Fatalf("unexpected generic image reference fields: %#v", record)
	}
	if record.Origin == nil || record.Origin.Kind != "imported" || record.Origin.CreatedByClearCutt || record.Origin.ProvenanceClaim != "none" {
		t.Fatalf("generic image record should preserve imported origin metadata: %#v", record.Origin)
	}
	if record.Governance == nil || !record.Governance.Imported {
		t.Fatalf("generic image record should preserve imported governance metadata: %#v", record.Governance)
	}
	if len(record.Releases) != 1 {
		t.Fatalf("expected one generic release, got %d", len(record.Releases))
	}
	release := record.Releases[0]
	if release.Tag != "v1.2.3" || !release.IsLatest || release.ManifestDigest != nil || release.Signature != nil || release.Provenance != nil {
		t.Fatalf("unexpected generic release fields: %#v", release)
	}
	if release.Evidence == nil || release.Evidence.ArchCount != 2 || release.Evidence.Signature || release.Evidence.Provenance || release.Evidence.SBOM {
		t.Fatalf("unexpected generic release evidence: %#v", release.Evidence)
	}
	if release.Evidence.Statuses == nil || release.Evidence.Statuses.Provenance.Status != catalog.EvidenceStatusMissing || release.Evidence.Statuses.SBOM.Status != catalog.EvidenceStatusMissing {
		t.Fatalf("generic release should emit missing evidence statuses: %#v", release.Evidence.Statuses)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(outDir, evidenceManifestFilename))
	if err != nil {
		t.Fatalf("expected generic evidence manifest: %v", err)
	}
	var manifest evidenceManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("failed to decode generic evidence manifest: %v\n%s", err, manifestRaw)
	}
	if manifest.Summary.ImageReleases != 1 || manifest.Summary.Complete != 0 || manifest.Summary.MissingEvidence != 1 {
		t.Fatalf("unexpected generic manifest summary: %#v", manifest.Summary)
	}
	if got := strings.Join(manifest.Releases[0].Missing, ","); !strings.Contains(got, "signature") || !strings.Contains(got, "sbom") {
		t.Fatalf("expected generic manifest to preserve missing evidence, got %#v", manifest.Releases[0].Missing)
	}
	if manifest.Releases[0].Channels.Provenance.Status != catalog.EvidenceStatusMissing || manifest.Releases[0].Channels.Provenance.Source != "none" {
		t.Fatalf("generic manifest should preserve missing provenance status/source: %#v", manifest.Releases[0].Channels.Provenance)
	}
	if len(release.Architectures) != 2 {
		t.Fatalf("expected two generic architectures, got %d", len(release.Architectures))
	}
	for _, arch := range release.Architectures {
		if arch.OS != "linux" || arch.SBOM.PackageCount != 0 || len(arch.SBOM.Packages) != 0 || arch.TestResults != nil || arch.Vulnerabilities != nil {
			t.Fatalf("unexpected generic architecture payload: %#v", arch)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "schemas", "catalog-index.v1.schema.json")); err != nil {
		t.Fatalf("expected generated catalog index schema: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "schemas", "evidence-manifest.v1.schema.json")); err != nil {
		t.Fatalf("expected generated evidence manifest schema: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "schemas", "evidence-manifest.v2.schema.json")); err != nil {
		t.Fatalf("expected generated status-aware evidence manifest schema: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "schemas", "image-record.v1.schema.json")); err != nil {
		t.Fatalf("expected generated image record schema: %v", err)
	}

	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.CatalogIndexSchemaVersion)
	if err != nil {
		t.Fatalf("generic catalog should satisfy index schema version: %v\n%s", err, validateOut)
	}
	validateOut, err = runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.ImageRecordSchemaVersion)
	if err != nil {
		t.Fatalf("generic catalog should satisfy image schema version: %v\n%s", err, validateOut)
	}
	validateOut, err = runCLI(t, "--catalog", outDir, "catalog", "validate", "--schema-version", catalog.EvidenceManifestSchemaVersion)
	if err != nil {
		t.Fatalf("generic catalog should satisfy evidence manifest schema version: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "missing signature evidence") || !strings.Contains(validateOut, "missing or incomplete SBOM evidence") {
		t.Fatalf("expected generic validation warnings for unavailable evidence, got:\n%s", validateOut)
	}
}

func TestCatalogValidateImportedObservedEvidenceWarnsButDoesNotFail(t *testing.T) {
	outDir := generateObservedImportedCatalog(t)

	validateOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate")
	if err != nil {
		t.Fatalf("observed imported catalog should validate with warnings: %v\n%s", err, validateOut)
	}
	for _, want := range []string{
		"0 error(s)",
		"missing provenance evidence",
		"missing or incomplete vulnerability scans",
	} {
		if !strings.Contains(validateOut, want) {
			t.Fatalf("expected validation output to contain %q, got:\n%s", want, validateOut)
		}
	}
	if strings.Contains(validateOut, "missing or incomplete SBOM evidence") {
		t.Fatalf("observed SBOM should not be reported as missing:\n%s", validateOut)
	}

	strictOut, err := runCLI(t, "--catalog", outDir, "catalog", "validate", "--warnings-as-errors")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("warnings-as-errors should fail for imported warning catalog, got err=%v\n%s", err, strictOut)
	}
}

func generateObservedImportedCatalog(t *testing.T) string {
	t.Helper()
	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte(`images:
  - id: java21-runtime
    image: ghcr.io/acme/imported/java21@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
    language:
      id: java
      displayName: Java
      version: "21"
    tier: slim
    architectures:
      - amd64
    origin:
      kind: imported
      createdByClearCutt: false
      provenanceClaim: none
    governance:
      imported: true
      classificationConfidence: high
    evidencePolicy:
      provenance: optional
`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "catalog")
	stdout, err := runCLI(t,
		"catalog", "generate",
		"--images", inventoryPath,
		"--output", outDir,
		"--owner", "acme",
		"--repo", "imported",
		"--registry-base", "ghcr.io/acme/imported",
		"--generated-at", "2026-06-04T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("catalog generate --images failed: %v\n%s", err, stdout)
	}
	updateEvidence := func(e *catalog.EvidenceSummary) {
		if e == nil {
			t.Fatal("expected evidence summary")
		}
		e.Signature = false
		e.Provenance = true
		e.SBOM = false
		e.Tests = false
		e.Vulnerabilities = false
		e.Statuses = &catalog.EvidenceStatuses{
			Signature:       catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusVerified, Source: "test"},
			Provenance:      catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "test"},
			SBOM:            catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusObserved, Source: "test", Claim: "Observed SBOM is not build provenance"},
			Tests:           catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "test"},
			Vulnerabilities: catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusMissing, Source: "test"},
		}
		catalog.NormalizeEvidenceSummary(e)
	}
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("load generated index: %v", err)
	}
	updateEvidence(index.Images[0].Evidence)
	index.Images[0].Signed = index.Images[0].Evidence.Signature
	index.Images[0].Provenance = index.Images[0].Evidence.Provenance
	index.Images[0].Passed = index.Images[0].Evidence.Tests
	if err := writeJSONFile(filepath.Join(outDir, "index.json"), index); err != nil {
		t.Fatalf("write updated index: %v", err)
	}
	record, err := catalog.LoadImageRecord(outDir, "java21-runtime")
	if err != nil {
		t.Fatalf("load generated record: %v", err)
	}
	updateEvidence(record.Releases[0].Evidence)
	if err := writeJSONFile(filepath.Join(outDir, "images", "java21-runtime.json"), record); err != nil {
		t.Fatalf("write updated record: %v", err)
	}
	if err := writeEvidenceManifestFile(outDir); err != nil {
		t.Fatalf("write evidence manifest: %v", err)
	}
	return outDir
}

func TestCatalogGenerateFromGenericOCIImagesRejectsUnsupportedArchitecture(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(inventoryPath, []byte(`images:
  - id: node-dev
    image: registry.example.com/platform/node-dev:v1
    language:
      id: node
      displayName: Node.js
      version: "22"
    tier: dev
    architectures:
      - s390x
`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "catalog")

	stdout, err := runCLI(t,
		"catalog", "generate",
		"--images", inventoryPath,
		"--output", outDir,
		"--generated-at", "2026-06-04T12:00:00Z",
	)
	if err == nil || !strings.Contains(err.Error(), `unsupported architecture "s390x"`) {
		t.Fatalf("expected unsupported architecture error, got err=%v\n%s", err, stdout)
	}
}

func copyFixtureCatalog(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "catalog")
	if err := copyCatalogTree(fixtureCatalog(), dst); err != nil {
		t.Fatal(err)
	}
	return dst
}

func assertRawEvidenceDirs(t *testing.T, catalogPath string) {
	t.Helper()
	for _, rel := range []string{
		filepath.Join("raw", "sbom"),
		filepath.Join("raw", "provenance"),
		filepath.Join("raw", "scans"),
		filepath.Join("raw", "test-results"),
	} {
		info, err := os.Stat(filepath.Join(catalogPath, rel))
		if err != nil {
			t.Fatalf("expected generated raw evidence directory %s: %v", rel, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected generated raw evidence path %s to be a directory", rel)
		}
	}
}

func writeMinimalSiteTemplate(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "template")
	if err := os.MkdirAll(filepath.Join(dir, "src", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"build":"astro build"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "astro.config.mjs"), []byte("export default {};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "lib", "catalog.ts"), []byte("export {};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGeneratorIdentityFromBuildInfo(t *testing.T) {
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "abc123def456"},
		{Key: "vcs.modified", Value: "false"},
	}}
	version, commit := generatorIdentityFromBuildInfo("", info)
	if version != "dev" || commit != "abc123def456" {
		t.Fatalf("expected dev/abc123def456, got %q/%q", version, commit)
	}

	info.Settings[1].Value = "true"
	version, commit = generatorIdentityFromBuildInfo("v1.2.3", info)
	if version != "v1.2.3" || commit != "abc123def456-dirty" {
		t.Fatalf("expected v1.2.3/abc123def456-dirty, got %q/%q", version, commit)
	}

	version, commit = generatorIdentityFromBuildInfo("", nil)
	if version != "dev" || commit != "unknown" {
		t.Fatalf("expected dev/unknown without build info, got %q/%q", version, commit)
	}
}

func TestGeneratedIndexGeneratorCommitFromVCS(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("build info unavailable")
	}
	revision := ""
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			revision = setting.Value
		}
	}
	if revision == "" {
		t.Skip("build info carries no vcs.revision (test binaries are not VCS-stamped)")
	}
	outDir := t.TempDir()
	writeTestFile(t, filepath.Join(outDir, "index.json"), []byte(`{"generatedAt":"2026-06-05T20:00:00Z","owner":"acme","repo":"images","repoUrl":"https://github.com/acme/images","registryBase":"ghcr.io/acme","latestTag":"v1.0.0","releases":[],"languages":[],"tiers":[],"images":[]}`))
	if err := stampCatalogIndexMetadata(outDir); err != nil {
		t.Fatalf("stampCatalogIndexMetadata: %v", err)
	}
	index, err := catalog.LoadCatalogIndex(outDir)
	if err != nil {
		t.Fatalf("LoadCatalogIndex: %v", err)
	}
	if index.Generator == nil || index.Generator.Commit == "unknown" || index.Generator.Commit == "" {
		t.Fatalf("expected real generator commit from VCS build info, got %#v", index.Generator)
	}
	if !strings.HasPrefix(index.Generator.Commit, revision) {
		t.Fatalf("expected generator commit %q to start with vcs.revision %q", index.Generator.Commit, revision)
	}
}
