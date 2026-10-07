package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/northcutted/clearcutt-verify/internal/sitetemplate"
	"github.com/northcutted/clearcutt-verify/internal/sitetemplate/rules"
	"github.com/spf13/cobra"
)

type catalogSiteFlags struct {
	catalogPath  string
	config       string
	imagesFile   string
	owner        string
	repo         string
	registryBase string
	generatedAt  string
	output       string
	template     string
	siteConfig   string
	overrides    string
	force        bool
	install      bool
	clean        bool
	basePath     string
	siteURL      string
	generateVEX  bool
	vexDir       string
	graphFile    string
	layersFile   string
	workDir      string
	host         string
	port         int
}

var catalogSiteOpts catalogSiteFlags

func newCatalogSiteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "site",
		Short: "Scaffold an Astro evidence portal from catalog data",
	}
	cmd.AddCommand(newCatalogSiteScaffoldCmd())
	cmd.AddCommand(newCatalogSiteBuildCmd())
	cmd.AddCommand(newCatalogSitePreviewCmd())
	cmd.AddCommand(newCatalogSiteEjectCmd())
	return cmd
}

func newCatalogSiteScaffoldCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scaffold",
		Short: "Create a standalone Astro catalog site",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogSiteScaffold()
		},
	}
	cmd.Flags().StringVar(&catalogSiteOpts.catalogPath, "catalog", "", "Generated catalog directory to copy into the site")
	cmd.Flags().StringVar(&catalogSiteOpts.output, "output", "", "Output directory for the scaffolded Astro project")
	cmd.Flags().StringVar(&catalogSiteOpts.template, "template", "", "Astro template directory (defaults to templates/astro-catalog or site)")
	cmd.Flags().StringVar(&catalogSiteOpts.siteConfig, "site-config", "", "Optional clearcutt.site.yaml to copy into the scaffold")
	cmd.Flags().StringVar(&catalogSiteOpts.overrides, "overrides", "", "Optional site-overrides directory with components/, pages/, styles/, or public/")
	cmd.Flags().BoolVar(&catalogSiteOpts.force, "force", false, "Overwrite the output directory if it already exists")
	cmd.MarkFlagRequired("output")
	return cmd
}

func newCatalogSiteBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build a static Astro evidence portal from catalog data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogSiteBuild(cmd)
		},
	}
	cmd.Flags().StringVar(&catalogSiteOpts.catalogPath, "catalog", "", "Generated catalog directory to copy into the site")
	cmd.Flags().StringVar(&catalogSiteOpts.config, "config", "", "ClearCutt fleet config to generate catalog data before building")
	cmd.Flags().StringVar(&catalogSiteOpts.imagesFile, "images", "", "Generic OCI images.yaml inventory to generate catalog data before building")
	cmd.Flags().StringVar(&catalogSiteOpts.owner, "owner", "", "Catalog source owner for --images one-shot builds")
	cmd.Flags().StringVar(&catalogSiteOpts.repo, "repo", "", "Catalog source repository for --images one-shot builds")
	cmd.Flags().StringVar(&catalogSiteOpts.registryBase, "registry-base", "", "Catalog registry base for --images one-shot builds")
	cmd.Flags().StringVar(&catalogSiteOpts.generatedAt, "generated-at", "", "Override generatedAt timestamp for generated catalog data")
	cmd.Flags().StringVar(&catalogSiteOpts.output, "output", "", "Static site output directory")
	cmd.Flags().StringVar(&catalogSiteOpts.template, "template", "", "Astro template directory (defaults to templates/astro-catalog or site)")
	cmd.Flags().StringVar(&catalogSiteOpts.graphFile, "graph", "", "Optional `clearcutt-verify graph build` JSON to publish as the estate view")
	cmd.Flags().StringVar(&catalogSiteOpts.layersFile, "layers", "", "Optional `clearcutt-verify graph layers` JSON to publish as the layer commonality view")
	cmd.Flags().StringVar(&catalogSiteOpts.siteConfig, "site-config", "", "Optional clearcutt.site.yaml to copy into the build workspace")
	cmd.Flags().StringVar(&catalogSiteOpts.overrides, "overrides", "", "Optional site-overrides directory with components/, pages/, styles/, or public/")
	cmd.Flags().BoolVar(&catalogSiteOpts.install, "install", false, "Install generated site dependencies with the detected package manager before building")
	cmd.Flags().BoolVar(&catalogSiteOpts.clean, "clean", false, "Remove the output directory before writing static site files")
	cmd.Flags().StringVar(&catalogSiteOpts.basePath, "base-path", "", "Astro base path to pass as BASE_PATH during the build")
	cmd.Flags().StringVar(&catalogSiteOpts.siteURL, "site-url", "", "Astro site URL to pass as SITE_URL during the build")
	cmd.Flags().BoolVar(&catalogSiteOpts.generateVEX, "generate-vex", false, "Generate public OpenVEX documents for every catalog image before building")
	cmd.Flags().StringVar(&catalogSiteOpts.vexDir, "vex-dir", filepath.Join("public", "vex"), "Build-workspace directory for --generate-vex output")
	cmd.Flags().StringVar(&catalogSiteOpts.workDir, "work-dir", "", "Reusable build workspace; defaults to a temporary directory")
	cmd.MarkFlagRequired("output")
	return cmd
}

func newCatalogSitePreviewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Run a local Astro preview server for catalog data",
		Long: `Scaffold a temporary Astro catalog site and run the detected package manager's dev script. If
dependencies are not installed and --install is not set, the command prints
next steps instead of failing so preview remains optional for catalog data
generation workflows.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogSitePreview()
		},
	}
	cmd.Flags().StringVar(&catalogSiteOpts.catalogPath, "catalog", "", "Generated catalog directory to copy into the site")
	cmd.Flags().StringVar(&catalogSiteOpts.template, "template", "", "Astro template directory (defaults to templates/astro-catalog or site)")
	cmd.Flags().StringVar(&catalogSiteOpts.siteConfig, "site-config", "", "Optional clearcutt.site.yaml to copy into the preview workspace")
	cmd.Flags().StringVar(&catalogSiteOpts.overrides, "overrides", "", "Optional site-overrides directory with components/, pages/, styles/, or public/")
	cmd.Flags().StringVar(&catalogSiteOpts.graphFile, "graph", "", "Optional `clearcutt-verify graph build` JSON to publish as the estate view")
	cmd.Flags().StringVar(&catalogSiteOpts.layersFile, "layers", "", "Optional `clearcutt-verify graph layers` JSON to publish as the layer commonality view")
	cmd.Flags().BoolVar(&catalogSiteOpts.install, "install", false, "Install generated site dependencies with the detected package manager before previewing")
	cmd.Flags().StringVar(&catalogSiteOpts.basePath, "base-path", "", "Astro base path to pass as BASE_PATH during preview")
	cmd.Flags().StringVar(&catalogSiteOpts.workDir, "work-dir", "", "Reusable preview workspace; defaults to a temporary directory")
	cmd.Flags().StringVar(&catalogSiteOpts.host, "host", "127.0.0.1", "Preview server host")
	cmd.Flags().IntVar(&catalogSiteOpts.port, "port", 4321, "Preview server port")
	return cmd
}

func newCatalogSiteEjectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eject",
		Short: "Export the Astro catalog site template for customization",
		Long: `Copy the Astro catalog site template into an editable project without
copying any generated catalog data. Use this when you want to vendor and customize
the renderer separately from a specific catalog artifact.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogSiteEject()
		},
	}
	cmd.Flags().StringVar(&catalogSiteOpts.output, "output", "", "Output directory for the ejected Astro template")
	cmd.Flags().StringVar(&catalogSiteOpts.template, "template", "", "Astro template directory (defaults to templates/astro-catalog or site)")
	cmd.Flags().StringVar(&catalogSiteOpts.siteConfig, "site-config", "", "Optional clearcutt.site.yaml to copy into the ejected template")
	cmd.Flags().StringVar(&catalogSiteOpts.overrides, "overrides", "", "Optional site-overrides directory with components/, pages/, styles/, or public/")
	cmd.Flags().BoolVar(&catalogSiteOpts.force, "force", false, "Overwrite the output directory if it already exists")
	cmd.MarkFlagRequired("output")
	return cmd
}

func runCatalogSiteScaffold() error {
	catalogPath := catalogSiteOpts.catalogPath
	if catalogPath == "" {
		catalogPath = GlobalOpts.CatalogPath
	}
	outputDir := catalogSiteOpts.output
	if outputDir == "" {
		return fmt.Errorf("--output is required")
	}
	if _, err := materializeCatalogSite(catalogPath, outputDir, catalogSiteOpts.force); err != nil {
		return err
	}
	fmt.Fprintf(out, "Created catalog site at %s\n\n", outputDir)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintf(out, "  cd %s\n", outputDir)
	fmt.Fprintln(out, "  npm install  # or the package manager matching your lockfile")
	fmt.Fprintln(out, "  npm run dev")
	return nil
}

func runCatalogSiteEject() error {
	if catalogSiteOpts.output == "" {
		return fmt.Errorf("--output is required")
	}
	if _, err := materializeCatalogSiteTemplate(catalogSiteOpts.output, catalogSiteOpts.force); err != nil {
		return err
	}
	fmt.Fprintf(out, "Ejected catalog site template at %s\n\n", catalogSiteOpts.output)
	fmt.Fprintln(out, "Next:")
	fmt.Fprintf(out, "  cd %s\n", catalogSiteOpts.output)
	fmt.Fprintln(out, "  npm install  # or the package manager matching your lockfile")
	fmt.Fprintln(out, "  npm run dev")
	fmt.Fprintln(out, "  # add catalog data under public/catalog before building")
	return nil
}

func runCatalogSiteBuild(cmd *cobra.Command) error {
	if cmd != nil && cmd.Flags().Changed("config") && cmd.Flags().Changed("images") {
		return fmt.Errorf("--config and --images are mutually exclusive")
	}
	catalogPath, cleanupCatalog, err := resolveCatalogSiteInput(cmd)
	if err != nil {
		return err
	}
	defer cleanupCatalog()

	if catalogSiteOpts.output == "" {
		return fmt.Errorf("--output is required")
	}

	workDir := catalogSiteOpts.workDir
	removeWorkDir := false
	if workDir == "" {
		temp, err := os.MkdirTemp("", "clearcutt-catalog-site-*")
		if err != nil {
			return err
		}
		workDir = temp
		removeWorkDir = true
	}
	if removeWorkDir {
		defer os.RemoveAll(workDir)
	}

	templatePath, err := materializeCatalogSite(catalogPath, workDir, true)
	if err != nil {
		return err
	}
	if catalogSiteOpts.generateVEX {
		vexDir := catalogSiteOpts.vexDir
		if !filepath.IsAbs(vexDir) {
			vexDir = filepath.Join(workDir, vexDir)
		}
		result, err := generateOpenVEXForCatalog(catalogPath, vexDir, "", "")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "[site-build] generated %d OpenVEX document(s) in %s\n", result.Count, result.OutputDir)
	}
	pm := detectPackageManager(workDir)
	if err := ensureNodeDependencies(workDir, templatePath, catalogSiteOpts.install, pm); err != nil {
		return err
	}
	env := os.Environ()
	if catalogSiteOpts.basePath != "" {
		env = append(env, "BASE_PATH="+catalogSiteOpts.basePath)
	}
	if catalogSiteOpts.siteURL != "" {
		env = append(env, "SITE_URL="+catalogSiteOpts.siteURL)
	}
	if err := runPackageManager(pm, workDir, env, pm.runArgs("build")...); err != nil {
		return err
	}

	if err := prepareBuildOutput(catalogSiteOpts.output, catalogSiteOpts.clean); err != nil {
		return err
	}
	if err := copyCatalogTree(filepath.Join(workDir, "dist"), catalogSiteOpts.output); err != nil {
		return err
	}
	if err := ensureRawEvidenceDirs(filepath.Join(catalogSiteOpts.output, "catalog")); err != nil {
		return err
	}
	fmt.Fprintf(out, "Built catalog site at %s\n", catalogSiteOpts.output)
	return nil
}

func resolveCatalogSiteInput(cmd *cobra.Command) (string, func(), error) {
	if cmd != nil && cmd.Flags().Changed("config") {
		return generateCatalogForSiteBuild()
	}
	if cmd != nil && cmd.Flags().Changed("images") {
		return generateImagesCatalogForSiteBuild()
	}
	catalogPath := catalogSiteOpts.catalogPath
	if catalogPath == "" {
		catalogPath = GlobalOpts.CatalogPath
	}
	return catalogPath, func() {}, nil
}

func generateCatalogForSiteBuild() (string, func(), error) {
	catalogPath := catalogSiteOpts.catalogPath
	cleanup := func() {}
	if catalogPath == "" {
		temp, err := os.MkdirTemp("", "clearcutt-catalog-data-*")
		if err != nil {
			return "", nil, err
		}
		catalogPath = temp
		cleanup = func() { _ = os.RemoveAll(temp) }
	}

	oldGatherOpts := catalogGatherOpts
	oldCatalogPath := GlobalOpts.CatalogPath
	defer func() {
		catalogGatherOpts = oldGatherOpts
		GlobalOpts.CatalogPath = oldCatalogPath
	}()

	catalogGatherOpts.config = catalogSiteOpts.config
	catalogGatherOpts.outDir = catalogPath
	GlobalOpts.CatalogPath = catalogPath
	if err := runCatalogGenerateWithConfig(true, false); err != nil {
		cleanup()
		return "", nil, err
	}
	fmt.Fprintf(out, "[site-build] generated catalog data from %s\n", catalogSiteOpts.config)
	return catalogPath, cleanup, nil
}

func generateImagesCatalogForSiteBuild() (string, func(), error) {
	catalogPath := catalogSiteOpts.catalogPath
	cleanup := func() {}
	if catalogPath == "" {
		temp, err := os.MkdirTemp("", "clearcutt-catalog-data-*")
		if err != nil {
			return "", nil, err
		}
		catalogPath = temp
		cleanup = func() { _ = os.RemoveAll(temp) }
	}

	oldGatherOpts := catalogGatherOpts
	oldCatalogPath := GlobalOpts.CatalogPath
	defer func() {
		catalogGatherOpts = oldGatherOpts
		GlobalOpts.CatalogPath = oldCatalogPath
	}()

	catalogGatherOpts.imagesFile = catalogSiteOpts.imagesFile
	catalogGatherOpts.outDir = catalogPath
	catalogGatherOpts.owner = catalogSiteOpts.owner
	catalogGatherOpts.repo = catalogSiteOpts.repo
	catalogGatherOpts.registryBase = catalogSiteOpts.registryBase
	catalogGatherOpts.generatedAt = catalogSiteOpts.generatedAt
	catalogGatherOpts.pretty = true
	GlobalOpts.CatalogPath = catalogPath
	if err := runCatalogGenerateWithConfig(false, false); err != nil {
		cleanup()
		return "", nil, err
	}
	fmt.Fprintf(out, "[site-build] generated catalog data from %s\n", catalogSiteOpts.imagesFile)
	return catalogPath, cleanup, nil
}

func runCatalogSitePreview() error {
	catalogPath := catalogSiteOpts.catalogPath
	if catalogPath == "" {
		catalogPath = GlobalOpts.CatalogPath
	}

	workDir := catalogSiteOpts.workDir
	removeWorkDir := false
	if workDir == "" {
		temp, err := os.MkdirTemp("", "clearcutt-catalog-site-*")
		if err != nil {
			return err
		}
		workDir = temp
		removeWorkDir = true
	}
	if removeWorkDir {
		defer os.RemoveAll(workDir)
	}

	templatePath, err := materializeCatalogSite(catalogPath, workDir, true)
	if err != nil {
		return err
	}
	pm := detectPackageManager(workDir)
	if err := ensureNodeDependencies(workDir, templatePath, catalogSiteOpts.install, pm); err != nil {
		if catalogSiteOpts.install {
			return err
		}
		printPreviewFallback(workDir, catalogPath, err)
		return nil
	}
	if _, err := exec.LookPath(pm.binary); err != nil {
		pmErr := packageManagerNotFoundError(pm)
		if catalogSiteOpts.install {
			return pmErr
		}
		printPreviewFallback(workDir, catalogPath, pmErr)
		return nil
	}

	env := os.Environ()
	if catalogSiteOpts.basePath != "" {
		env = append(env, "BASE_PATH="+catalogSiteOpts.basePath)
	}
	fmt.Fprintf(out, "Starting catalog site preview at http://%s:%d\n", catalogSiteOpts.host, catalogSiteOpts.port)
	return runPackageManager(pm, workDir, env, pm.runArgs("dev", "--", "--host", catalogSiteOpts.host, "--port", fmt.Sprintf("%d", catalogSiteOpts.port))...)
}

func materializeCatalogSite(catalogPath, outputDir string, force bool) (string, error) {
	if _, err := catalog.LoadCatalogIndex(catalogPath); err != nil {
		return "", err
	}
	templatePath, err := materializeCatalogSiteTemplate(outputDir, force)
	if err != nil {
		return "", err
	}
	if err := copyCatalogTree(catalogPath, filepath.Join(outputDir, "public", "catalog")); err != nil {
		return "", err
	}
	if err := ensureRawEvidenceDirs(filepath.Join(outputDir, "public", "catalog")); err != nil {
		return "", err
	}
	if err := stageEstateArtifacts(filepath.Join(outputDir, "public", "estate")); err != nil {
		return "", err
	}
	return templatePath, nil
}

// stageEstateArtifacts copies the optional `graph build` / `graph layers` output
// next to the catalog data, where site/src/lib/estate.ts resolves it. Both are
// optional by design: a site with no estate scan renders an empty state naming
// the commands that populate it, which is the common case for a fresh scaffold.
func stageEstateArtifacts(dst string) error {
	sources := map[string]string{
		"graph.json":  strings.TrimSpace(catalogSiteOpts.graphFile),
		"layers.json": strings.TrimSpace(catalogSiteOpts.layersFile),
	}
	staged := false
	for name, src := range sources {
		if src == "" {
			continue
		}
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("estate artifact %s: %w", src, err)
		}
		if !staged {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			staged = true
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, name), data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "[site] staged estate artifact %s\n", name)
	}
	return nil
}

func materializeCatalogSiteTemplate(outputDir string, force bool) (string, error) {
	templatePath, err := resolveCatalogSiteTemplate(catalogSiteOpts.template)
	if err != nil {
		return "", err
	}
	if err := prepareScaffoldOutput(outputDir, force); err != nil {
		return "", err
	}
	if templatePath == "" {
		// No on-disk template found: materialize the template embedded in the
		// binary so scaffold/build/eject work outside the ClearCutt repo.
		if err := sitetemplate.Materialize(outputDir); err != nil {
			return "", err
		}
	} else if err := copyTemplateTree(templatePath, outputDir); err != nil {
		return "", err
	}
	if err := writeSiteConfig(outputDir, catalogSiteOpts.siteConfig); err != nil {
		return "", err
	}
	if err := writeSiteReadme(outputDir); err != nil {
		return "", err
	}
	if err := applySiteOverrides(outputDir, catalogSiteOpts.overrides); err != nil {
		return "", err
	}
	return templatePath, nil
}

// resolveCatalogSiteTemplate locates an on-disk Astro template to copy. An
// explicit --template must exist or it is an error. Otherwise it prefers the
// live site/ directory when running inside the repo (which also lets the build
// reuse its node_modules), and returns "" to signal that the caller should fall
// back to the template embedded in the binary.
func resolveCatalogSiteTemplate(flag string) (string, error) {
	if flag != "" {
		info, err := os.Stat(flag)
		if err == nil && info.IsDir() {
			if !isCatalogSiteTemplateDir(flag) {
				return "", fmt.Errorf("site template directory is missing package.json or src/: %s", flag)
			}
			return flag, nil
		}
		return "", fmt.Errorf("site template directory not found: %s", flag)
	}
	for _, candidate := range []string{
		"site",
		filepath.Join("..", "site"),
		filepath.Join("..", "..", "site"),
		filepath.Join("..", "..", "..", "site"),
	} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() && isCatalogSiteTemplateDir(candidate) {
			return candidate, nil
		}
	}
	return "", nil
}

func isCatalogSiteTemplateDir(path string) bool {
	if !fileExists(filepath.Join(path, "package.json")) {
		return false
	}
	if info, err := os.Stat(filepath.Join(path, "src")); err != nil || !info.IsDir() {
		return false
	}
	return true
}

func prepareScaffoldOutput(outputDir string, force bool) error {
	info, err := os.Stat(outputDir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("output path exists and is not a directory: %s", outputDir)
		}
		entries, err := os.ReadDir(outputDir)
		if err != nil {
			return err
		}
		if len(entries) > 0 && !force {
			return fmt.Errorf("output directory %s is not empty; pass --force to replace it", outputDir)
		}
		if force {
			if err := os.RemoveAll(outputDir); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(outputDir, 0o755)
}

func prepareBuildOutput(outputDir string, clean bool) error {
	info, err := os.Stat(outputDir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("output path exists and is not a directory: %s", outputDir)
		}
		entries, err := os.ReadDir(outputDir)
		if err != nil {
			return err
		}
		if len(entries) > 0 && !clean {
			return fmt.Errorf("output directory %s is not empty; pass --clean to replace it", outputDir)
		}
		if clean {
			if err := os.RemoveAll(outputDir); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(outputDir, 0o755)
}

type sitePackageManager struct {
	name          string
	binary        string
	detectedFrom  string
	installArgs   []string
	installAction string
}

func (pm sitePackageManager) runArgs(script string, args ...string) []string {
	out := []string{"run", script}
	return append(out, args...)
}

func detectPackageManager(workDir string) sitePackageManager {
	switch {
	case fileExists(filepath.Join(workDir, "pnpm-lock.yaml")):
		return sitePackageManager{
			name:          "pnpm",
			binary:        "pnpm",
			detectedFrom:  "pnpm-lock.yaml",
			installArgs:   []string{"install", "--frozen-lockfile"},
			installAction: "pnpm install --frozen-lockfile",
		}
	case fileExists(filepath.Join(workDir, "package-lock.json")):
		return sitePackageManager{
			name:          "npm",
			binary:        "npm",
			detectedFrom:  "package-lock.json",
			installArgs:   []string{"ci"},
			installAction: "npm ci",
		}
	case fileExists(filepath.Join(workDir, "yarn.lock")):
		return sitePackageManager{
			name:          "yarn",
			binary:        "yarn",
			detectedFrom:  "yarn.lock",
			installArgs:   []string{"install", "--frozen-lockfile"},
			installAction: "yarn install --frozen-lockfile",
		}
	case fileExists(filepath.Join(workDir, "bun.lockb")):
		return sitePackageManager{
			name:          "bun",
			binary:        "bun",
			detectedFrom:  "bun.lockb",
			installArgs:   []string{"install", "--frozen-lockfile"},
			installAction: "bun install --frozen-lockfile",
		}
	default:
		return sitePackageManager{
			name:          "npm",
			binary:        "npm",
			detectedFrom:  "no lockfile",
			installArgs:   []string{"install"},
			installAction: "npm install",
		}
	}
}

func ensureNodeDependencies(workDir, templatePath string, install bool, pm sitePackageManager) error {
	if fileExists(filepath.Join(workDir, "node_modules")) {
		return nil
	}
	if install {
		return runPackageManager(pm, workDir, os.Environ(), pm.installArgs...)
	}
	if templatePath != "" {
		templateNodeModules := filepath.Join(templatePath, "node_modules")
		if fileExists(templateNodeModules) {
			absNodeModules, err := filepath.Abs(templateNodeModules)
			if err != nil {
				return err
			}
			return os.Symlink(absNodeModules, filepath.Join(workDir, "node_modules"))
		}
	}
	return fmt.Errorf("site dependencies are not installed; pass --install to run %s (detected %s from %s)", pm.installAction, pm.name, pm.detectedFrom)
}

func printPreviewFallback(workDir, catalogPath string, cause error) {
	fmt.Fprintf(out, "Catalog preview was not started: %v\n\n", cause)
	fmt.Fprintln(out, "Next:")
	if catalogSiteOpts.workDir == "" {
		fmt.Fprintf(out, "  clearcutt-verify catalog site preview --catalog %s --install\n", catalogPath)
		fmt.Fprintln(out, "  # or scaffold a persistent project:")
		fmt.Fprintf(out, "  clearcutt-verify catalog site scaffold --catalog %s --output ./clearcutt-catalog-site\n", catalogPath)
		return
	}
	fmt.Fprintf(out, "  cd %s\n", workDir)
	pm := detectPackageManager(workDir)
	fmt.Fprintf(out, "  %s\n", pm.installAction)
	fmt.Fprintf(out, "  %s run dev -- --host %s --port %d\n", pm.name, catalogSiteOpts.host, catalogSiteOpts.port)
}

func runPackageManager(pm sitePackageManager, workDir string, env []string, args ...string) error {
	bin, err := exec.LookPath(pm.binary)
	if err != nil {
		return packageManagerNotFoundError(pm)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = workDir
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed in %s: %w", pm.name, strings.Join(args, " "), workDir, err)
	}
	return nil
}

func packageManagerNotFoundError(pm sitePackageManager) error {
	return fmt.Errorf("%s was not found on PATH (detected %s from %s)", pm.binary, pm.name, pm.detectedFrom)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyTemplateTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if shouldSkipTemplatePath(rel, entry) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return copyFile(path, target, info.Mode())
	})
}

// shouldSkipTemplatePath shares the exclusion rules with the embedded template
// generator (see internal/sitetemplate/rules), so copying the live site/ from
// disk and materializing the embedded template produce an identical tree.
func shouldSkipTemplatePath(rel string, _ fs.DirEntry) bool {
	return rules.IsExcluded(rel)
}

func copyCatalogTree(src, dst string) error {
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return copyFile(path, target, info.Mode())
	})
}

func writeSiteConfig(outputDir, source string) error {
	target := filepath.Join(outputDir, "clearcutt.site.yaml")
	if source != "" {
		info, err := os.Stat(source)
		if err != nil {
			return err
		}
		return copyFile(source, target, info.Mode())
	}
	if _, err := os.Stat(target); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(target, []byte(deriveSiteConfigYAML()), 0o644)
}

// deriveSiteConfigYAML builds a fork-branded clearcutt.site.yaml from the same
// inputs the rest of the pipeline uses: the fleet config when building from one,
// otherwise the identity recorded in the generated catalog index. The produced
// site therefore carries the fork's identity with no hardcoded upstream brand.
func deriveSiteConfigYAML() string {
	var title, description, sourceRepo, registry string
	if catalogSiteOpts.config != "" {
		if cfg, err := config.Load(catalogSiteOpts.config); err == nil {
			title = cfg.Branding.ProductName + " Catalog"
			description = cfg.Site.Description
			sourceRepo = cfg.RepoURL()
			registry = "https://" + cfg.RegistryBase()
		}
	}
	if title == "" {
		if repo, repoURL, registryBase, ok := catalogIndexIdentity(catalogSiteOpts.catalogPath); ok {
			title = config.DeriveProductName(repo) + " Catalog"
			sourceRepo = repoURL
			if registryBase != "" {
				registry = "https://" + registryBase
			}
		}
	}
	if title == "" {
		title = "Container Image Estate"
	}
	if description == "" {
		description = "Static evidence portal generated from signed base-image catalog data"
	}
	return renderSiteConfigYAML(title, description, sourceRepo, registry)
}

// catalogIndexIdentity reads repo/repoUrl/registryBase from a catalog index.json
// so the site can self-brand when scaffolding from catalog data alone, with no
// fleet config available.
func catalogIndexIdentity(catalogPath string) (repo, repoURL, registryBase string, ok bool) {
	if catalogPath == "" {
		return "", "", "", false
	}
	raw, err := os.ReadFile(filepath.Join(catalogPath, "index.json"))
	if err != nil {
		return "", "", "", false
	}
	var idx struct {
		Repo         string `json:"repo"`
		RepoURL      string `json:"repoUrl"`
		RegistryBase string `json:"registryBase"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		return "", "", "", false
	}
	return idx.Repo, idx.RepoURL, idx.RegistryBase, idx.Repo != ""
}

func renderSiteConfigYAML(title, description, sourceRepo, registry string) string {
	return fmt.Sprintf(`site:
  title: %q
  description: %q
  logo: ""

  theme:
    mode: "dark"
    accent: "#7c3aed"

  navigation:
    showHome: true
    showGettingStarted: true
    showOperatorDocs: true
    showCliDocs: true
    showAuditGuide: true

  features:
    sbomTable: true
    vulnerabilityTable: true
    layerExplorer: true
    provenance: true
    ociLabels: true
    versionHistory: true
    kyvernoPolicies: false

  terminology:
    distroless: "Distroless"
    slim: "Slim"
    dev: "Dev"

  links:
    sourceRepo: %q
    registry: %q
    support: ""
    docs: ""

  home:
    title: %q
    description: "Use this catalog to containerize applications with approved runtime images, inspect evidence, and find the next step for your role."
    showNotice: true
    noticeTitle: "Before you use this catalog"
    noticeBody: "The catalog is a static view of generated image metadata and evidence. Treat missing signatures, provenance, SBOMs, or scans as explicit gaps instead of inferring trust from another channel."
    quickLinks:
      - label: "Containerize your app"
        href: "getting-started"
        description: "Copy a multi-stage container example and local validation commands."
      - label: "Browse images"
        href: "catalog"
        description: "Filter runtimes, tiers, services, release status, and CVE gates."
      - label: "Audit evidence"
        href: "about?tab=audit"
        description: "Verify signatures, provenance, SBOMs, and workflow identity."
      - label: "Know limits"
        href: "limitations"
        description: "Review what the catalog proves and what your team still owns."
    personas:
      - id: "platform"
        label: "Platform engineers"
        summary: "Publish, govern, and maintain the approved image fleet."
        steps:
          - title: "Check catalog coverage"
            description: "Confirm latest images, pending matrix slots, services, and evidence counts."
            href: "catalog"
            ctaLabel: "Open matrix"
          - title: "Fork and configure the fleet"
            description: "Review the platform kit commands, fleet config contract, and generated site workflow."
            href: "platform-kit"
            ctaLabel: "Open platform kit"
          - title: "Publish refreshed catalog data"
            description: "Generate catalog data and build the static site artifact for your own registry."
            command: "clearcutt-verify catalog site build --catalog ./dist/catalog --output ./dist/site --install"
      - id: "application"
        label: "Application engineers"
        summary: "Pick a runtime image, build an app container, and validate it before release."
        steps:
          - title: "Choose a runtime and tier"
            description: "Use the catalog matrix to find the right language version and production tier."
            href: "catalog"
            ctaLabel: "Choose an image"
          - title: "Copy the build pattern"
            description: "Start with a dev-to-runtime multi-stage example that does not require Nix locally."
            href: "getting-started"
            ctaLabel: "Copy app pattern"
          - title: "Plan rebase and certification"
            description: "Use app lifecycle examples for app build, diff-base, certify, and rebase workflows."
            href: "app-lifecycle"
            ctaLabel: "Open lifecycle"
      - id: "audit"
        label: "Security and audit engineers"
        summary: "Review evidence channels, vulnerability state, and threat-model boundaries."
        steps:
          - title: "Verify supply-chain evidence"
            description: "Run the audit guide checks for keyless signatures, SLSA provenance, and SBOMs."
            href: "about?tab=audit"
            ctaLabel: "Verify evidence"
          - title: "Inspect vulnerabilities"
            description: "Use image detail pages to review active findings, fix state, OpenVEX notes, and exceptions."
            href: "catalog"
            ctaLabel: "Inspect findings"
          - title: "Read the boundaries"
            description: "Confirm what shell-free, provenance, and remediation claims do and do not prove."
            href: "limitations"
            ctaLabel: "Read limits"
`, title, description, sourceRepo, registry, title)
}

func writeSiteReadme(outputDir string) error {
	target := filepath.Join(outputDir, "README.md")
	if _, err := os.Stat(target); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(target, []byte(defaultCatalogSiteReadme), 0o644)
}

func applySiteOverrides(outputDir, source string) error {
	if source == "" {
		return nil
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("site overrides path is not a directory: %s", source)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	applied := 0
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !entry.IsDir() {
			return fmt.Errorf("unsupported site override %q: expected one of components/, pages/, styles/, or public/", name)
		}
		targetRoot, ok := siteOverrideTargetRoot(outputDir, name)
		if !ok {
			return fmt.Errorf("unsupported site override directory %q: expected one of components/, pages/, styles/, or public/", name)
		}
		if err := copyOverrideTree(name, filepath.Join(source, name), targetRoot); err != nil {
			return err
		}
		applied++
	}
	if applied > 0 {
		fmt.Fprintf(out, "[site] applied overrides from %s\n", source)
	}
	return nil
}

func siteOverrideTargetRoot(outputDir, name string) (string, bool) {
	switch name {
	case "components":
		return filepath.Join(outputDir, "src", "components"), true
	case "pages":
		return filepath.Join(outputDir, "src", "pages"), true
	case "styles":
		return filepath.Join(outputDir, "src", "styles"), true
	case "public":
		return filepath.Join(outputDir, "public"), true
	default:
		return "", false
	}
}

func copyOverrideTree(rootName, src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}
		if shouldSkipOverridePath(rel, entry) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if rootName == "pages" {
			if err := removeConflictingPageOverride(target); err != nil {
				return err
			}
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if rootName == "pages" {
			return copyPageOverrideFile(path, target, info.Mode(), dst)
		}
		return copyFile(path, target, info.Mode())
	})
}

func copyPageOverrideFile(src, dst string, mode fs.FileMode, pagesRoot string) error {
	ext := filepath.Ext(dst)
	if ext != ".md" && ext != ".mdx" {
		return copyFile(src, dst, mode)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	layoutPath, err := filepath.Rel(filepath.Dir(dst), filepath.Join(filepath.Dir(pagesRoot), "layouts", "Base.astro"))
	if err != nil {
		return err
	}
	data := ensureMarkdownLayout(raw, filepath.ToSlash(layoutPath))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode.Perm())
}

func ensureMarkdownLayout(raw []byte, layoutPath string) []byte {
	text := string(raw)
	lines := strings.SplitAfter(text, "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == "---" {
		for i := 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if strings.HasPrefix(line, "layout:") {
				return raw
			}
			if line == "---" {
				out := make([]string, 0, len(lines)+1)
				out = append(out, lines[0])
				out = append(out, "layout: "+layoutPath+"\n")
				out = append(out, lines[1:]...)
				return []byte(strings.Join(out, ""))
			}
		}
	}
	return []byte("---\nlayout: " + layoutPath + "\n---\n" + text)
}

func removeConflictingPageOverride(target string) error {
	ext := filepath.Ext(target)
	if ext != ".astro" && ext != ".md" && ext != ".mdx" {
		return nil
	}
	stem := strings.TrimSuffix(target, ext)
	for _, candidateExt := range []string{".astro", ".md", ".mdx"} {
		candidate := stem + candidateExt
		if candidate == target {
			continue
		}
		if err := os.Remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func shouldSkipOverridePath(rel string, entry fs.DirEntry) bool {
	parts := splitPath(rel)
	for _, part := range parts {
		switch part {
		case "node_modules", "dist", ".astro":
			return true
		}
	}
	return false
}

func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	outFile, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	defer outFile.Close()
	_, err = io.Copy(outFile, in)
	return err
}

func splitPath(path string) []string {
	parts := []string{}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

const defaultCatalogSiteReadme = `# ClearCutt Catalog Site

This Astro project renders ClearCutt catalog data as a static evidence portal.

## Run Locally

~~~bash
npm install  # or the package manager matching your lockfile
npm run dev
~~~

Build static output with:

~~~bash
npm run build  # or pnpm/yarn/bun run build when that lockfile is present
~~~

Generated catalog data is expected under ` + "`public/catalog`" + `. The scaffold command copies
the catalog you pass with ` + "`--catalog`" + ` into that directory.

## Customize

Edit ` + "`clearcutt.site.yaml`" + ` to customize branding and behavior:

- ` + "`site.title`" + `, ` + "`site.description`" + `, and ` + "`site.logo`" + ` set the catalog identity.
- ` + "`site.theme.mode`" + ` and ` + "`site.theme.accent`" + ` set the theme preference and accent color.
- ` + "`site.navigation`" + ` toggles the home, getting started, operator, CLI, and audit nav links.
- ` + "`site.features`" + ` toggles SBOMs, vulnerabilities, layers, provenance, OCI labels, release history, and Kyverno policy examples.
- ` + "`site.terminology`" + ` renames tier labels such as distroless, slim, and dev.
- ` + "`site.links`" + ` adds source repository, registry, support, and docs links.
- ` + "`site.home`" + ` customizes homepage title, notice, quick links, persona workflow sections, and per-step CTA labels.

Use ` + "`--site-config ./clearcutt.site.yaml`" + ` when scaffolding or building to copy an
external config into the generated project.

## Override Content

Pass ` + "`--overrides ./site-overrides`" + ` to copy targeted customizations without forking
ClearCutt:

~~~text
site-overrides/
  components/  -> src/components/
  pages/       -> src/pages/
  styles/      -> src/styles/
  public/      -> public/
~~~

Markdown page overrides automatically use the default site layout when no layout
frontmatter is provided. Page overrides also replace conflicting Astro, Markdown,
or MDX routes with the same path.

## Regenerate

~~~bash
clearcutt-verify catalog generate --config clearcutt.fleet.yaml --output ./dist/catalog
clearcutt-verify catalog site scaffold --catalog ./dist/catalog --output ./clearcutt-catalog-site
clearcutt-verify catalog site build --catalog ./dist/catalog --output ./dist/site
~~~
`
