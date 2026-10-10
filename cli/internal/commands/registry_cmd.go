package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/registryscan"
	"github.com/spf13/cobra"
)

type registryScanFlags struct {
	registry     string
	namespace    string
	repositories []string
	tagPatterns  []string
	excludeTags  []string
	maxTags      int
	includeSide  bool
	output       string
	refsOutput   string
	scanOutput   string
	owner        string
	repo         string
	defaultTier  string
	generatedAt  string
	username     string
	passwordEnv  string
	force        bool
	githubOrg    string
	prefixes     []string
}

var registryScanOpts registryScanFlags

// NewRegistryCmd builds the `clearcutt-verify registry` command group.
func NewRegistryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Discover what is actually published in a registry",
		Long: `Enumerate an OCI registry namespace into a ClearCutt inventory.

Every other governance path starts from a list of image references. This command
produces that list by asking the registry what it holds, so the inventory covers the
images you actually have rather than the ones someone remembered to write down.

Enumeration is read-only: it lists repositories and tags and writes local files. It
never pulls layers, mutates tags, or publishes anything.`,
	}
	cmd.AddCommand(newRegistryScanCmd())
	return cmd
}

func newRegistryScanCmd() *cobra.Command {
	registryScanOpts = registryScanFlags{defaultTier: "slim", maxTags: 25}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Enumerate a registry namespace into an images.yaml inventory",
		Long: `Enumerate a registry namespace into a ClearCutt images.yaml inventory.

Cosign signature, attestation, and SBOM sidecar tags (sha256-<digest>.sig and
friends) are skipped by default: they are evidence about an image, not images a
workload runs, and they outnumber real tags in most registries.

Registries that do not implement the distribution _catalog endpoint (GHCR and Docker
Hub among them) cannot be enumerated blindly. Name the repositories with
--repository, which can be repeated. For GHCR, --github-org lists an
organization's (or user's) container packages through the GitHub Packages API
instead, with a GITHUB_TOKEN that can read packages.`,
		Args: cobra.NoArgs,
		Example: `  # Enumerate a namespace on a registry that supports _catalog
  clearcutt-verify registry scan --registry registry.acme.dev --namespace platform/base \
    --output dist/scan/images.yaml

  # GHCR: name the repositories explicitly
  clearcutt-verify registry scan --registry ghcr.io --namespace acme/platform \
    --repository base-java21 --repository base-node22 \
    --tag-pattern 'v*' --output dist/scan/images.yaml

  # GHCR: every container package of an organization under apps/ and platform/
  clearcutt-verify registry scan --github-org acme --package-prefix apps/ --package-prefix platform/ \
    --output dist/scan/images.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryScan(cmd.Context())
		},
	}
	f := cmd.Flags()
	f.StringVar(&registryScanOpts.registry, "registry", "", "Registry host, e.g. ghcr.io")
	f.StringVar(&registryScanOpts.namespace, "namespace", "", "Repository path prefix to scan, e.g. acme/platform")
	f.StringArrayVar(&registryScanOpts.repositories, "repository", nil, "Scan this repository directly instead of enumerating the catalog (repeatable)")
	f.StringArrayVar(&registryScanOpts.tagPatterns, "tag-pattern", nil, "Only keep tags matching this glob (repeatable; default all)")
	f.StringArrayVar(&registryScanOpts.excludeTags, "exclude-tag", nil, "Reject tags matching this glob (repeatable)")
	f.IntVar(&registryScanOpts.maxTags, "max-tags", 25, "Maximum tags to keep per repository")
	f.BoolVar(&registryScanOpts.includeSide, "include-sidecar-tags", false, "Keep cosign/attestation sidecar tags in the inventory")
	f.StringVar(&registryScanOpts.output, "output", "", "Output images.yaml inventory path")
	f.StringVar(&registryScanOpts.refsOutput, "refs-output", "", "Also write the flat ref list to this path")
	f.StringVar(&registryScanOpts.scanOutput, "scan-output", "", "Also write the raw scan record (repositories, tag counts, warnings) to this path")
	f.StringVar(&registryScanOpts.owner, "owner", "", "Inventory owner label")
	f.StringVar(&registryScanOpts.repo, "repo", "", "Inventory repo label")
	f.StringVar(&registryScanOpts.defaultTier, "default-tier", "slim", "Default tier for discovered images")
	f.StringVar(&registryScanOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	f.StringVar(&registryScanOpts.username, "username", "", "Registry username (default: ambient keychain)")
	f.StringVar(&registryScanOpts.passwordEnv, "password-env", "", "Environment variable holding the registry password or token")
	f.BoolVar(&registryScanOpts.force, "force", false, "Overwrite existing output files")
	f.StringVar(&registryScanOpts.githubOrg, "github-org", "", "List this GitHub organization's (or user's) ghcr.io container packages through the GitHub Packages API (GITHUB_TOKEN with packages: read)")
	f.StringArrayVar(&registryScanOpts.prefixes, "package-prefix", nil, "With --github-org, keep only packages whose name starts with this (repeatable), e.g. apps/")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runRegistryScan(ctx context.Context) error {
	opts := registryScanOpts
	if opts.githubOrg != "" {
		if opts.registry != "" && opts.registry != "ghcr.io" {
			return fmt.Errorf("--github-org lists ghcr.io packages; --registry %s doesn't apply", opts.registry)
		}
		opts.registry = "ghcr.io"
		if opts.namespace == "" {
			opts.namespace = strings.ToLower(opts.githubOrg)
		}
	} else if len(opts.prefixes) > 0 {
		return errors.New("--package-prefix needs --github-org")
	}
	if opts.registry == "" {
		return errors.New("--registry (or --github-org) is required")
	}
	for _, path := range []string{opts.output, opts.refsOutput, opts.scanOutput} {
		if path == "" || opts.force {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite", path)
		}
	}

	lister, err := registryLister(opts)
	if err != nil {
		return err
	}
	result, err := registryscan.Scan(ctx, lister, registryscan.Options{
		Registry:           opts.registry,
		Namespace:          opts.namespace,
		Repositories:       opts.repositories,
		TagPatterns:        opts.tagPatterns,
		ExcludeTagPatterns: opts.excludeTags,
		MaxTagsPerRepo:     opts.maxTags,
		IncludeSidecarTags: opts.includeSide,
		GeneratedAt:        opts.generatedAt,
	})
	if err != nil {
		return err
	}
	if len(result.Refs) == 0 {
		return fmt.Errorf("scan of %s/%s matched no images; %s", opts.registry, opts.namespace, strings.Join(result.Warnings, "; "))
	}

	inventory, summary, err := estategraph.ImportRefList(result.Refs, estategraph.ImportOptions{
		Owner:        opts.owner,
		Repo:         opts.repo,
		RegistryBase: strings.TrimSuffix(opts.registry+"/"+opts.namespace, "/"),
		DefaultTier:  opts.defaultTier,
		GeneratedAt:  result.GeneratedAt,
	})
	if err != nil {
		return err
	}
	if err := writeAlongside(opts.output, func(path string) error {
		return estategraph.WriteImagesFile(path, inventory)
	}); err != nil {
		return err
	}
	if opts.refsOutput != "" {
		if err := writeAlongside(opts.refsOutput, func(path string) error {
			return os.WriteFile(path, []byte(strings.Join(result.Refs, "\n")+"\n"), 0o644)
		}); err != nil {
			return err
		}
	}
	if opts.scanOutput != "" {
		if err := writeAlongside(opts.scanOutput, func(path string) error {
			return writeJSONFile(path, result)
		}); err != nil {
			return err
		}
	}

	if structuredFormat() {
		return printStructured(struct {
			registryscan.Result
			Inventory string `json:"inventory"`
			Images    int    `json:"images"`
		}{Result: result, Inventory: opts.output, Images: summary.ImageCount})
	}
	fmt.Fprintf(out, "[registry-scan] %s/%s: %d repositories, %d tags discovered, %d selected\n",
		opts.registry, opts.namespace, result.Summary.RepositoriesDiscovered, result.Summary.TagsDiscovered, result.Summary.TagsSelected)
	if result.Summary.SidecarTagsSkipped > 0 {
		fmt.Fprintf(out, "[registry-scan] skipped %d cosign/attestation sidecar tag(s); pass --include-sidecar-tags to keep them\n", result.Summary.SidecarTagsSkipped)
	}
	if result.Summary.RepositoriesFailed > 0 {
		fmt.Fprintf(errOut, "[registry-scan] %d repository(ies) could not be listed; see per-repository warnings with --scan-output\n", result.Summary.RepositoriesFailed)
	}
	fmt.Fprintf(out, "[registry-scan] wrote %d image(s) to %s\n", summary.ImageCount, opts.output)
	if summary.LowConfidence > 0 {
		fmt.Fprintf(out, "[registry-scan] %d image(s) could not be classified by runtime and need review\n", summary.LowConfidence)
	}
	fmt.Fprintf(out, "[registry-scan] next: clearcutt-verify import observe --images %s --output observations.json\n", opts.output)
	return nil
}

// registryLister picks explicit credentials over the ambient keychain.
//
// The password is read from an environment variable rather than taken as a flag so a
// registry token never lands in shell history or a process listing.
func registryLister(opts registryScanFlags) (registryscan.Lister, error) {
	if opts.githubOrg != "" {
		return &registryscan.GitHubPackages{Owner: opts.githubOrg, Prefixes: opts.prefixes}, nil
	}
	if opts.username == "" && opts.passwordEnv == "" {
		return registryscan.NewRemoteLister(), nil
	}
	if opts.username == "" || opts.passwordEnv == "" {
		return nil, fmt.Errorf("--username and --password-env must be supplied together")
	}
	password := os.Getenv(opts.passwordEnv)
	if password == "" {
		return nil, fmt.Errorf("environment variable %s is empty; it must hold the registry password or token", opts.passwordEnv)
	}
	return registryscan.NewRemoteListerWithBasicAuth(opts.username, password), nil
}

// writeAlongside creates the parent directory then writes via the supplied writer.
func writeAlongside(path string, write func(string) error) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return write(path)
}
