package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/estateverify"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/northcutted/clearcutt-verify/internal/registryauth"
)

type policyInitFlags struct {
	refs, images, out string
	concurrency       int
	platforms         []string
}

// NewPolicyCmd groups policy bootstrap commands.
func NewPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Prepare a policy from discovered evidence without inferring trust"}
	var opts policyInitFlags
	init := &cobra.Command{
		Use:   "init",
		Short: "Discover evidence and write a starter policy and inactive trust skeleton",
		Long: `Inspects image references or an images.yaml inventory and writes policy.yaml
and trust-policy.yaml into a new --out directory. Required evidence is what
discovery found for every image, with SBOM and scan availability checked for
every selected platform. An unreadable image, platform or evidence listing
stops initialization instead of weakening the suggested requirements.

Discovery does not verify signatures or evidence content. All signer
candidates are commented UNVERIFIED claims; the active trust list is empty.
Review these candidates out of band and choose vulnerability/freshness gates
before using the policy. An untouched starter cannot verify an image.

Existing output directories, files and symlinks are refused. Both documents
are validated before the new directory is published. --verbose reports
discovery progress on stderr; --format json or yaml prints a summary, not
the policy documents themselves.`,
		Example: `  clearcutt-verify policy init --refs refs.txt --out policy
  clearcutt-verify policy init --images images.yaml --platforms linux/amd64,linux/arm64 --out policy`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyInit(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}
	f := init.Flags()
	f.StringVar(&opts.refs, "refs", "", "File of image references, one per line")
	f.StringVar(&opts.images, "images", "", "images.yaml inventory (only its image references are used)")
	f.StringVar(&opts.out, "out", "", "New directory for policy.yaml and trust-policy.yaml; existing paths are refused")
	f.IntVar(&opts.concurrency, "concurrency", 4, "Image references to inspect at once")
	f.StringSliceVar(&opts.platforms, "platforms", nil, "Inspect only matching platform images; use the same scope when verifying")
	_ = init.MarkFlagRequired("out")
	cmd.AddCommand(init)
	return cmd
}

func runPolicyInit(ctx context.Context, stdout, stderr io.Writer, opts policyInitFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.out == "" {
		return errors.New("--out is required")
	}
	if err := policyOutputAbsent(opts.out); err != nil {
		return err
	}
	if (opts.refs == "") == (opts.images == "") {
		return errors.New("pass exactly one of --refs and --images")
	}
	if opts.concurrency < 1 {
		return errors.New("--concurrency must be at least 1")
	}
	var inventory estategraph.ImagesFile
	var err error
	if opts.refs != "" {
		inventory, _, err = estategraph.ImportRefs(estategraph.ImportOptions{RefsPath: opts.refs})
	} else {
		var input estategraph.ImagesFile
		input, err = estategraph.ReadImagesFile(opts.images)
		if err == nil {
			var refs []string
			for _, image := range input.Images {
				refs = append(refs, image.Image)
			}
			// Inventory declarations and IDs do not establish registry evidence.
			inventory, _, err = estategraph.ImportRefList(refs, estategraph.ImportOptions{})
		}
	}
	if err != nil {
		return fmt.Errorf("read image references: %w", err)
	}
	verbose := GlobalOpts.Verbose && !GlobalOpts.Quiet
	if verbose {
		fmt.Fprintf(stderr, "[policy-init] resolving %d image reference(s)\n", len(inventory.Images))
	}
	ropts := []remote.Option{remote.WithAuthFromKeychain(registryauth.Keychain), remote.WithTransport(estateverify.NewManifestCache(remote.DefaultTransport))}
	observations, _, err := estategraph.ObserveImages(ctx, inventory, estategraph.RegistryObserver{Options: ropts},
		estategraph.ObserveOptions{Strict: true, Concurrency: opts.concurrency})
	if err != nil {
		return err
	}
	settings := estateverify.PolicyInitOptions{Concurrency: opts.concurrency, Platforms: opts.platforms, RemoteOptions: ropts}
	if verbose {
		settings.Progress = func(completed, total int, ref string) {
			fmt.Fprintf(stderr, "[policy-init] inspected %d/%d %q\n", completed, total, ref)
		}
	}
	suggestion, err := estateverify.SuggestPolicy(ctx, observations, settings)
	if err != nil {
		return err
	}
	if err := publishPolicyStarter(ctx, opts.out, suggestion); err != nil {
		return err
	}
	summary := struct {
		estateverify.PolicySuggestion
		Output string `json:"output"`
	}{suggestion, opts.out}
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(stdout, summary)
	case "yaml", "yml":
		raw, err := yaml.Marshal(summary)
		if err != nil {
			return err
		}
		_, err = stdout.Write(raw)
		return err
	default:
		if !GlobalOpts.Quiet {
			_, err = fmt.Fprintf(stdout, "[policy-init] wrote policy.yaml and trust-policy.yaml to %q from %d image reference(s); no signers are trusted yet\n", opts.out, suggestion.Images)
		}
		return err
	}
}

func policyOutputAbsent(path string) error {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return fmt.Errorf("%s already exists; choose a new --out directory", path)
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("check output %s: %w", path, err)
	}
}

func publishPolicyStarter(ctx context.Context, dest string, suggestion estateverify.PolicySuggestion) error {
	policy, trust, err := estateverify.RenderPolicySuggestion(suggestion)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dest = filepath.Clean(dest)
	if err := policyOutputAbsent(dest); err != nil {
		return err
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".clearcutt-policy-")
	if err != nil {
		return err
	}
	defer func() {
		if stage != "" {
			_ = os.RemoveAll(stage)
		}
	}()
	for file, raw := range map[string][]byte{"policy.yaml": policy, "trust-policy.yaml": trust} {
		if err := os.WriteFile(filepath.Join(stage, file), raw, 0o644); err != nil {
			return err
		}
	}
	if _, err := estateverify.ReadPolicy(filepath.Join(stage, "policy.yaml")); err != nil {
		return err
	}
	if _, err := estateverify.ReadTrustPolicy(filepath.Join(stage, "trust-policy.yaml")); err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := policyOutputAbsent(dest); err != nil {
		return err
	}
	// A sibling directory rename publishes the validated pair together.
	if err := os.Rename(stage, dest); err != nil {
		return err
	}
	stage = ""
	return nil
}
