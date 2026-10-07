package commands

import (
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/spf13/cobra"
)

// Version is the CLI version, overridable at build time via -ldflags.
var Version = "dev"

// GlobalOptions stores the CLI flags shared across commands.
type GlobalOptions struct {
	CatalogPath string
	Format      string
	Quiet       bool
	Verbose     bool
}

// GlobalOpts holds the active parsed global options.
var GlobalOpts GlobalOptions

// NewRootCmd initializes the Cobra root command hierarchy.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "clearcutt-verify",
		Short: "ClearCutt Verify: govern and verify container image estates",
		Long: `ClearCutt Verify maps an image estate (which images are built on which,
proven by layer digest), verifies each image's signatures and attestations
against trusted signers, and writes the estate report clearcutt-portal
publishes. It is part of ClearCutt, with clearcutt-factory.`,
		Version: Version,
		// Returned errors are already actionable; don't dump usage text on every
		// failure, and let main own error/exit-code presentation.
		SilenceUsage:  true,
		SilenceErrors: true,
		// Cobra runs only the closest PersistentPreRunE in the command chain,
		// so a subcommand that defines its own hook must call
		// ValidateGlobalFormat itself. No subcommand defines one today; keep it
		// that way or compose explicitly.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := ValidateGlobalFormat(GlobalOpts.Format); err != nil {
				return err
			}
			// The default catalog data directory is repo state under
			// site/src/data/catalog; resolve it against the enclosing repo
			// root so catalog readers and the catalog build pipeline's default
			// output sink agree no matter which subdirectory the CLI runs
			// from. An explicit --catalog keeps its exact (cwd-relative)
			// meaning.
			resolveRepoRootDefault(cmd, "catalog", &GlobalOpts.CatalogPath)
			return nil
		},
	}

	rootCmd.PersistentFlags().StringVar(&GlobalOpts.CatalogPath, "catalog", "site/src/data/catalog", "Path to local catalog JSON data directory")
	rootCmd.PersistentFlags().StringVar(&GlobalOpts.Format, "format", "table", "Output format: table, json, or yaml")
	rootCmd.PersistentFlags().BoolVar(&GlobalOpts.Quiet, "quiet", false, "Suppress non-essential console outputs")
	rootCmd.PersistentFlags().BoolVar(&GlobalOpts.Verbose, "verbose", false, "Enable verbose debug outputs")
	rootCmd.PersistentFlags().BoolVar(&catalog.Strict, "strict", false, "Reject catalog JSON containing fields unknown to the CLI data model")

	// The CLI help is a tool map, not a marketing funnel. Several commands span
	// multiple SDLC phases, so group them by operator job while the README/site
	// explain the higher-level lifecycle story.
	rootCmd.AddGroup(
		&cobra.Group{ID: "catalog", Title: "Catalog & Release Evidence:"},
		&cobra.Group{ID: "browse", Title: "Catalog Discovery:"},
		&cobra.Group{ID: "apps", Title: "App Team Workflow:"},
		&cobra.Group{ID: "govern", Title: "Governance Gates:"},
		&cobra.Group{ID: "secure", Title: "Security Operations:"},
	)

	add := func(groupID string, cmd *cobra.Command) {
		cmd.GroupID = groupID
		rootCmd.AddCommand(cmd)
	}

	// Build catalog data and publish release evidence.
	add("catalog", NewCatalogCmd())
	add("catalog", NewReleaseCmd())

	// Browse published catalog contents.
	add("browse", NewListCmd())
	add("browse", NewInspectCmd())
	add("browse", NewDiffCmd())

	// Give app teams matching dev, build, rebase, mirroring, and admission tools.
	add("apps", NewAppCmd())
	add("apps", NewRebaseCmd())
	add("apps", NewMirrorCmd())
	add("apps", NewPolicyCmd())

	// Gate image releases and cluster admission decisions.
	add("govern", NewRegistryCmd())
	add("govern", NewGraphCmd())
	add("govern", NewImportCmd())
	add("govern", NewEstateCmd())
	add("govern", NewEvidenceCmd())
	add("govern", NewCertifyCmd())
	add("govern", NewVerifyCmd())
	add("govern", NewConformanceCmd())

	// Operate security remediation, exceptions, and VEX flows.
	add("secure", NewScanCmd())
	add("secure", NewExceptionsCmd())
	add("secure", NewVexCmd())

	return rootCmd
}

// ValidateGlobalFormat rejects unknown --format values before any command
// runs, instead of letting them silently fall back to table output. The
// accepted set (case-insensitive) matches the format switches used across the
// commands: table, json, yaml, and the yml alias.
func ValidateGlobalFormat(format string) error {
	switch strings.ToLower(format) {
	case "table", "json", "yaml", "yml":
		return nil
	default:
		return fmt.Errorf("unknown --format %q (expected table, json, or yaml)", format)
	}
}
