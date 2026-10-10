package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// Version is the CLI version, overridable at build time via -ldflags.
var Version = "dev"

// GlobalOptions stores the CLI flags shared across commands.
type GlobalOptions struct {
	Format  string
	Quiet   bool
	Verbose bool
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
			return ValidateGlobalFormat(GlobalOpts.Format)
		},
	}

	rootCmd.PersistentFlags().StringVar(&GlobalOpts.Format, "format", "table", "Output format: table, json, or yaml")
	rootCmd.PersistentFlags().BoolVar(&GlobalOpts.Quiet, "quiet", false, "Suppress non-essential console outputs")
	rootCmd.PersistentFlags().BoolVar(&GlobalOpts.Verbose, "verbose", false, "Enable verbose debug outputs")

	rootCmd.AddGroup(
		&cobra.Group{ID: "map", Title: "Map an estate:"},
		&cobra.Group{ID: "verify", Title: "Verify and report:"},
	)
	add := func(groupID string, cmd *cobra.Command) {
		cmd.GroupID = groupID
		rootCmd.AddCommand(cmd)
	}

	// Find the images, and what they are built on, share, and install.
	add("map", NewRegistryCmd())
	add("map", NewImportCmd())
	add("map", NewGraphCmd())

	// Verify their evidence, write the estate report, and keep it.
	add("verify", NewEstateCmd())
	add("verify", NewEvidenceCmd())
	add("verify", NewVerifyCmd())

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
