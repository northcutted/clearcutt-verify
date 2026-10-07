package commands

import (
	"github.com/northcutted/clearcutt-verify/internal/config"
	"github.com/spf13/cobra"
)

// addConfigFlag registers --config for a command's ClearCutt config path, and
// keeps --fleet-config working as a hidden alias.
//
// The flag was named --fleet-config when the file was clearcutt.fleet.yaml.
// Both named the smallest thing the file does: three of its eleven sections
// configure building a fleet, and the governance commands — the product — never
// read it at all. A user governing their registry should not be asked for a
// "fleet config" they do not have.
//
// The alias is hidden rather than deprecated-with-warning on purpose. A
// deprecation notice would print on every invocation in every fork's CI logs,
// which is a lot of noise to impose for a rename we chose. It keeps working
// silently; the help text advertises --config.
func addConfigFlag(cmd *cobra.Command, target *string, usage string) {
	cmd.Flags().StringVar(target, "config", config.DefaultConfigPath, usage)
	cmd.Flags().StringVar(target, "fleet-config", config.DefaultConfigPath, usage)
	_ = cmd.Flags().MarkHidden("fleet-config")
}
