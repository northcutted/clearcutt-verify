package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/northcutted/clearcutt-verify/internal/commands"
)

// Exit code contract (documented in docs/cli-reference.md):
//
//	0 - all checks passed / command succeeded
//	1 - operational error (bad flags, IO failure, missing catalog, tooling)
//	2 - a policy gate failed (verification, conformance, certification,
//	    exception, or threshold checks)
//
// CI systems can therefore distinguish "the gate said no" (2) from "the gate
// could not run" (1) without parsing output.
const (
	exitOperationalError = 1
	exitPolicyFailure    = 2
)

func main() {
	rootCmd := commands.NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		// Gating failures (verify/certify/conformance/exceptions) already
		// printed a detailed report; exit with the policy code without an
		// extra, redundant error line.
		if errors.Is(err, commands.ErrCheckFailed) {
			os.Exit(exitPolicyFailure)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitOperationalError)
	}
}
