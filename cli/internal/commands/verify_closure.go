package commands

import (
	"fmt"

	"github.com/northcutted/clearcutt-verify/internal/certify"
	"github.com/spf13/cobra"
)

type closurePurityFlags struct {
	allowlist  string
	storePaths string
}

var closurePurityOpts closurePurityFlags

// newVerifyClosurePurityCmd is the native-Go port of
// core/tests/closure-purity-check.py: it gates an image's full /nix/store
// closure (not just FHS paths) against shells, package managers, and
// setuid/setgid files. Exit code follows the CLI contract: 0 clean, 2 on
// violations (a policy gate failure), 1 on operational error.
func newVerifyClosurePurityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "closure-purity [image-archive]",
		Short: "Gate an image's /nix/store closure against shells, package managers, and setuid/setgid files",
		Long: `Walks a docker-save or OCI-layout image archive (layer tar headers, so
permission bits survive non-root extraction) — or a closureInfo store-paths
file via --store-paths — and fails if any store path provides an interactive
shell (sh, bash, ash, dash) or a package manager (npm, npx, corepack, pip*,
apk, dpkg, rpm), or if any setuid/setgid regular file is present.

Findings can be consciously accepted with an explained-exception allowlist
(--allowlist), where each non-comment line is:
  <store-name-pattern> <one-line reason>

This is the native-Go port of core/tests/closure-purity-check.py and walks the
full /nix/store closure, not just FHS paths.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive := ""
			if len(args) == 1 {
				archive = args[0]
			}
			return runVerifyClosurePurity(archive)
		},
	}
	cmd.Flags().StringVar(&closurePurityOpts.allowlist, "allowlist", "", "Explained-exception allowlist file")
	cmd.Flags().StringVar(&closurePurityOpts.storePaths, "store-paths", "", "closureInfo store-paths file to scan instead of an image archive")
	return cmd
}

func runVerifyClosurePurity(archive string) error {
	if (archive != "") == (closurePurityOpts.storePaths != "") {
		return fmt.Errorf("provide exactly one of <image-archive> or --store-paths FILE")
	}

	allowlist, err := certify.LoadClosureAllowlist(closurePurityOpts.allowlist)
	if err != nil {
		return err
	}

	var result certify.ClosurePurityResult
	if archive != "" {
		result, err = certify.ScanImageArchiveForClosurePurity(archive, allowlist)
	} else {
		result, err = certify.ScanStorePathsForClosurePurity(closurePurityOpts.storePaths, allowlist)
	}
	if err != nil {
		return err
	}

	for _, note := range result.Accepted {
		fmt.Fprintf(out, "[closure-purity] ACCEPTED: %s\n", note)
	}

	if !result.Clean() {
		for _, v := range result.Violations {
			fmt.Fprintf(errOut, "[closure-purity] VIOLATION: %s\n", v.Message)
		}
		fmt.Fprintf(errOut, "[closure-purity] %d violation(s). Either remove the offending package from the production closure or add an explained entry to the closure-purity allowlist.\n", len(result.Violations))
		return ErrCheckFailed
	}

	fmt.Fprintln(out, "[closure-purity] clean: no shells, package managers, or setuid/setgid files found.")
	return nil
}
