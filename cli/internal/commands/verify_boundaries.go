package commands

import (
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/certify"
	"github.com/spf13/cobra"
)

type boundariesFlags struct {
	allowlist      string
	storePaths     string
	coreDir        string
	buildOutputs   string
	closureTargets []string
	configPath     string
}

var boundariesOpts boundariesFlags

// newVerifyBoundariesCmd runs every image-security boundary gate over one
// shipped closure. It is the CLI-owned umbrella for the gates that previously
// lived only in core/tests/verify.sh, so a forker gets the same verification by
// running the binary. New gates are added here as they are ported.
func newVerifyBoundariesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "boundaries [image-archive]",
		Short: "Run all image-security boundary gates (closure purity + runtime-patch completeness)",
		Long: `Runs every native-Go image-security boundary gate over one shipped closure
(a docker-save / OCI-layout archive, or a closureInfo store-paths file):

  closure-purity   no shells, package managers, or setuid/setgid files

Fails if any gate fails. This is the CLI-owned umbrella that replaces the
per-gate python invocations in core/tests/verify.sh.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive := ""
			if len(args) == 1 {
				archive = args[0]
			}
			return runVerifyBoundaries(archive)
		},
	}
	cmd.Flags().StringVar(&boundariesOpts.allowlist, "allowlist", "", "closure-purity explained-exception allowlist file")
	cmd.Flags().StringVar(&boundariesOpts.storePaths, "store-paths", "", "closureInfo store-paths file to scan instead of an image archive")
	return cmd
}

func runVerifyBoundaries(archive string) error {
	if (archive != "") == (boundariesOpts.storePaths != "") {
		return fmt.Errorf("provide exactly one of <image-archive> or --store-paths FILE")
	}

	failed := false

	// Gate 1: closure purity.
	allowlist, err := certify.LoadClosureAllowlist(boundariesOpts.allowlist)
	if err != nil {
		return err
	}
	var purity certify.ClosurePurityResult
	if archive != "" {
		purity, err = certify.ScanImageArchiveForClosurePurity(archive, allowlist)
	} else {
		purity, err = certify.ScanStorePathsForClosurePurity(boundariesOpts.storePaths, allowlist)
	}
	if err != nil {
		return err
	}
	for _, note := range purity.Accepted {
		fmt.Fprintf(out, "[closure-purity] ACCEPTED: %s\n", note)
	}
	if purity.Clean() {
		fmt.Fprintln(out, "[closure-purity] clean: no shells, package managers, or setuid/setgid files found.")
	} else {
		for _, v := range purity.Violations {
			fmt.Fprintf(errOut, "[closure-purity] VIOLATION: %s\n", v.Message)
		}
		failed = true
	}

	if failed {
		return ErrCheckFailed
	}
	fmt.Fprintln(out, "[boundaries] all image-security boundary gates passed.")
	return nil
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
