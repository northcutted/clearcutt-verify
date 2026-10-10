package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/northcutted/clearcutt-verify/internal/estateverify"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

type estateDependentsFlags struct {
	report      string
	base        string
	minStrength string
	transitive  bool
}

var estateDependentsOpts estateDependentsFlags

// DependentsResult is the structured output of estate dependents.
type DependentsResult struct {
	Base       string                   `json:"base"`
	Report     string                   `json:"report"`
	Dependents []estateverify.Dependent `json:"dependents"`
}

func newEstateDependentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dependents",
		Short: "List the images built on a base, from an estate report",
		Long: `Lists the images an estate report records as built on a base repository,
with the version they are on, how far behind it is, and the repository each
image was built from. A platform team's workflow uses it to wake exactly the
repositories a new base affects.

By default only relationships proven by layer digest count (--min-strength
proof); --transitive also lists images built on those images.`,
		Example: `  clearcutt-verify estate dependents --report dist/estate/estate-report.json \
    --base ghcr.io/acme/platform/run-python --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEstateDependents()
		},
	}
	f := cmd.Flags()
	f.StringVar(&estateDependentsOpts.report, "report", "estate-report.json", "Estate report (from estate verify)")
	f.StringVar(&estateDependentsOpts.base, "base", "", "Base repository (a tag or digest is ignored)")
	f.StringVar(&estateDependentsOpts.minStrength, "min-strength", "proof", "Weakest relationship that counts: proof, declared, assisted, or weak")
	f.BoolVar(&estateDependentsOpts.transitive, "transitive", false, "Also list images built on the dependents")
	_ = cmd.MarkFlagRequired("base")
	return cmd
}

func runEstateDependents() error {
	o := estateDependentsOpts
	switch o.minStrength {
	case "proof", "declared", "assisted", "weak":
	default:
		return fmt.Errorf("--min-strength %q must be proof, declared, assisted, or weak", o.minStrength)
	}
	raw, err := os.ReadFile(o.report)
	if err != nil {
		return err
	}
	var r report.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("%s: %w", o.report, err)
	}
	if r.APIVersion != report.APIVersion || r.Kind != report.KindReport {
		return fmt.Errorf("%s is not an estate report (%s %s)", o.report, report.APIVersion, report.KindReport)
	}
	result := DependentsResult{Base: o.base, Report: o.report, Dependents: estateverify.Dependents(&r, o.base, o.minStrength, o.transitive)}
	if structuredFormat() {
		return printStructured(result)
	}
	if len(result.Dependents) == 0 {
		fmt.Fprintf(out, "no images in %s are built on %s (at strength %s or better)\n", o.report, o.base, o.minStrength)
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IMAGE\tON\tDRIFT\tSTRENGTH\tSOURCE")
	for _, d := range result.Dependents {
		on := d.Base.Ref
		if d.Depth > 1 {
			on = fmt.Sprintf("%s (depth %d)", on, d.Depth)
		}
		drift := d.Base.Drift
		if d.Base.Drift == "stale" {
			drift = fmt.Sprintf("stale, %dd behind", d.Base.DaysBehind)
		}
		source := "-"
		if d.Source != nil {
			source = d.Source.URL
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", d.ImageID, on, drift, d.Base.Strength, source)
	}
	return w.Flush()
}
