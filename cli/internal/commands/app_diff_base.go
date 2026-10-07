package commands

import (
	"fmt"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type appDiffBaseFlags struct {
	image           string
	candidateBase   string
	candidateBaseID string
	currentBase     string
	failOnIncompat  bool
}

var appDiffBaseOpts appDiffBaseFlags

type sevCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// AppDiffBaseResult is the structured output of `app diff-base`.
type AppDiffBaseResult struct {
	Image         string `json:"image"`
	CurrentBase   string `json:"currentBase"`
	CandidateBase string `json:"candidateBase"`
	Compatible    bool   `json:"compatible"`
	CompatReason  string `json:"compatReason"`
	Rebasable     bool   `json:"rebasable"`
	Boundary      string `json:"boundary,omitempty"`

	CurrentVulns      *sevCounts `json:"currentVulns,omitempty"`
	CandidateVulns    *sevCounts `json:"candidateVulns,omitempty"`
	VulnDelta         *sevCounts `json:"vulnDelta,omitempty"`
	VulnDeltaComputed bool       `json:"vulnDeltaComputed"`
}

func newAppDiffBaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff-base",
		Short: "Compare an app image or catalog base against a candidate base",
		Long: `Audits whether an application image can safely move to a candidate base, before
committing to a rebase. It reports:

  - runtime compatibility (same family and major/minor line; patch upgrades allowed),
  - whether the app is rebasable and where its base boundary sits,
  - the base-image CVE delta from the catalog (e.g. "High: 12 -> 0").

The CVE delta is computed entirely offline from the local catalog. Pass --current-base
to skip the registry read of --image and compare two catalog bases purely offline.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAppDiffBase()
		},
	}

	f := cmd.Flags()
	f.StringVar(&appDiffBaseOpts.image, "image", "", "Application image reference to audit (read for its base labels)")
	f.StringVar(&appDiffBaseOpts.candidateBase, "candidate-base", "", "Candidate base: catalog id or registry reference")
	f.StringVar(&appDiffBaseOpts.candidateBaseID, "candidate-base-id", "", "Candidate base catalog id (when --candidate-base is a raw reference)")
	f.StringVar(&appDiffBaseOpts.currentBase, "current-base", "", "Current base catalog id; set this to compare two catalog bases offline without reading --image")
	f.BoolVar(&appDiffBaseOpts.failOnIncompat, "fail-on-incompatible", false, "Exit non-zero if the candidate base is not runtime-compatible")

	_ = cmd.MarkFlagRequired("candidate-base")

	return cmd
}

func runAppDiffBase() error {
	if appDiffBaseOpts.image == "" && appDiffBaseOpts.currentBase == "" {
		return fmt.Errorf("provide --image (to read its base) or --current-base (to compare offline)")
	}

	result := AppDiffBaseResult{}

	// Determine the current base id and (when reading the image) its rebase metadata.
	currentBaseID := appDiffBaseOpts.currentBase
	if appDiffBaseOpts.image != "" && currentBaseID == "" {
		result.Image = appDiffBaseOpts.image
		meta, err := newOCIClient().ReadAppMeta(appDiffBaseOpts.image)
		if err != nil {
			return fmt.Errorf("read app image: %w", err)
		}
		currentBaseID = meta.BaseID
		result.Rebasable = meta.Rebasable
		result.Boundary = meta.BaseLastLayer
		if currentBaseID == "" {
			return fmt.Errorf("image %q has no recorded base id (%s); was it built with `clearcutt-verify app build`?", appDiffBaseOpts.image, "dev.clearcutt.app.base.id")
		}
	}
	result.CurrentBase = currentBaseID

	// Candidate base id: explicit flag, else the catalog id when --candidate-base is one.
	candidateBaseID := appDiffBaseOpts.candidateBaseID
	if candidateBaseID == "" {
		if !strings.ContainsAny(appDiffBaseOpts.candidateBase, "/@:") {
			candidateBaseID = appDiffBaseOpts.candidateBase
		}
	}
	result.CandidateBase = appDiffBaseOpts.candidateBase

	// Compatibility gate.
	if candidateBaseID == "" {
		result.Compatible = false
		result.CompatReason = "candidate base id unknown (pass --candidate-base-id for a raw reference); cannot check runtime compatibility"
	} else {
		ok, reason := runtimeCompat(currentBaseID, candidateBaseID)
		result.Compatible = ok
		result.CompatReason = reason
	}

	// CVE delta from the catalog (offline). Computed only when both bases resolve.
	cur, curOK := baseSeverity(currentBaseID)
	cand, candOK := baseSeverity(candidateBaseID)
	if curOK && candOK {
		delta := sevCounts{
			Critical: cur.Critical - cand.Critical,
			High:     cur.High - cand.High,
			Medium:   cur.Medium - cand.Medium,
			Low:      cur.Low - cand.Low,
		}
		result.CurrentVulns = &cur
		result.CandidateVulns = &cand
		result.VulnDelta = &delta
		result.VulnDeltaComputed = true
	}

	if err := emitAppDiffBaseResult(result); err != nil {
		return err
	}
	if appDiffBaseOpts.failOnIncompat && !result.Compatible {
		return ErrCheckFailed
	}
	return nil
}

// baseSeverity returns the worst-arch severity counts for a base id's latest release.
func baseSeverity(baseID string) (sevCounts, bool) {
	if baseID == "" {
		return sevCounts{}, false
	}
	rec, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, baseID)
	if err != nil {
		return sevCounts{}, false
	}
	rel, err := latestOrTaggedRelease(rec.Releases, "")
	if err != nil {
		return sevCounts{}, false
	}
	var worst sevCounts
	found := false
	for _, arch := range rel.Architectures {
		if arch.Vulnerabilities == nil {
			continue
		}
		found = true
		c := arch.Vulnerabilities.CountsBySeverity
		if c.Critical > worst.Critical {
			worst.Critical = c.Critical
		}
		if c.High > worst.High {
			worst.High = c.High
		}
		if c.Medium > worst.Medium {
			worst.Medium = c.Medium
		}
		if c.Low > worst.Low {
			worst.Low = c.Low
		}
	}
	return worst, found
}

func emitAppDiffBaseResult(r AppDiffBaseResult) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, r)
	case "yaml", "yml":
		return output.PrintYAML(out, r)
	default:
		fmt.Fprintf(out, "Base rebase audit\n")
		if r.Image != "" {
			fmt.Fprintf(out, "  app image      : %s\n", r.Image)
			fmt.Fprintf(out, "  rebasable      : %t\n", r.Rebasable)
			if r.Boundary != "" {
				fmt.Fprintf(out, "  base boundary  : %s\n", truncateDigest(r.Boundary))
			}
		}
		fmt.Fprintf(out, "  current base   : %s\n", emptyDash(r.CurrentBase))
		fmt.Fprintf(out, "  candidate base : %s\n", r.CandidateBase)
		verdict := "INCOMPATIBLE"
		if r.Compatible {
			verdict = "COMPATIBLE"
		}
		fmt.Fprintf(out, "  compatibility  : %s (%s)\n", verdict, r.CompatReason)
		if r.VulnDeltaComputed {
			fmt.Fprintln(out, "  CVE delta (worst arch, current -> candidate):")
			tp := output.NewTablePrinter("SEVERITY", "CURRENT", "CANDIDATE", "DELTA")
			tp.AddRow("Critical", itoa(r.CurrentVulns.Critical), itoa(r.CandidateVulns.Critical), signed(r.VulnDelta.Critical))
			tp.AddRow("High", itoa(r.CurrentVulns.High), itoa(r.CandidateVulns.High), signed(r.VulnDelta.High))
			tp.AddRow("Medium", itoa(r.CurrentVulns.Medium), itoa(r.CandidateVulns.Medium), signed(r.VulnDelta.Medium))
			tp.AddRow("Low", itoa(r.CurrentVulns.Low), itoa(r.CandidateVulns.Low), signed(r.VulnDelta.Low))
			if err := tp.Print(out); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(out, "  CVE delta      : unavailable (one or both bases not in the catalog)")
		}
		return nil
	}
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// signed renders a delta where a positive number (CVEs removed by the candidate) is
// the desirable direction, so it is shown with an explicit sign.
func signed(n int) string {
	if n > 0 {
		return fmt.Sprintf("-%d", n) // current minus candidate > 0 means CVEs removed
	}
	if n < 0 {
		return fmt.Sprintf("+%d", -n)
	}
	return "0"
}
