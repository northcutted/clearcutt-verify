package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type rebaseDiscoverFlags struct {
	apps         string
	bases        string
	observations string
	output       string
	generatedAt  string
}

type rebasePlanFlags struct {
	candidate    string
	candidates   string
	newBase      string
	observations string
	output       string
}

var rebaseDiscoverOpts rebaseDiscoverFlags
var rebasePlanOpts rebasePlanFlags

func NewRebaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rebase",
		Short: "Discover and plan estate app rebases",
		Long: `Discover and plan app image rebases across an estate. These commands
never publish images, mutate registry tags, or apply a rebase automatically.`,
	}
	cmd.AddCommand(newRebaseDiscoverCmd())
	cmd.AddCommand(newRebasePlanCmd())
	return cmd
}

func newRebaseDiscoverCmd() *cobra.Command {
	rebaseDiscoverOpts = rebaseDiscoverFlags{}
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover rebase candidates in an estate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRebaseDiscover()
		},
	}
	f := cmd.Flags()
	f.StringVar(&rebaseDiscoverOpts.apps, "apps", "", "App image inventory YAML")
	f.StringVar(&rebaseDiscoverOpts.bases, "bases", "", "Imported base images.yaml")
	f.StringVar(&rebaseDiscoverOpts.observations, "observations", "", "Imported observations.json")
	f.StringVar(&rebaseDiscoverOpts.output, "output", "", "Output candidates.json path")
	f.StringVar(&rebaseDiscoverOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	_ = cmd.MarkFlagRequired("apps")
	_ = cmd.MarkFlagRequired("bases")
	_ = cmd.MarkFlagRequired("observations")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runRebaseDiscover() error {
	apps, err := estategraph.ReadAppInventory(rebaseDiscoverOpts.apps)
	if err != nil {
		return err
	}
	bases, err := estategraph.ReadImagesFile(rebaseDiscoverOpts.bases)
	if err != nil {
		return err
	}
	observations, err := estategraph.ReadObservations(rebaseDiscoverOpts.observations)
	if err != nil {
		return err
	}
	candidates, err := estategraph.DiscoverRebaseCandidates(apps, bases, observations, rebaseDiscoverOpts.generatedAt)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rebaseDiscoverOpts.output), 0o755); err != nil {
		return err
	}
	if err := estategraph.WriteRebaseCandidates(rebaseDiscoverOpts.output, candidates); err != nil {
		return err
	}
	if strings.EqualFold(GlobalOpts.Format, "json") {
		return output.PrintJSON(out, candidates)
	}
	fmt.Fprintf(out, "[rebase-discover] wrote %d candidate(s) to %s\n", len(candidates.Candidates), rebaseDiscoverOpts.output)
	return nil
}

func newRebasePlanCmd() *cobra.Command {
	rebasePlanOpts = rebasePlanFlags{}
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Create an auditable estate rebase plan",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRebasePlan()
		},
	}
	f := cmd.Flags()
	f.StringVar(&rebasePlanOpts.candidate, "candidate", "", "Candidate app id")
	f.StringVar(&rebasePlanOpts.candidates, "candidates", "", "Rebase candidates JSON")
	f.StringVar(&rebasePlanOpts.newBase, "new-base", "", "Discovered new base id@sha256 digest")
	f.StringVar(&rebasePlanOpts.observations, "observations", "", "Imported observations.json")
	f.StringVar(&rebasePlanOpts.output, "output", "", "Output rebase plan JSON")
	_ = cmd.MarkFlagRequired("candidate")
	_ = cmd.MarkFlagRequired("candidates")
	_ = cmd.MarkFlagRequired("new-base")
	_ = cmd.MarkFlagRequired("observations")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runRebasePlan() error {
	candidates, err := estategraph.ReadRebaseCandidates(rebasePlanOpts.candidates)
	if err != nil {
		return err
	}
	observations, err := estategraph.ReadObservations(rebasePlanOpts.observations)
	if err != nil {
		return err
	}
	plan, err := estategraph.PlanRebase(candidates, rebasePlanOpts.candidate, rebasePlanOpts.newBase, observations)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rebasePlanOpts.output), 0o755); err != nil {
		return err
	}
	if err := estategraph.WriteRebasePlan(rebasePlanOpts.output, plan); err != nil {
		return err
	}
	if strings.EqualFold(GlobalOpts.Format, "json") {
		return output.PrintJSON(out, plan)
	}
	fmt.Fprintf(out, "[rebase-plan] wrote %s\n", rebasePlanOpts.output)
	return nil
}
