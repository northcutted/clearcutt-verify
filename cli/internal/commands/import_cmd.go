package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type importImagesFlags struct {
	refs             string
	output           string
	owner            string
	repo             string
	registryBase     string
	defaultTier      string
	defaultLifecycle string
	generatedAt      string
	force            bool
}

type importObserveFlags struct {
	images          string
	output          string
	offlineFixtures string
	generatedAt     string
	strict          bool
	concurrency     int
	since           string
}

type importAssessFlags struct {
	images       string
	observations string
	output       string
	generatedAt  string
}

type importReportFlags struct {
	assessment string
	output     string
}

var importImagesOpts importImagesFlags
var importObserveOpts importObserveFlags
var importAssessOpts importAssessFlags
var importReportOpts importReportFlags

func NewImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import external OCI refs and observe them without inferring trust",
		Long: `Import existing OCI image references into ClearCutt-compatible catalog
inventories, observe available metadata, assess governance gaps, and generate
deterministic reports without claiming ClearCutt build provenance.`,
	}
	cmd.AddCommand(newImportImagesCmd())
	cmd.AddCommand(newImportObserveCmd())
	cmd.AddCommand(newImportAssessCmd())
	cmd.AddCommand(newImportReportCmd())
	return cmd
}

func newImportImagesCmd() *cobra.Command {
	importImagesOpts = importImagesFlags{defaultTier: "slim", defaultLifecycle: "active"}
	cmd := &cobra.Command{
		Use:   "images",
		Short: "Convert OCI refs into a generic ClearCutt images.yaml",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImportImages()
		},
	}
	f := cmd.Flags()
	f.StringVar(&importImagesOpts.refs, "refs", "", "Path to newline-delimited OCI image refs")
	f.StringVar(&importImagesOpts.output, "output", "", "Output images.yaml path")
	f.StringVar(&importImagesOpts.owner, "owner", "", "Estate owner label")
	f.StringVar(&importImagesOpts.repo, "repo", "", "Estate repo label")
	f.StringVar(&importImagesOpts.registryBase, "registry-base", "", "Registry namespace for generated catalog examples")
	f.StringVar(&importImagesOpts.defaultTier, "default-tier", "slim", "Default tier for imported images")
	f.StringVar(&importImagesOpts.defaultLifecycle, "default-lifecycle", "active", "Default lifecycle status for imported images")
	f.StringVar(&importImagesOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	f.BoolVar(&importImagesOpts.force, "force", false, "Overwrite an existing output file")
	_ = cmd.MarkFlagRequired("refs")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runImportImages() error {
	if !importImagesOpts.force {
		if _, err := os.Stat(importImagesOpts.output); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite", importImagesOpts.output)
		}
	}
	inventory, summary, err := estategraph.ImportRefs(estategraph.ImportOptions{
		RefsPath:         importImagesOpts.refs,
		Owner:            importImagesOpts.owner,
		Repo:             importImagesOpts.repo,
		RegistryBase:     importImagesOpts.registryBase,
		DefaultTier:      importImagesOpts.defaultTier,
		DefaultLifecycle: importImagesOpts.defaultLifecycle,
		GeneratedAt:      importImagesOpts.generatedAt,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(importImagesOpts.output), 0o755); err != nil {
		return err
	}
	if err := estategraph.WriteImagesFile(importImagesOpts.output, inventory); err != nil {
		return err
	}
	summary.Output = importImagesOpts.output
	if strings.EqualFold(GlobalOpts.Format, "json") {
		return output.PrintJSON(out, summary)
	}
	fmt.Fprintf(out, "[import-images] wrote %d imported image(s) to %s\n", summary.ImageCount, importImagesOpts.output)
	if summary.LowConfidence > 0 {
		fmt.Fprintf(out, "[import-images] %d image(s) need classification review\n", summary.LowConfidence)
	}
	return nil
}

func newImportObserveCmd() *cobra.Command {
	importObserveOpts = importObserveFlags{}
	cmd := &cobra.Command{
		Use:   "observe",
		Short: "Observe imported image metadata without inferring provenance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImportObserve(cmd.Context())
		},
	}
	f := cmd.Flags()
	f.StringVar(&importObserveOpts.images, "images", "", "Estate images.yaml inventory")
	f.StringVar(&importObserveOpts.output, "output", "", "Output observations.json path")
	f.StringVar(&importObserveOpts.offlineFixtures, "offline-fixtures", "", "Offline observations fixture JSON")
	f.IntVar(&importObserveOpts.concurrency, "concurrency", estategraph.DefaultObserveConcurrency, "Images to observe at once; 1 forces serial")
	f.StringVar(&importObserveOpts.since, "since", "", "Previous observations.json; images whose manifest digest is unchanged are carried forward after one HEAD instead of being re-read")
	f.StringVar(&importObserveOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	f.BoolVar(&importObserveOpts.strict, "strict", false, "Fail the command when any image cannot be observed")
	_ = cmd.MarkFlagRequired("images")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runImportObserve(ctx context.Context) error {
	inventory, err := estategraph.ReadImagesFile(importObserveOpts.images)
	if err != nil {
		return fmt.Errorf("read images inventory: %w", err)
	}
	var observer estategraph.ImageObserver = estategraph.RegistryObserver{}
	var fixtureObservations *estategraph.Observations
	if importObserveOpts.offlineFixtures != "" {
		fixtures, err := estategraph.ReadObservations(importObserveOpts.offlineFixtures)
		if err != nil {
			return fmt.Errorf("read offline fixtures: %w", err)
		}
		fixtureObservations = &fixtures
		observer = estategraph.NewFixtureObserver(fixtures)
	}
	// Carrying a prior observation set forward turns an unchanged image from a
	// full read into a single HEAD. On a large estate where a handful of images
	// move per day, that is most of the scan.
	var previous *estategraph.Observations
	if path := strings.TrimSpace(importObserveOpts.since); path != "" {
		prior, err := estategraph.ReadObservations(path)
		if err != nil {
			return fmt.Errorf("reading previous observations from %s: %w", path, err)
		}
		previous = &prior
	}
	observations, stats, err := estategraph.ObserveImages(ctx, inventory, observer, estategraph.ObserveOptions{
		GeneratedAt: importObserveOpts.generatedAt,
		Strict:      importObserveOpts.strict,
		Concurrency: importObserveOpts.concurrency,
		Previous:    previous,
	})
	if err != nil {
		return err
	}
	if stats.Reused > 0 {
		fmt.Fprintf(out, "[import-observe] reused %d unchanged observation(s), read %d, failed %d\n",
			stats.Reused, stats.Observed, stats.Failed)
	}
	if fixtureObservations != nil {
		observations = mergeExtraFixtureObservations(observations, *fixtureObservations)
	}
	if err := os.MkdirAll(filepath.Dir(importObserveOpts.output), 0o755); err != nil {
		return err
	}
	if err := estategraph.WriteObservations(importObserveOpts.output, observations); err != nil {
		return err
	}
	if strings.EqualFold(GlobalOpts.Format, "json") {
		return output.PrintJSON(out, observations)
	}
	fmt.Fprintf(out, "[import-observe] wrote observations for %d image(s) to %s\n", len(observations.Images), importObserveOpts.output)
	return nil
}

func newImportAssessCmd() *cobra.Command {
	importAssessOpts = importAssessFlags{}
	cmd := &cobra.Command{
		Use:   "assess",
		Short: "Assess estate evidence and runtime governance gaps",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImportAssess()
		},
	}
	f := cmd.Flags()
	f.StringVar(&importAssessOpts.images, "images", "", "Estate images.yaml inventory")
	f.StringVar(&importAssessOpts.observations, "observations", "", "Imported observations.json")
	f.StringVar(&importAssessOpts.output, "output", "", "Output governance directory")
	f.StringVar(&importAssessOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	_ = cmd.MarkFlagRequired("images")
	_ = cmd.MarkFlagRequired("observations")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runImportAssess() error {
	inventory, err := estategraph.ReadImagesFile(importAssessOpts.images)
	if err != nil {
		return err
	}
	observations, err := estategraph.ReadObservations(importAssessOpts.observations)
	if err != nil {
		return err
	}
	assessment, err := estategraph.Assess(inventory, observations, estategraph.AssessOptions{GeneratedAt: importAssessOpts.generatedAt})
	if err != nil {
		return err
	}
	if err := estategraph.WriteAssessmentDir(importAssessOpts.output, assessment); err != nil {
		return err
	}
	if strings.EqualFold(GlobalOpts.Format, "json") {
		return output.PrintJSON(out, assessment)
	}
	fmt.Fprintf(out, "[import-assess] wrote imported fleet governance report to %s\n", importAssessOpts.output)
	return nil
}

func newImportReportCmd() *cobra.Command {
	importReportOpts = importReportFlags{}
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render a deterministic estate report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImportReport()
		},
	}
	f := cmd.Flags()
	f.StringVar(&importReportOpts.assessment, "assessment", "", "Assessment output directory")
	f.StringVar(&importReportOpts.output, "output", "", "Output markdown report path")
	_ = cmd.MarkFlagRequired("assessment")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runImportReport() error {
	assessment, err := estategraph.ReadAssessmentDir(importReportOpts.assessment)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(importReportOpts.output), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(importReportOpts.output, []byte(estategraph.ReportMarkdown(assessment)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "[import-report] wrote %s\n", importReportOpts.output)
	return nil
}

func mergeExtraFixtureObservations(observed estategraph.Observations, fixtures estategraph.Observations) estategraph.Observations {
	seen := map[string]bool{}
	for _, obs := range observed.Images {
		if obs.ID != "" {
			seen["id:"+obs.ID] = true
		}
		if obs.SourceRef != "" {
			seen["source:"+obs.SourceRef] = true
		}
	}
	for _, obs := range fixtures.Images {
		if obs.ID != "" && seen["id:"+obs.ID] {
			continue
		}
		if obs.SourceRef != "" && seen["source:"+obs.SourceRef] {
			continue
		}
		observed.Images = append(observed.Images, obs)
	}
	sort.SliceStable(observed.Images, func(i, j int) bool { return observed.Images[i].ID < observed.Images[j].ID })
	return observed
}
