package commands

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/spf13/cobra"
)

type graphBuildFlags struct {
	observations  string
	output        string
	report        string
	basePatterns  []string
	minConfidence string
	maxShared     int
	generatedAt   string
	failOnStale   bool
	failOnUnknown bool
	force         bool
}

var graphBuildOpts graphBuildFlags

// NewGraphCmd builds the `clearcutt-verify graph` command group.
func NewGraphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Map what an estate is built on, shares, and installs",
		Long: `Derive the base-image dependency graph for an observed estate.

Where 'rebase discover' checks a relationship someone declared, 'graph build'
discovers relationships nobody wrote down: it compares observed images and reports
which are built on which, how that was established, and how far behind each consumer
is from the newest version of its base.

Only layer-digest matching is proof. Label- and history-based matches are reported as
claims made by whoever built the image, and labelled as such.`,
	}
	cmd.AddCommand(newGraphBuildCmd())
	cmd.AddCommand(newGraphLayersCmd())
	cmd.AddCommand(newGraphPackagesCmd())
	return cmd
}

type graphLayersFlags struct {
	observations  string
	output        string
	report        string
	mermaid       string
	coverage      float64
	minSimilarity float64
	maxPairs      int
	generatedAt   string
	force         bool
}

var graphLayersOpts graphLayersFlags

func newGraphLayersCmd() *cobra.Command {
	graphLayersOpts = graphLayersFlags{}
	cmd := &cobra.Command{
		Use:   "layers",
		Short: "Show what the estate has in common at the layer level",
		Long: `Analyse content commonality across observed images.

Where 'graph build' asks what an image is built ON — a parentage question answered by
layer order — this asks what the fleet has IN COMMON, a content question answered by
layer membership. The two are independent: images can share nearly all their content
with no parentage between them, and a parent and child can share very little.

Reports the estate core, the most widely carried layers, content-identical images,
similarity clusters, per-image unique content, and how much storage layer reuse
saves. Shared content means shared exposure, never a base relationship.`,
		Args: cobra.NoArgs,
		Example: `  clearcutt-verify graph layers --observations observations.json \
    --output layers.json --report commonality.md

  # Only layers present in every image, and only near-identical pairs
  clearcutt-verify graph layers --observations observations.json --output layers.json \
    --coverage 1.0 --min-similarity 0.9`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGraphLayers()
		},
	}
	f := cmd.Flags()
	f.StringVar(&graphLayersOpts.observations, "observations", "observations.json", "Observations JSON from `clearcutt-verify import observe`")
	f.StringVar(&graphLayersOpts.output, "output", "", "Output layer graph JSON path")
	f.StringVar(&graphLayersOpts.report, "report", "", "Also write a Markdown commonality report to this path")
	f.StringVar(&graphLayersOpts.mermaid, "mermaid", "", "Also write the clustered commonality diagram to this path")
	f.Float64Var(&graphLayersOpts.coverage, "coverage", 0.75, "Fleet share a layer must reach to count as common (0-1)")
	f.Float64Var(&graphLayersOpts.minSimilarity, "min-similarity", 0.5, "Jaccard floor for reporting a pair and drawing a cluster edge (0-1)")
	f.IntVar(&graphLayersOpts.maxPairs, "max-pairs", 250, "Cap reported image pairs, most similar first (-1 keeps all)")
	f.StringVar(&graphLayersOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	f.BoolVar(&graphLayersOpts.force, "force", false, "Overwrite existing output files")
	return cmd
}

func runGraphLayers() error {
	opts := graphLayersOpts
	for _, path := range []string{opts.output, opts.report, opts.mermaid} {
		if path == "" || opts.force {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite", path)
		}
	}
	observations, err := estategraph.ReadObservations(opts.observations)
	if err != nil {
		return fmt.Errorf("read observations: %w", err)
	}
	graph, err := estategraph.BuildLayerGraph(observations, estategraph.LayerGraphOptions{
		GeneratedAt:       opts.generatedAt,
		CoverageThreshold: opts.coverage,
		MinSimilarity:     opts.minSimilarity,
		MaxPairs:          opts.maxPairs,
	})
	if err != nil {
		return err
	}
	if opts.output != "" {
		if err := writeAlongside(opts.output, func(path string) error {
			return estategraph.WriteLayerGraph(path, graph)
		}); err != nil {
			return err
		}
	}
	if opts.report != "" {
		if err := writeAlongside(opts.report, func(path string) error {
			return os.WriteFile(path, []byte(estategraph.LayerGraphMarkdown(graph)), 0o644)
		}); err != nil {
			return err
		}
	}
	if opts.mermaid != "" {
		diagram := estategraph.LayerGraphMermaid(graph)
		if diagram == "" {
			fmt.Fprintf(errOut, "[graph-layers] no diagram written: nothing reached the similarity threshold\n")
		} else if err := writeAlongside(opts.mermaid, func(path string) error {
			return os.WriteFile(path, []byte(diagram), 0o644)
		}); err != nil {
			return err
		}
	}

	if structuredFormat() {
		return printStructured(graph)
	}
	printLayerGraphSummary(graph, opts)
	return nil
}

// printLayerGraphSummary renders the terminal view of fleet commonality: what is
// shared, what is redundant, and what a fix to shared content would reach.
func printLayerGraphSummary(graph estategraph.LayerGraph, opts graphLayersFlags) {
	s := graph.Summary
	fmt.Fprintf(out, "[graph-layers] %d image(s), %d distinct layer(s): %d shared, %d unique to one image\n",
		s.Images, s.DistinctLayers, s.SharedLayers, s.UniqueLayers)
	fmt.Fprintf(out, "[graph-layers] estate core: %d layer(s) in every image; %d layer(s) in at least %.0f%%\n",
		s.CoreLayers, s.CommonLayers, s.CoverageThreshold*100)
	fmt.Fprintf(out, "[graph-layers] stored once %s vs %s without reuse — sharing avoids %.0f%%\n",
		humanSize(s.StoredBytes), humanSize(s.NaiveBytes), s.SharingRatio*100)

	if len(graph.Identical) > 0 {
		total := 0
		for _, group := range graph.Identical {
			total += len(group.Images)
		}
		fmt.Fprintf(out, "\n%d image(s) in %d group(s) carry byte-identical content:\n", total, len(graph.Identical))
		for _, group := range graph.Identical {
			fmt.Fprintf(out, "  %d layers, %s\n", group.LayerCount, humanSize(group.Bytes))
			for _, ref := range group.Images {
				fmt.Fprintf(out, "    %s\n", ref)
			}
		}
	}

	if len(graph.Common) > 0 {
		fmt.Fprintf(out, "\nMost widely carried layers:\n")
		fmt.Fprintf(out, "%-30s %8s %10s %9s\n", "LAYER", "IMAGES", "COVERAGE", "SIZE")
		for i, layer := range graph.Common {
			if i >= 5 {
				fmt.Fprintf(out, "... %d more (see the graph JSON or --report)\n", len(graph.Common)-5)
				break
			}
			fmt.Fprintf(out, "%-30s %8d %8.0f%% %9s\n", truncate(layer.Digest, 30), layer.ImageCount, layer.Coverage*100, humanSize(layer.Size))
		}
	}

	if len(graph.Clusters) > 0 {
		fmt.Fprintf(out, "\n%d cluster(s):\n", len(graph.Clusters))
		fmt.Fprintf(out, "%-9s %8s %26s %9s\n", "CLUSTER", "IMAGES", "LAYERS COMMON TO ALL", "SIZE")
		for _, cluster := range graph.Clusters {
			fmt.Fprintf(out, "%-9d %8d %26d %9s\n", cluster.ID, len(cluster.Images), cluster.SharedLayers, humanSize(cluster.SharedBytes))
		}
	}

	for _, warning := range graph.Warnings {
		fmt.Fprintf(errOut, "[graph-layers] %s\n", warning)
	}
	announceWritten(out, "graph-layers", opts.output, opts.report, opts.mermaid)
}

// humanSize formats a compressed byte count for terminal output.
func humanSize(size int64) string {
	switch {
	case size <= 0:
		return "0"
	case size < 1024*1024:
		return fmt.Sprintf("%.0fKB", float64(size)/1024)
	case size < 1024*1024*1024:
		return fmt.Sprintf("%.0fMB", float64(size)/(1024*1024))
	default:
		return fmt.Sprintf("%.1fGB", float64(size)/(1024*1024*1024))
	}
}

func newGraphBuildCmd() *cobra.Command {
	graphBuildOpts = graphBuildFlags{}
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the base-image dependency graph from observations",
		Args:  cobra.NoArgs,
		Example: `  # Full path from a registry to an auditable inventory
  clearcutt-verify registry scan --registry ghcr.io --namespace acme/platform \
    --repository base-java21 --repository payments --output images.yaml
  clearcutt-verify import observe --images images.yaml --output observations.json
  clearcutt-verify graph build --observations observations.json \
    --output graph.json --report inventory.md

  # Gate CI on proof, and fail when anything is on a stale base
  clearcutt-verify graph build --observations observations.json --output graph.json \
    --min-confidence verified --fail-on-stale`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGraphBuild()
		},
	}
	f := cmd.Flags()
	f.StringVar(&graphBuildOpts.observations, "observations", "observations.json", "Observations JSON from `clearcutt-verify import observe`")
	f.StringVar(&graphBuildOpts.output, "output", "", "Output graph JSON path")
	f.StringVar(&graphBuildOpts.report, "report", "", "Also write a Markdown governance inventory to this path")
	f.StringArrayVar(&graphBuildOpts.basePatterns, "base-repository", nil, "Only this repository glob may act as a base (repeatable; default: infer from layering)")
	f.StringVar(&graphBuildOpts.minConfidence, "min-confidence", "", "Drop edges weaker than this: verified, declared, assisted, weak")
	f.IntVar(&graphBuildOpts.maxShared, "max-shared-layers", 100, "Cap shared layers retained for blast-radius analysis, widest reach first (-1 keeps all)")
	f.StringVar(&graphBuildOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	f.BoolVar(&graphBuildOpts.failOnStale, "fail-on-stale", false, "Exit 2 when any consumer sits on a stale base version")
	f.BoolVar(&graphBuildOpts.failOnUnknown, "fail-on-unknown", false, "Exit 2 when any image's base could not be determined")
	f.BoolVar(&graphBuildOpts.force, "force", false, "Overwrite existing output files")
	return cmd
}

func runGraphBuild() error {
	opts := graphBuildOpts
	for _, path := range []string{opts.output, opts.report} {
		if path == "" || opts.force {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite", path)
		}
	}
	observations, err := estategraph.ReadObservations(opts.observations)
	if err != nil {
		return fmt.Errorf("read observations: %w", err)
	}
	graph, err := estategraph.BuildGraph(observations, estategraph.GraphOptions{
		GeneratedAt:     opts.generatedAt,
		BasePatterns:    opts.basePatterns,
		MinConfidence:   opts.minConfidence,
		MaxSharedLayers: opts.maxShared,
	})
	if err != nil {
		return err
	}
	if opts.output != "" {
		if err := writeAlongside(opts.output, func(path string) error {
			return estategraph.WriteGraph(path, graph)
		}); err != nil {
			return err
		}
	}
	if opts.report != "" {
		if err := writeAlongside(opts.report, func(path string) error {
			return os.WriteFile(path, []byte(estategraph.GraphMarkdown(graph)), 0o644)
		}); err != nil {
			return err
		}
	}

	if structuredFormat() {
		if err := printStructured(graph); err != nil {
			return err
		}
		return graphGateResult(graph, opts)
	}
	printGraphSummary(graph, opts)
	return graphGateResult(graph, opts)
}

// graphGateResult turns the requested gates into the shared check-failure sentinel so
// `graph build` can be used as a CI gate with the same exit-code contract as the
// other ClearCutt gates.
func graphGateResult(graph estategraph.Graph, opts graphBuildFlags) error {
	failures := []string{}
	if opts.failOnStale && graph.Summary.StaleConsumers > 0 {
		failures = append(failures, fmt.Sprintf("%d consumer(s) sit on a stale base version", graph.Summary.StaleConsumers))
	}
	if opts.failOnUnknown && graph.Summary.UnresolvedConsumers > 0 {
		failures = append(failures, fmt.Sprintf("%d image(s) have an undetermined base", graph.Summary.UnresolvedConsumers))
	}
	if len(failures) == 0 {
		return nil
	}
	for _, failure := range failures {
		fmt.Fprintf(errOut, "[graph] FAIL: %s\n", failure)
	}
	return ErrCheckFailed
}

// describeBuilders renders the builder mix most-common first, so an operator
// reads what actually produced their estate rather than an alphabetical list.
func describeBuilders(profile estategraph.BuilderProfile) string {
	type row struct {
		name  string
		count int
	}
	rows := make([]row, 0, len(profile.ByBuilder))
	for name, count := range profile.ByBuilder {
		rows = append(rows, row{name, count})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].name < rows[j].name
	})
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, fmt.Sprintf("%s x%d", r.name, r.count))
	}
	return strings.Join(parts, ", ")
}

// printGraphSummary renders the terminal pane of glass: what is stale, what is
// unknown, and how much of the graph rests on proof rather than on a label.
func printGraphSummary(graph estategraph.Graph, opts graphBuildFlags) {
	s := graph.Summary
	fmt.Fprintf(out, "[graph] %d image(s) observed: %d base famil(ies), %d consumer(s), %d root(s)\n",
		s.ObservedImages, s.BaseFamilies, s.Consumers, s.RootImages)
	fmt.Fprintf(out, "[graph] resolved %d consumer(s): %d on the current base, %d stale, %d undetermined\n",
		s.ResolvedConsumers, s.CurrentConsumers, s.StaleConsumers, s.UnresolvedConsumers)

	// How the estate was built decides what those numbers mean. On a Nix or
	// Wolfi estate zero resolved is the correct answer, not a coverage gap, and
	// an operator who is not told that will go looking for provenance that was
	// never there.
	if b := s.Builders; b.Stacking+b.Composed > 0 {
		fmt.Fprintf(out, "[graph] built by: %s (%d stacking, %d composed)\n",
			describeBuilders(b), b.Stacking, b.Composed)
	}
	if note := estategraph.ComposedEstateNote(s.Builders, s.ResolvedConsumers); note != "" {
		fmt.Fprintf(out, "\n[graph] %s\n\n", note)
	}

	proven := s.EdgesByConfidence["verified"]
	if s.ResolvedConsumers > 0 {
		fmt.Fprintf(out, "[graph] %d of %d relationship(s) are proven by layer digests; the rest rely on labels the image author supplied\n",
			proven, s.ResolvedConsumers)
	}

	if len(graph.Bases) > 0 {
		fmt.Fprintf(out, "\n%-44s %9s %10s %8s\n", "BASE REPOSITORY", "VERSIONS", "CONSUMERS", "STALE")
		for _, base := range graph.Bases {
			fmt.Fprintf(out, "%-44s %9d %10d %8d\n", truncate(base.Repository, 44), base.Versions, base.Consumers, base.StaleConsumers)
		}
	}

	stale := []estategraph.GraphEdge{}
	for _, edge := range graph.Edges {
		if edge.Drift == "stale" {
			stale = append(stale, edge)
		}
	}
	if len(stale) > 0 {
		sort.SliceStable(stale, func(i, j int) bool {
			if stale[i].VersionsBehind != stale[j].VersionsBehind {
				return stale[i].VersionsBehind > stale[j].VersionsBehind
			}
			return stale[i].ConsumerRef < stale[j].ConsumerRef
		})
		fmt.Fprintf(out, "\nStale consumers (rebase candidates):\n")
		fmt.Fprintf(out, "%-50s %-30s %8s %7s\n", "CONSUMER", "BASE", "BEHIND", "DAYS")
		for _, edge := range stale {
			fmt.Fprintf(out, "%-50s %-30s %8d %7d\n",
				truncate(edge.ConsumerRef, 50), truncate(edge.BaseRepository, 30), edge.VersionsBehind, edge.DaysBehind)
		}
	}

	if len(graph.SharedLayers) > 0 {
		fmt.Fprintf(out, "\nShared layers (blast radius): %d of %d distinct layers are in more than one image; the widest is in %d\n",
			s.SharedLayers, s.DistinctLayers, s.WidestLayerReach)
		fmt.Fprintf(out, "%-30s %8s\n", "LAYER", "IMAGES")
		for i, layer := range graph.SharedLayers {
			if i >= 5 {
				fmt.Fprintf(out, "... %d more (see the graph JSON or --report)\n", len(graph.SharedLayers)-5)
				break
			}
			fmt.Fprintf(out, "%-30s %8d\n", truncate(layer.Digest, 30), layer.ImageCount)
		}
	}

	if len(graph.Unresolved) > 0 {
		fmt.Fprintf(out, "\nBase could not be determined for %d image(s):\n", len(graph.Unresolved))
		for _, entry := range graph.Unresolved {
			fmt.Fprintf(out, "  %s\n    %s\n", entry.ConsumerRef, strings.Join(entry.Reasons, "; "))
		}
	}
	for _, warning := range graph.Warnings {
		fmt.Fprintf(errOut, "[graph] %s\n", warning)
	}
	announceWritten(out, "graph", opts.output, opts.report)
}

func truncate(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width <= 1 {
		return value[:width]
	}
	return "…" + value[len(value)-width+1:]
}

// announceWritten reports the artifacts a graph command actually wrote. Every
// output path is optional, so the leading blank line is emitted only if at
// least one of them was requested.
func announceWritten(w io.Writer, label string, paths ...string) {
	first := true
	for _, path := range paths {
		if path == "" {
			continue
		}
		if first {
			fmt.Fprintln(w)
			first = false
		}
		fmt.Fprintf(w, "[%s] wrote %s\n", label, path)
	}
}
