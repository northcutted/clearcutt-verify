package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/spf13/cobra"
)

type graphPackagesFlags struct {
	observations  string
	output        string
	generatedAt   string
	minSimilarity float64
	maxReach      int
	maxPairs      int
	fetchSBOMs    bool
	concurrency   int
	packageFilter string
}

var graphPackagesOpts graphPackagesFlags

func newGraphPackagesCmd() *cobra.Command {
	graphPackagesOpts = graphPackagesFlags{}
	cmd := &cobra.Command{
		Use:   "packages",
		Short: "Show what the estate installs, and which images share build inputs",
		Long: `Analyse an estate at the PACKAGE level.

This is the view that works for composed builders. Nix dockerTools and apko
(Wolfi, Chainguard) build from a package set rather than stacking on a base
image, so 'graph build' correctly finds no parentage — there is none. What those
estates have instead is shared build inputs, and that is what this measures.

It also answers the question a layer view cannot: when a CVE lands against a
named package at a named version, which images carry it.

COST: for Nix this is FREE. dockerTools records the store paths of every layer
in the image config, which is already fetched to observe the image at all — so
the exact package set, with content hashes, comes at no network cost.

Builders that leave no package trail in their config need an SBOM, which must be
fetched. That is opt-in via --fetch-sboms, and the command reports how many
requests it will make before making them.`,
		Args: cobra.NoArgs,
		Example: `  clearcutt-verify graph packages --observations observations.json --output packages.json

  # Which images carry a vulnerable package?
  clearcutt-verify graph packages --observations observations.json --package glibc`,
		RunE: func(_ *cobra.Command, _ []string) error { return runGraphPackages() },
	}
	f := cmd.Flags()
	f.StringVar(&graphPackagesOpts.observations, "observations", "observations.json", "Observations JSON to analyse")
	f.StringVar(&graphPackagesOpts.output, "output", "", "Write the package graph JSON here")
	f.StringVar(&graphPackagesOpts.generatedAt, "generated-at", "", "Deterministic generated timestamp")
	f.Float64Var(&graphPackagesOpts.minSimilarity, "min-similarity", 0, "Jaccard floor for reporting a lineage pair (0 applies the default)")
	f.IntVar(&graphPackagesOpts.maxReach, "max-reach", 0, "Cap reported packages, widest reach first")
	f.IntVar(&graphPackagesOpts.maxPairs, "max-pairs", 0, "Cap reported lineage pairs, closest first")
	f.StringVar(&graphPackagesOpts.packageFilter, "package", "", "Report only packages whose name contains this substring")
	f.BoolVar(&graphPackagesOpts.fetchSBOMs, "fetch-sboms", false, "Fetch attached SBOMs for images whose config records no package set. Costs network; the command reports how many requests first")
	f.IntVar(&graphPackagesOpts.concurrency, "concurrency", estategraph.DefaultObserveConcurrency, "SBOM fetches to run at once")
	return cmd
}

func runGraphPackages() error {
	observations, err := estategraph.ReadObservations(graphPackagesOpts.observations)
	if err != nil {
		return err
	}

	var sbomWarnings []string
	if graphPackagesOpts.fetchSBOMs {
		observations, sbomWarnings, err = fetchSBOMsWithWarning(observations)
		if err != nil {
			return err
		}
	} else if plan := estategraph.PlanSBOMFetch(observations); plan.Unresolved > 0 {
		// Say what is missing and what recovering it would cost, without doing
		// it. An operator should choose the network spend, not discover it.
		fmt.Fprintf(out, "[graph-packages] %d image(s) record no package set in their config.\n", plan.Unresolved)
		fmt.Fprintf(out, "[graph-packages] --fetch-sboms would recover them with %d registry fetch(es) (%d avoided by deduplicating identical content).\n",
			plan.Fetches, plan.Saved)
	}

	graph, err := estategraph.BuildPackageGraph(observations, estategraph.PackageGraphOptions{
		GeneratedAt:   graphPackagesOpts.generatedAt,
		MinSimilarity: graphPackagesOpts.minSimilarity,
		MaxReach:      graphPackagesOpts.maxReach,
		MaxPairs:      graphPackagesOpts.maxPairs,
	})
	if err != nil {
		return err
	}

	if path := strings.TrimSpace(graphPackagesOpts.output); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := estategraph.WritePackageGraph(path, graph); err != nil {
			return err
		}
	}
	graph.Warnings = append(sbomWarnings, graph.Warnings...)
	printPackageGraph(graph)
	if path := strings.TrimSpace(graphPackagesOpts.output); path != "" {
		fmt.Fprintf(out, "\n[graph-packages] wrote %s\n", path)
	}
	return nil
}

func printPackageGraph(graph estategraph.PackageGraph) {
	s := graph.Summary
	fmt.Fprintf(out, "[graph-packages] %d image(s): %d with a readable package set, %d unknown\n",
		s.Images, s.Resolved, s.Unresolved)
	if len(s.BySource) > 0 {
		parts := make([]string, 0, len(s.BySource))
		for source, count := range s.BySource {
			parts = append(parts, fmt.Sprintf("%s x%d", source, count))
		}
		sort.Strings(parts)
		fmt.Fprintf(out, "[graph-packages] evidence: %s\n", strings.Join(parts, ", "))
	}
	fmt.Fprintf(out, "[graph-packages] %d distinct package(s), %d carried by more than one image; the widest is in %d\n",
		s.DistinctPackages, s.SharedPackages, s.WidestReach)

	filter := strings.ToLower(strings.TrimSpace(graphPackagesOpts.packageFilter))
	rows := graph.Reach
	if filter != "" {
		matched := rows[:0:0]
		for _, r := range rows {
			if strings.Contains(strings.ToLower(r.Package.Name), filter) {
				matched = append(matched, r)
			}
		}
		rows = matched
		fmt.Fprintf(out, "[graph-packages] %d package(s) match %q\n", len(rows), graphPackagesOpts.packageFilter)
	}
	if len(rows) > 0 {
		limit := len(rows)
		if filter == "" && limit > 12 {
			limit = 12
		}
		fmt.Fprintf(out, "\n%-34s %-18s %8s\n", "PACKAGE", "VERSION", "IMAGES")
		for _, r := range rows[:limit] {
			fmt.Fprintf(out, "%-34s %-18s %8d\n", truncate(r.Package.Name, 34), truncate(r.Package.Version, 18), r.Count)
		}
		if limit < len(rows) {
			fmt.Fprintf(out, "... %d more (see the package graph JSON)\n", len(rows)-limit)
		}
	}
	// When a filter matched, name the images: that is the CVE-response question.
	if filter != "" && len(rows) > 0 {
		fmt.Fprintf(out, "\nImages carrying %q:\n", graphPackagesOpts.packageFilter)
		shown := 0
		for _, r := range rows {
			for _, image := range r.Images {
				if shown >= 20 {
					break
				}
				fmt.Fprintf(out, "  %s %s  %s\n", r.Package.Name, r.Package.Version, image)
				shown++
			}
		}
		if shown >= 20 {
			fmt.Fprintln(out, "  ... truncated; see the package graph JSON for the full list")
		}
	}
	for _, warning := range graph.Warnings {
		fmt.Fprintf(out, "\n[graph-packages] %s\n", warning)
	}
}

// fetchSBOMsWithWarning performs the expensive path, after telling the operator
// exactly what it will cost.
//
// The estimate is printed BEFORE the fetches run, and reports what
// deduplication saves. An estate re-tags the same content on every release, so
// the number of distinct images is usually far below the number of tags — the
// difference between those two numbers is the reason this is affordable at all.
func fetchSBOMsWithWarning(observations estategraph.Observations) (estategraph.Observations, []string, error) {
	plan := estategraph.PlanSBOMFetch(observations)
	if plan.Fetches == 0 {
		fmt.Fprintln(out, "[graph-packages] every image already records a package set; no SBOM fetch needed")
		return observations, nil, nil
	}
	fmt.Fprintf(errOut, "[graph-packages] WARNING: fetching SBOMs for %d image(s) with no package set in their config.\n", plan.Unresolved)
	fmt.Fprintf(errOut, "[graph-packages] WARNING: this makes %d registry request(s) at concurrency %d; %d fetch(es) avoided by deduplicating identical content.\n",
		plan.Fetches, graphPackagesOpts.concurrency, plan.Saved)
	fmt.Fprintf(errOut, "[graph-packages] WARNING: large estates can hit registry rate limits. Nix images need none of this — their package set is already in the config.\n")

	fetcher := estategraph.SBOMFetcher(estategraph.NewRegistrySBOMFetcher())
	if sbomFetcherOverride != nil {
		fetcher = sbomFetcherOverride
	}
	return estategraph.EnrichWithSBOMs(context.Background(), observations, fetcher, graphPackagesOpts.concurrency)
}

// sbomFetcherOverride lets tests exercise the expensive path without a registry.
var sbomFetcherOverride estategraph.SBOMFetcher
