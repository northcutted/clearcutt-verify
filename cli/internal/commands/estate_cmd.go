package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/estate"
	"github.com/spf13/cobra"
)

type estateFlags struct {
	dir         string
	files       []string
	generatedAt string
	insecure    bool
	output      string
	history     string
}

var estateOpts estateFlags

// estateDefaultFiles are the artifacts a governance snapshot is made of. They
// are the outputs of `import observe`, `graph build` and `graph layers`.
var estateDefaultFiles = []string{"observations.json", "graph.json", "layers.json"}

// NewEstateCmd builds the `clearcutt-verify estate` command group: verify an
// estate and write its report, persist a snapshot or report to a registry,
// and read one back.
func NewEstateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "estate",
		Short: "Verify an estate, and keep its reports and snapshots in a registry",
		Long: `Verify every image in an estate and write the estate report (estate verify),
and store reports or governance snapshots (observations, base graph, layer
graph) in a registry as OCI artifacts (estate push, pull, history).

The registry is a deliberate backing store, not a convenient one. The evidence
lives under the same auth boundary, replication and retention as the images it
describes; digests make each snapshot immutable; tags give history, so estate
drift is a diff between two tags; and a mirror carries its own evidence into an
air gap. Nothing new has to be operated.

Snapshots are deterministic: identical inputs produce an identical digest, so a
nightly push of an unchanged estate does not create a new version.`,
	}
	cmd.AddCommand(newEstateVerifyCmd(), newEstatePushCmd(), newEstatePullCmd(), newEstateHistoryCmd())
	return cmd
}

func newEstatePushCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push <reference>",
		Short: "Push an estate snapshot to a registry as an OCI artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEstatePush(args[0])
		},
	}
	cmd.Flags().StringVar(&estateOpts.dir, "dir", ".", "Directory holding the snapshot files")
	cmd.Flags().StringSliceVar(&estateOpts.files, "file", nil, "Snapshot file(s) to store (default: observations.json, graph.json, layers.json)")
	cmd.Flags().StringVar(&estateOpts.generatedAt, "generated-at", "", "Snapshot timestamp recorded as a manifest annotation")
	cmd.Flags().BoolVar(&estateOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	cmd.Flags().StringVar(&estateOpts.history, "history", "", "Also append this snapshot to a history index at this reference (e.g. ghcr.io/acme/estate:history)")
	return cmd
}

func newEstatePullCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull <reference>",
		Short: "Pull an estate snapshot out of a registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEstatePull(args[0])
		},
	}
	cmd.Flags().StringVar(&estateOpts.output, "output", ".", "Directory to write the snapshot files into")
	cmd.Flags().BoolVar(&estateOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	return cmd
}

func estateClient() *estate.Client {
	if estateOpts.insecure {
		return estate.NewInsecureClient()
	}
	// Prefer explicit credentials from the environment, then fall back to the
	// ambient keychain. A CI runner has REGISTRY_TOKEN or GITHUB_TOKEN and no
	// docker config; a developer laptop has the reverse. Resolving in this order
	// means the same command works in both without a flag.
	if user, token := registryDestCredentialPair(); user != "" && token != "" {
		return estate.NewBasicAuthClient(user, token)
	}
	return estate.NewClient()
}

func runEstatePush(ref string) error {
	wanted := nonEmptyStrings(estateOpts.files)
	if len(wanted) == 0 {
		wanted = estateDefaultFiles
	}
	snapshot := estate.Snapshot{
		GeneratedAt: strings.TrimSpace(estateOpts.generatedAt),
		Files:       map[string][]byte{},
	}
	var missing []string
	for _, fileName := range wanted {
		path := fileName
		if !filepath.IsAbs(path) {
			path = filepath.Join(estateOpts.dir, fileName)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) && len(estateOpts.files) == 0 {
				// Defaults are a convenience, not a contract: a fleet that has
				// not run `graph layers` yet should still be able to push what
				// it does have. An explicitly requested file is different — the
				// operator asked for it by name, so its absence is an error.
				missing = append(missing, fileName)
				continue
			}
			return fmt.Errorf("reading estate file %s: %w", path, err)
		}
		snapshot.Files[filepath.Base(fileName)] = body
	}
	if len(snapshot.Files) == 0 {
		return fmt.Errorf("no estate files found in %s (looked for %s); run `clearcutt-verify import observe` and `clearcutt-verify graph build` first",
			estateOpts.dir, strings.Join(wanted, ", "))
	}
	for _, fileName := range missing {
		fmt.Fprintf(out, "[estate] %s not present; pushing without it\n", fileName)
	}

	digest, historyDigest, err := estateClient().PushSnapshot(ref, estateOpts.history, snapshot)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(snapshot.Files))
	for fileName := range snapshot.Files {
		names = append(names, fileName)
	}
	sort.Strings(names)
	fmt.Fprintf(out, "[estate] pushed %d file(s) to %s\n", len(names), ref)
	for _, fileName := range names {
		fmt.Fprintf(out, "[estate]   %s (%d bytes)\n", fileName, len(snapshot.Files[fileName]))
	}
	fmt.Fprintf(out, "[estate] digest %s\n", digest)
	fmt.Fprintf(out, "[estate] this digest is stable for identical content, so an unchanged estate re-pushes to the same version\n")
	if historyDigest != "" {
		metrics := estate.ExtractMetrics(snapshot)
		fmt.Fprintf(out, "[estate] appended to history %s (%s)\n", estateOpts.history, historyDigest)
		fmt.Fprintf(out, "[estate]   %s\n", metrics)
	}
	return nil
}

func newEstateHistoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history <reference>",
		Short: "Show how an estate changed over time",
		Long: `Read a history index and print the trend.

Reading a trend costs one manifest fetch regardless of how long the series is:
each run's metrics are carried in the index annotations, so no snapshot blobs
are pulled. Pull an individual snapshot by digest to drill into a date.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEstateHistory(args[0])
		},
	}
	cmd.Flags().BoolVar(&estateOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	return cmd
}

func runEstateHistory(ref string) error {
	history, err := estateClient().ReadHistory(ref)
	if err != nil {
		return err
	}
	if len(history.Entries) == 0 {
		fmt.Fprintf(out, "[estate] %s holds no snapshots yet\n", ref)
		return nil
	}
	if strings.EqualFold(GlobalOpts.Format, "json") {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(history)
	}

	fmt.Fprintf(out, "%-22s  %6s  %8s  %6s  %6s  %8s\n", "GENERATED", "IMAGES", "RESOLVED", "PROVEN", "STALE", "COVERAGE")
	for _, entry := range history.Entries {
		generated := entry.GeneratedAt
		if generated == "" {
			generated = "(untimed)"
		}
		if len(generated) > 22 {
			generated = generated[:22]
		}
		fmt.Fprintf(out, "%-22s  %6d  %8d  %6d  %6d  %7.0f%%\n",
			generated, entry.Metrics.Images, entry.Metrics.Resolved, entry.Metrics.Proven,
			entry.Metrics.Stale, entry.Metrics.Coverage()*100)
	}

	first, last, ok := history.Delta()
	if !ok {
		fmt.Fprintf(out, "\n[estate] one snapshot so far; a trend needs at least two\n")
		return nil
	}
	fmt.Fprintf(out, "\n[estate] over %d snapshots:\n", len(history.Entries))
	trend := func(label string, from, to int, higherIsBetter bool) {
		delta := to - from
		direction := "unchanged"
		switch {
		case delta > 0 && higherIsBetter, delta < 0 && !higherIsBetter:
			direction = "improved"
		case delta != 0:
			direction = "regressed"
		}
		fmt.Fprintf(out, "[estate]   %-24s %4d -> %-4d  %+d (%s)\n", label, from, to, delta, direction)
	}
	trend("images observed", first.Metrics.Images, last.Metrics.Images, true)
	trend("provenance resolved", first.Metrics.Resolved, last.Metrics.Resolved, true)
	trend("proven by layer digests", first.Metrics.Proven, last.Metrics.Proven, true)
	trend("stale consumers", first.Metrics.Stale, last.Metrics.Stale, false)
	fmt.Fprintf(out, "[estate]   %-24s %3.0f%% -> %.0f%%\n", "proof share of resolved",
		first.Metrics.ProvenShare()*100, last.Metrics.ProvenShare()*100)
	return nil
}

func runEstatePull(ref string) error {
	snapshot, digest, err := estateClient().Pull(ref)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(estateOpts.output, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(snapshot.Files))
	for fileName := range snapshot.Files {
		names = append(names, fileName)
	}
	sort.Strings(names)
	for _, fileName := range names {
		// The file name comes off a registry annotation, which is attacker
		// controllable. Take only the base name so a crafted artifact cannot
		// write outside the output directory.
		safe := filepath.Base(filepath.Clean(fileName))
		if safe == "." || safe == string(filepath.Separator) || safe == ".." {
			return fmt.Errorf("estate artifact contains an unusable file name %q", fileName)
		}
		path := filepath.Join(estateOpts.output, safe)
		if err := os.WriteFile(path, snapshot.Files[fileName], 0o644); err != nil {
			return err
		}
		fmt.Fprintf(out, "[estate] wrote %s (%d bytes)\n", path, len(snapshot.Files[fileName]))
	}
	if snapshot.GeneratedAt != "" {
		fmt.Fprintf(out, "[estate] snapshot generated at %s\n", snapshot.GeneratedAt)
	}
	fmt.Fprintf(out, "[estate] pulled %s\n", digest)
	return nil
}
