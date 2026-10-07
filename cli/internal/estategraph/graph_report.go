package estategraph

import (
	"fmt"
	"sort"
	"strings"
)

// GraphMarkdown renders a base-image dependency graph as an audit-ready report.
//
// The ordering is deliberate: an auditor is asked to accept a claim about what runs
// on what, so the report states how each claim was established before it states any
// conclusions. Proven edges and self-reported edges are never mixed into one number.
func GraphMarkdown(graph Graph) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Base Image Governance Inventory\n\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", graph.GeneratedAt)

	fmt.Fprintf(&b, "## Executive summary\n\n")
	fmt.Fprintf(&b, "| Metric | Count |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Images observed | %d |\n", graph.Summary.ObservedImages)
	fmt.Fprintf(&b, "| Base families | %d |\n", graph.Summary.BaseFamilies)
	fmt.Fprintf(&b, "| Root images (no parent) | %d |\n", graph.Summary.RootImages)
	fmt.Fprintf(&b, "| Consumers with a resolved base | %d |\n", graph.Summary.ResolvedConsumers)
	fmt.Fprintf(&b, "| Consumers on the current base | %d |\n", graph.Summary.CurrentConsumers)
	fmt.Fprintf(&b, "| Consumers on a stale base | %d |\n", graph.Summary.StaleConsumers)
	fmt.Fprintf(&b, "| Consumers whose base is unknown | %d |\n", graph.Summary.UnresolvedConsumers)
	fmt.Fprintf(&b, "| Distinct layers | %d |\n", graph.Summary.DistinctLayers)
	fmt.Fprintf(&b, "| Layers shared by more than one image | %d |\n", graph.Summary.SharedLayers)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## How each relationship was established\n\n")
	fmt.Fprintf(&b, "Only `layer-prefix` is proof. It compares layer digests, so it holds regardless of what an image claims about itself. Every other method reads a label or a build record that the image's own author wrote, and is reported as a claim.\n\n")
	fmt.Fprintf(&b, "| Method | Edges | Strength | What it means |\n|---|---:|---|---|\n")
	for _, method := range []struct{ id, strength, meaning string }{
		{MethodLayerPrefix, "proof", "The consumer's leading layer digests are the base's layers."},
		{MethodOCIBaseDigest, "declared", "`org.opencontainers.image.base.digest` names this base. Exact but self-reported."},
		{MethodBuildpacksMetadata, "declared", "Buildpacks lifecycle metadata names this run image. Exact but self-reported."},
		{MethodOCIBaseName, "assisted", "`org.opencontainers.image.base.name` names the repository but not a version."},
		{MethodHistory, "weak", "The base repository appears in the consumer's build history."},
	} {
		fmt.Fprintf(&b, "| `%s` | %d | %s | %s |\n", method.id, graph.Summary.EdgesByMethod[method.id], method.strength, method.meaning)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## Base families\n\n")
	if len(graph.Bases) == 0 {
		fmt.Fprintf(&b, "No base family had an observed consumer.\n\n")
	} else {
		fmt.Fprintf(&b, "| Base repository | Versions | Current version | Consumers | On a stale version |\n|---|---:|---|---:|---:|\n")
		for _, base := range graph.Bases {
			fmt.Fprintf(&b, "| `%s` | %d | `%s` | %d | %d |\n",
				base.Repository, base.Versions, tagOf(base.CurrentRef), base.Consumers, base.StaleConsumers)
		}
		fmt.Fprintf(&b, "\n")
		for _, base := range graph.Bases {
			for _, warning := range base.Warnings {
				fmt.Fprintf(&b, "- `%s`: %s\n", base.Repository, warning)
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Consumers on a stale base\n\n")
	stale := filterEdges(graph.Edges, func(e GraphEdge) bool { return e.Drift == DriftStale })
	if len(stale) == 0 {
		fmt.Fprintf(&b, "Every consumer with a resolved base is on that base's current version.\n\n")
	} else {
		fmt.Fprintf(&b, "These are the rebase candidates. Versions and days behind are measured against the newest observed version of the same base repository.\n\n")
		fmt.Fprintf(&b, "| Consumer | Base repository | On version | Current version | Versions behind | Days behind | Established by |\n|---|---|---|---|---:|---:|---|\n")
		for _, edge := range stale {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %d | %d | `%s` |\n",
				edge.ConsumerRef, edge.BaseRepository, tagOf(edge.BaseRef), tagOf(edge.CurrentBaseRef),
				edge.VersionsBehind, edge.DaysBehind, edge.Method)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Full relationship inventory\n\n")
	if len(graph.Edges) == 0 {
		fmt.Fprintf(&b, "No base relationships were detected.\n\n")
	} else {
		fmt.Fprintf(&b, "| Consumer | Base | Established by | Confidence | Drift |\n|---|---|---|---|---|\n")
		for _, edge := range graph.Edges {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s | %s |\n",
				edge.ConsumerRef, edge.BaseRef, edge.Method, edge.Confidence, edge.Drift)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Root images\n\n")
	if len(graph.Roots) == 0 {
		fmt.Fprintf(&b, "No root images were identified.\n\n")
	} else {
		fmt.Fprintf(&b, "Images with no parent of their own. These are the top of the supply chain, not gaps in it.\n\n")
		fmt.Fprintf(&b, "| Image | Consumers | Why it is a root |\n|---|---:|---|\n")
		for _, root := range graph.Roots {
			fmt.Fprintf(&b, "| `%s` | %d | %s |\n", root.ImageRef, root.Consumers, root.Reason)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Shared layer blast radius\n\n")
	if len(graph.SharedLayers) == 0 {
		fmt.Fprintf(&b, "No layer is carried by more than one observed image.\n\n")
	} else {
		fmt.Fprintf(&b, "Images can share content without one being built on the other. This table answers the remediation question directly: if a layer carries a vulnerable package, these are the images that ship it.\n\n")
		fmt.Fprintf(&b, "The widest-reaching layer is in %d of %d observed images.\n\n", graph.Summary.WidestLayerReach, graph.Summary.ObservedImages)
		fmt.Fprintf(&b, "| Layer | Images | Carried by |\n|---|---:|---|\n")
		shown := graph.SharedLayers
		const maxRows = 25
		truncated := 0
		if len(shown) > maxRows {
			truncated = len(shown) - maxRows
			shown = shown[:maxRows]
		}
		for _, layer := range shown {
			fmt.Fprintf(&b, "| `%s` | %d | %s |\n", shortDigest(layer.Digest), layer.ImageCount, summariseImages(layer.Images))
		}
		fmt.Fprintf(&b, "\n")
		if truncated > 0 {
			fmt.Fprintf(&b, "%d further shared layer(s) are recorded in the graph JSON but not listed here.\n\n", truncated)
		}
	}

	fmt.Fprintf(&b, "## Images whose base could not be determined\n\n")
	if len(graph.Unresolved) == 0 {
		fmt.Fprintf(&b, "Every observed image was either placed in the graph or identified as a root.\n\n")
	} else {
		fmt.Fprintf(&b, "These are audit findings, not omissions. ClearCutt could not establish what these images are built on from the evidence available.\n\n")
		fmt.Fprintf(&b, "| Image | Why |\n|---|---|\n")
		for _, entry := range graph.Unresolved {
			fmt.Fprintf(&b, "| `%s` | %s |\n", entry.ConsumerRef, strings.Join(entry.Reasons, "; "))
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## What this report does not prove\n\n")
	fmt.Fprintf(&b, "- A `layer-prefix` edge proves the consumer contains the base's layers. It does not prove the base was the one intended, nor that either image is signed, scanned, or fit for production.\n")
	fmt.Fprintf(&b, "- A `declared`, `assisted`, or `weak` edge rests on metadata the image's author supplied. Treat it as a claim to verify, not a finding.\n")
	fmt.Fprintf(&b, "- Currency is measured against the newest version observed **in this scan**, not against upstream. A base family that is itself out of date will still report its consumers as current.\n")
	fmt.Fprintf(&b, "- A shared layer means shared content, not a base relationship. Two sibling images built from the same recipe share layers while neither is built on the other.\n")
	fmt.Fprintf(&b, "- No CVE, signature, SBOM, or provenance conclusion is drawn here. Run `clearcutt-verify import assess` for the evidence-gap view.\n\n")

	if len(graph.Warnings) > 0 {
		fmt.Fprintf(&b, "## Scan warnings\n\n")
		for _, warning := range graph.Warnings {
			fmt.Fprintf(&b, "- %s\n", warning)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Reproduce this report\n\n")
	fmt.Fprintf(&b, "```bash\nclearcutt registry scan --registry <host> --namespace <namespace> --output images.yaml\nclearcutt import observe --images images.yaml --output observations.json\nclearcutt graph build --observations observations.json --output graph.json --report graph.md\n```\n")
	return b.String()
}

func filterEdges(edges []GraphEdge, keep func(GraphEdge) bool) []GraphEdge {
	out := []GraphEdge{}
	for _, edge := range edges {
		if keep(edge) {
			out = append(out, edge)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VersionsBehind != out[j].VersionsBehind {
			return out[i].VersionsBehind > out[j].VersionsBehind
		}
		return out[i].ConsumerRef < out[j].ConsumerRef
	})
	return out
}

// tagOf shortens a reference to its tag or digest for table display, falling back to
// the whole reference when there is nothing to trim.
func tagOf(ref string) string {
	if ref == "" {
		return "unknown"
	}
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		digest := ref[i+1:]
		if len(digest) > 19 {
			return digest[:19]
		}
		return digest
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i+1:], "/") {
		return ref[i+1:]
	}
	return ref
}

// shortDigest trims a digest for table display while keeping enough to be unique in
// practice across one scan.
func shortDigest(digest string) string {
	if len(digest) > 26 {
		return digest[:26]
	}
	return digest
}

// summariseImages keeps a blast-radius row readable: name a couple of carriers, then
// count the rest rather than pasting a wall of refs into a table cell.
func summariseImages(images []string) string {
	const named = 2
	if len(images) <= named {
		return "`" + strings.Join(images, "`, `") + "`"
	}
	head := make([]string, 0, named)
	for _, ref := range images[:named] {
		head = append(head, "`"+ref+"`")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(head, ", "), len(images)-named)
}
