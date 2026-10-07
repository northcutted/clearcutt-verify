package estategraph

import (
	"fmt"
	"sort"
	"strings"
)

// Rendering caps. A commonality graph over a real fleet has more edges than a reader
// can use; these keep the report readable and say what was elided rather than
// silently truncating.
const (
	maxDiagramImages = 24
	maxDiagramEdges  = 40
	maxCommonRows    = 25
	maxPairRows      = 25
)

// LayerGraphMarkdown renders the fleet's shared content as an audit-ready report.
func LayerGraphMarkdown(graph LayerGraph) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Fleet Layer Commonality\n\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", graph.GeneratedAt)
	fmt.Fprintf(&b, "What the observed images have in common, measured by layer content. This is not a base-image relationship: images can share nearly all their content with no parentage between them, and a parent and child can share very little. Shared content means shared exposure.\n\n")

	s := graph.Summary
	fmt.Fprintf(&b, "## Executive summary\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Images analysed | %d |\n", s.Images)
	fmt.Fprintf(&b, "| Distinct layers | %d |\n", s.DistinctLayers)
	fmt.Fprintf(&b, "| Layers in more than one image | %d |\n", s.SharedLayers)
	fmt.Fprintf(&b, "| Layers unique to a single image | %d |\n", s.UniqueLayers)
	fmt.Fprintf(&b, "| Layers in *every* image (fleet core) | %d |\n", s.CoreLayers)
	fmt.Fprintf(&b, "| Layers in at least %.0f%% of images | %d |\n", s.CoverageThreshold*100, s.CommonLayers)
	fmt.Fprintf(&b, "| Stored once | %s |\n", humanBytes(s.StoredBytes))
	fmt.Fprintf(&b, "| Cost without any layer reuse | %s |\n", humanBytes(s.NaiveBytes))
	fmt.Fprintf(&b, "| Avoided by sharing | %.0f%% |\n", s.SharingRatio*100)
	fmt.Fprintf(&b, "| Groups of content-identical images | %d |\n", s.IdenticalGroups)
	fmt.Fprintf(&b, "| Clusters | %d |\n", s.Clusters)
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## Content-identical images\n\n")
	if len(graph.Identical) == 0 {
		fmt.Fprintf(&b, "No two observed images carry exactly the same layer set.\n\n")
	} else {
		fmt.Fprintf(&b, "These images are published under different references but carry byte-identical content. Usually that means a release republished something that did not change. Rebuilding or re-tagging them changes nothing an image consumer can observe.\n\n")
		fmt.Fprintf(&b, "| Layers | Size | Images |\n|---:|---:|---|\n")
		for _, group := range graph.Identical {
			fmt.Fprintf(&b, "| %d | %s | %s |\n", group.LayerCount, humanBytes(group.Bytes), joinRefs(group.Images))
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## The common core\n\n")
	if len(graph.Common) == 0 {
		fmt.Fprintf(&b, "No layer reaches the %.0f%% coverage threshold. The fleet has no shared core at this setting.\n\n", s.CoverageThreshold*100)
	} else {
		if s.CoreLayers == 0 {
			fmt.Fprintf(&b, "No layer is present in *every* image, so the fleet has no universal core. These layers are the most widely carried, and are the highest-leverage remediation targets: a fix to one of them reaches every image below.\n\n")
		} else {
			fmt.Fprintf(&b, "%d layer(s) are present in every observed image. A vulnerability in any of them affects the entire fleet at once.\n\n", s.CoreLayers)
		}
		fmt.Fprintf(&b, "| Layer | Size | Images | Coverage |\n|---|---:|---:|---:|\n")
		shown, elided := capRows(len(graph.Common), maxCommonRows)
		for _, layer := range graph.Common[:shown] {
			fmt.Fprintf(&b, "| `%s` | %s | %d | %.0f%% |\n", shortDigest(layer.Digest), humanBytes(layer.Size), layer.ImageCount, layer.Coverage*100)
		}
		fmt.Fprintf(&b, "\n")
		if elided > 0 {
			fmt.Fprintf(&b, "%d further common layer(s) are in the graph JSON.\n\n", elided)
		}
	}

	fmt.Fprintf(&b, "## Clusters\n\n")
	if len(graph.Clusters) == 0 {
		fmt.Fprintf(&b, "No image pair reached the similarity threshold, so no clusters formed.\n\n")
	} else {
		fmt.Fprintf(&b, "Images connected by shared content. A cluster answers \"which images move together when this content changes\".\n\n")
		fmt.Fprintf(&b, "| Cluster | Images | Layers common to all members | Size |\n|---:|---:|---:|---:|\n")
		for _, cluster := range graph.Clusters {
			fmt.Fprintf(&b, "| %d | %d | %d | %s |\n", cluster.ID, len(cluster.Images), cluster.SharedLayers, humanBytes(cluster.SharedBytes))
		}
		fmt.Fprintf(&b, "\n")
		for _, cluster := range graph.Clusters {
			fmt.Fprintf(&b, "**Cluster %d** — %s\n\n", cluster.ID, joinRefs(cluster.Images))
		}
	}

	if diagram := LayerGraphMermaid(graph); diagram != "" {
		fmt.Fprintf(&b, "## Commonality diagram\n\n")
		fmt.Fprintf(&b, "Edges are labelled with the number of layers the two images share.\n\n")
		b.WriteString(diagram)
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Most similar image pairs\n\n")
	if len(graph.Similar) == 0 {
		fmt.Fprintf(&b, "No image pair reached the similarity threshold.\n\n")
	} else {
		fmt.Fprintf(&b, "Jaccard is shared layers over the union of both layer sets. Containment is shared layers over the smaller set, so it reaches 1.00 when one image's content is wholly inside the other's.\n\n")
		fmt.Fprintf(&b, "| Image A | Image B | Shared | Size | Jaccard | Containment |\n|---|---|---:|---:|---:|---:|\n")
		shown, elided := capRows(len(graph.Similar), maxPairRows)
		for _, pair := range graph.Similar[:shown] {
			fmt.Fprintf(&b, "| `%s` | `%s` | %d | %s | %.2f | %.2f |\n",
				shortRef(pair.A), shortRef(pair.B), pair.SharedLayers, humanBytes(pair.SharedBytes), pair.Jaccard, pair.Containment)
		}
		fmt.Fprintf(&b, "\n")
		if elided > 0 {
			fmt.Fprintf(&b, "%d further pair(s) are in the graph JSON.\n\n", elided)
		}
	}

	fmt.Fprintf(&b, "## Per-image content profile\n\n")
	fmt.Fprintf(&b, "How much of each image is content nothing else in the estate carries. A high unique share means remediating that image benefits only that image.\n\n")
	fmt.Fprintf(&b, "| Image | Layers | Shared | Unique | Total size | Unique size | Unique share |\n|---|---:|---:|---:|---:|---:|---:|\n")
	for _, profile := range graph.Images {
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d | %s | %s | %.0f%% |\n",
			shortRef(profile.Ref), profile.Layers, profile.SharedLayers, profile.UniqueLayers,
			humanBytes(profile.TotalBytes), humanBytes(profile.UniqueBytes), profile.UniqueShare*100)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## What this does not prove\n\n")
	fmt.Fprintf(&b, "- Shared layers are shared content, never a base-image relationship. Run `clearcutt-verify graph build` for parentage.\n")
	fmt.Fprintf(&b, "- Sizes are compressed layer sizes from the manifest, not installed footprint on disk.\n")
	fmt.Fprintf(&b, "- Identical layer sets mean identical content, not identical configuration: two images can share every layer and still differ in entrypoint, user, or labels.\n")
	fmt.Fprintf(&b, "- Commonality is measured only across the images observed in this scan. Widening the scan changes every coverage percentage here.\n\n")

	if len(graph.Warnings) > 0 {
		fmt.Fprintf(&b, "## Warnings\n\n")
		for _, warning := range graph.Warnings {
			fmt.Fprintf(&b, "- %s\n", warning)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Reproduce this report\n\n")
	fmt.Fprintf(&b, "```bash\nclearcutt registry scan --registry <host> --namespace <namespace> --output images.yaml\nclearcutt import observe --images images.yaml --output observations.json\nclearcutt graph layers --observations observations.json --output layers.json --report layers.md\n```\n")
	return b.String()
}

// LayerGraphMermaid renders the clustered commonality graph as a Mermaid diagram.
// It returns an empty string when there is nothing worth drawing.
func LayerGraphMermaid(graph LayerGraph) string {
	if len(graph.Similar) == 0 || len(graph.Clusters) == 0 {
		return ""
	}
	// Draw only images that belong to a cluster, largest clusters first, so a big
	// fleet still yields a readable picture of its main families.
	ids := map[string]string{}
	ordered := []string{}
	for _, cluster := range graph.Clusters {
		for _, ref := range cluster.Images {
			if _, seen := ids[ref]; seen {
				continue
			}
			if len(ordered) >= maxDiagramImages {
				break
			}
			ids[ref] = fmt.Sprintf("n%d", len(ordered))
			ordered = append(ordered, ref)
		}
	}
	if len(ordered) < 2 {
		return ""
	}

	var b strings.Builder
	b.WriteString("```mermaid\ngraph LR\n")
	for _, cluster := range graph.Clusters {
		drawn := []string{}
		for _, ref := range cluster.Images {
			if _, ok := ids[ref]; ok {
				drawn = append(drawn, ref)
			}
		}
		if len(drawn) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  subgraph cluster%d[\"Cluster %d · %d layers common to all\"]\n", cluster.ID, cluster.ID, cluster.SharedLayers)
		for _, ref := range drawn {
			fmt.Fprintf(&b, "    %s[\"%s\"]\n", ids[ref], mermaidLabel(shortRef(ref)))
		}
		b.WriteString("  end\n")
	}
	edges := 0
	for _, pair := range graph.Similar {
		left, okA := ids[pair.A]
		right, okB := ids[pair.B]
		if !okA || !okB {
			continue
		}
		if edges >= maxDiagramEdges {
			fmt.Fprintf(&b, "  %%%% %d further edge(s) omitted for readability\n", len(graph.Similar)-edges)
			break
		}
		fmt.Fprintf(&b, "  %s ---|\"%d\"| %s\n", left, pair.SharedLayers, right)
		edges++
	}
	b.WriteString("```\n")
	if edges == 0 {
		return ""
	}
	return b.String()
}

// mermaidLabel neutralises the characters that would break a quoted Mermaid label.
func mermaidLabel(value string) string {
	replacer := strings.NewReplacer(`"`, "'", "\n", " ", "[", "(", "]", ")", "{", "(", "}", ")")
	return replacer.Replace(value)
}

// shortRef trims a reference to the last path segment, which carries the image name
// and tag — enough to identify a row without a full registry path in every cell.
func shortRef(ref string) string {
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

func joinRefs(refs []string) string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, "`"+shortRef(ref)+"`")
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// capRows returns how many rows to render and how many were elided.
func capRows(total, max int) (shown, elided int) {
	if total <= max {
		return total, 0
	}
	return max, total - max
}

// humanBytes formats a compressed layer size for a report table.
func humanBytes(size int64) string {
	switch {
	case size <= 0:
		return "—"
	case size < 1024:
		return fmt.Sprintf("%d B", size)
	case size < 1024*1024:
		return fmt.Sprintf("%.0f KB", float64(size)/1024)
	case size < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	default:
		return fmt.Sprintf("%.2f GB", float64(size)/(1024*1024*1024))
	}
}
