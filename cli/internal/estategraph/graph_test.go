package estategraph

import (
	"fmt"
	"strings"
	"testing"
)

// obs builds an observation with layer digests derived from short names, so tests
// read as layer *shapes* rather than walls of hex.
func obs(ref, created string, layers ...string) Observation {
	o := baseObservation("", ref)
	o.Created = created
	o.ManifestDigest = "sha256:" + fakeHex(ref)
	o.DigestRef = repositoryOf(ref) + "@" + o.ManifestDigest
	for _, layer := range layers {
		o.Layers = append(o.Layers, LayerObservation{Digest: "sha256:" + fakeHex(layer), Size: 1})
	}
	normalizeObservation(&o)
	return o
}

func fakeHex(seed string) string {
	var b strings.Builder
	for _, r := range seed {
		fmt.Fprintf(&b, "%02x", byte(r))
	}
	for b.Len() < 64 {
		b.WriteString("0")
	}
	return b.String()[:64]
}

func graphOf(t *testing.T, opts GraphOptions, images ...Observation) Graph {
	t.Helper()
	if opts.GeneratedAt == "" {
		opts.GeneratedAt = "2026-01-01T00:00:00Z"
	}
	graph, err := BuildGraph(Observations{Images: images}, opts)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	return graph
}

func edgeFor(t *testing.T, graph Graph, consumerRef string) GraphEdge {
	t.Helper()
	for _, edge := range graph.Edges {
		if edge.ConsumerRef == consumerRef {
			return edge
		}
	}
	t.Fatalf("no edge for consumer %q; edges=%+v unresolved=%+v", consumerRef, graph.Edges, graph.Unresolved)
	return GraphEdge{}
}

func TestBuildGraphDetectsLayerPrefixAsProof(t *testing.T) {
	base := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os", "jdk")
	app := obs("reg.test/apps/payments:v9", "2026-02-01T00:00:00Z", "os", "jdk", "app")

	graph := graphOf(t, GraphOptions{}, base, app)

	edge := edgeFor(t, graph, "reg.test/apps/payments:v9")
	if edge.Method != MethodLayerPrefix {
		t.Fatalf("Method = %q, want %q", edge.Method, MethodLayerPrefix)
	}
	if edge.Confidence != "verified" {
		t.Fatalf("Confidence = %q, want verified", edge.Confidence)
	}
	if edge.BaseRepository != "reg.test/base/java21" {
		t.Fatalf("BaseRepository = %q", edge.BaseRepository)
	}
	if edge.Drift != DriftCurrent {
		t.Fatalf("Drift = %q, want current", edge.Drift)
	}
	// The base itself must not be reported as a consumer of the app.
	if graph.Summary.ResolvedConsumers != 1 {
		t.Fatalf("ResolvedConsumers = %d, want 1", graph.Summary.ResolvedConsumers)
	}
}

func TestBuildGraphReportsDriftAgainstNewestBaseVersion(t *testing.T) {
	old := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os-v1", "jdk-v1")
	mid := obs("reg.test/base/java21:v2", "2026-01-11T00:00:00Z", "os-v2", "jdk-v2")
	current := obs("reg.test/base/java21:v3", "2026-01-31T00:00:00Z", "os-v3", "jdk-v3")
	stale := obs("reg.test/apps/payments:v9", "2026-01-02T00:00:00Z", "os-v1", "jdk-v1", "app")
	fresh := obs("reg.test/apps/search:v4", "2026-02-01T00:00:00Z", "os-v3", "jdk-v3", "app")

	graph := graphOf(t, GraphOptions{}, old, mid, current, stale, fresh)

	staleEdge := edgeFor(t, graph, "reg.test/apps/payments:v9")
	if staleEdge.Drift != DriftStale {
		t.Fatalf("Drift = %q, want stale", staleEdge.Drift)
	}
	if staleEdge.VersionsBehind != 2 {
		t.Fatalf("VersionsBehind = %d, want 2", staleEdge.VersionsBehind)
	}
	if staleEdge.DaysBehind != 30 {
		t.Fatalf("DaysBehind = %d, want 30", staleEdge.DaysBehind)
	}
	if staleEdge.CurrentBaseRef != "reg.test/base/java21:v3" {
		t.Fatalf("CurrentBaseRef = %q, want the newest version", staleEdge.CurrentBaseRef)
	}

	freshEdge := edgeFor(t, graph, "reg.test/apps/search:v4")
	if freshEdge.Drift != DriftCurrent {
		t.Fatalf("Drift = %q, want current", freshEdge.Drift)
	}

	if graph.Summary.StaleConsumers != 1 || graph.Summary.CurrentConsumers != 1 {
		t.Fatalf("summary stale/current = %d/%d, want 1/1", graph.Summary.StaleConsumers, graph.Summary.CurrentConsumers)
	}
	var family *GraphBase
	for i := range graph.Bases {
		if graph.Bases[i].Repository == "reg.test/base/java21" {
			family = &graph.Bases[i]
		}
	}
	if family == nil {
		t.Fatal("expected the java21 base family in the graph")
	}
	if family.Consumers != 2 || family.StaleConsumers != 1 {
		t.Fatalf("family consumers/stale = %d/%d, want 2/1", family.Consumers, family.StaleConsumers)
	}
	if family.Versions != 3 {
		t.Fatalf("family Versions = %d, want 3", family.Versions)
	}
}

func TestBuildGraphCurrencyUsesCreationTimeNotTagOrder(t *testing.T) {
	// v10 is newer than v9 by timestamp but sorts lower as a string.
	older := obs("reg.test/base/node:v9", "2026-01-01T00:00:00Z", "os-a")
	newer := obs("reg.test/base/node:v10", "2026-03-01T00:00:00Z", "os-b")
	app := obs("reg.test/apps/web:v1", "2026-01-02T00:00:00Z", "os-a", "app")

	graph := graphOf(t, GraphOptions{}, older, newer, app)

	edge := edgeFor(t, graph, "reg.test/apps/web:v1")
	if edge.CurrentBaseRef != "reg.test/base/node:v10" {
		t.Fatalf("CurrentBaseRef = %q, want v10 (newest by created time)", edge.CurrentBaseRef)
	}
	if edge.Drift != DriftStale {
		t.Fatalf("Drift = %q, want stale", edge.Drift)
	}
}

func TestBuildGraphDetectsOCIBaseDigestLabel(t *testing.T) {
	base := obs("reg.test/base/python:v1", "2026-01-01T00:00:00Z", "os", "py")
	// Layers deliberately do not overlap, so only the label can find the base.
	app := obs("reg.test/apps/api:v1", "2026-02-01T00:00:00Z", "squashed")
	app.Labels["org.opencontainers.image.base.digest"] = base.ManifestDigest

	graph := graphOf(t, GraphOptions{}, base, app)

	edge := edgeFor(t, graph, "reg.test/apps/api:v1")
	if edge.Method != MethodOCIBaseDigest {
		t.Fatalf("Method = %q, want %q", edge.Method, MethodOCIBaseDigest)
	}
	if edge.Confidence != "declared" {
		t.Fatalf("Confidence = %q, want declared", edge.Confidence)
	}
}

func TestBuildGraphDetectsBuildpacksRunImageReference(t *testing.T) {
	base := obs("reg.test/base/run:v1", "2026-01-01T00:00:00Z", "os")
	app := obs("reg.test/apps/cnb:v1", "2026-02-01T00:00:00Z", "squashed")
	app.Labels["io.buildpacks.lifecycle.metadata"] = fmt.Sprintf(
		`{"runImage":{"topLayer":"sha256:deadbeef","reference":"reg.test/base/run@%s"}}`, base.ManifestDigest)

	graph := graphOf(t, GraphOptions{}, base, app)

	edge := edgeFor(t, graph, "reg.test/apps/cnb:v1")
	if edge.Method != MethodBuildpacksMetadata {
		t.Fatalf("Method = %q, want %q", edge.Method, MethodBuildpacksMetadata)
	}
	if edge.Confidence != "declared" {
		t.Fatalf("Confidence = %q, want declared", edge.Confidence)
	}
}

func TestBuildGraphDetectsBuildpacksTopLayerWhenReferenceIsUnhelpful(t *testing.T) {
	base := obs("reg.test/base/run:v1", "2026-01-01T00:00:00Z", "os", "final")
	app := obs("reg.test/apps/cnb:v1", "2026-02-01T00:00:00Z", "squashed")
	app.Labels["io.buildpacks.lifecycle.metadata"] = fmt.Sprintf(
		`{"runImage":{"topLayer":"sha256:%s","reference":"reg.test/base/run:latest"}}`, fakeHex("final"))

	graph := graphOf(t, GraphOptions{}, base, app)

	edge := edgeFor(t, graph, "reg.test/apps/cnb:v1")
	if edge.Method != MethodBuildpacksMetadata {
		t.Fatalf("Method = %q, want %q", edge.Method, MethodBuildpacksMetadata)
	}
}

func TestBuildGraphMalformedBuildpacksMetadataIsIgnoredNotFatal(t *testing.T) {
	base := obs("reg.test/base/run:v1", "2026-01-01T00:00:00Z", "os")
	app := obs("reg.test/apps/cnb:v1", "2026-02-01T00:00:00Z", "squashed")
	app.Labels["io.buildpacks.lifecycle.metadata"] = "{not json"

	graph := graphOf(t, GraphOptions{}, base, app)

	if len(graph.Edges) != 0 {
		t.Fatalf("malformed metadata must not produce an edge, got %+v", graph.Edges)
	}
	if len(graph.Unresolved) == 0 {
		t.Fatal("expected the consumer to be reported as unresolved")
	}
}

func TestBuildGraphBaseNameLabelIsOnlyAssisted(t *testing.T) {
	base := obs("reg.test/base/go:v1", "2026-01-01T00:00:00Z", "os")
	app := obs("reg.test/apps/svc:v1", "2026-02-01T00:00:00Z", "squashed")
	app.Labels["org.opencontainers.image.base.name"] = "reg.test/base/go:v1"

	graph := graphOf(t, GraphOptions{}, base, app)

	edge := edgeFor(t, graph, "reg.test/apps/svc:v1")
	if edge.Method != MethodOCIBaseName || edge.Confidence != "assisted" {
		t.Fatalf("Method/Confidence = %q/%q, want %q/assisted", edge.Method, edge.Confidence, MethodOCIBaseName)
	}
	joined := strings.Join(edge.Notes, " ")
	if !strings.Contains(joined, "not proven") {
		t.Fatalf("assisted edge must carry the inference caveat, notes=%v", edge.Notes)
	}
}

func TestBuildGraphHistoryIsTheWeakestSignal(t *testing.T) {
	base := obs("reg.test/base/rust:v1", "2026-01-01T00:00:00Z", "os")
	app := obs("reg.test/apps/tool:v1", "2026-02-01T00:00:00Z", "squashed")
	app.History = []HistoryObservation{{CreatedBy: "FROM reg.test/base/rust:v1"}}

	graph := graphOf(t, GraphOptions{}, base, app)

	edge := edgeFor(t, graph, "reg.test/apps/tool:v1")
	if edge.Method != MethodHistory || edge.Confidence != "weak" {
		t.Fatalf("Method/Confidence = %q/%q, want %q/weak", edge.Method, edge.Confidence, MethodHistory)
	}
}

func TestBuildGraphPrefersProofOverSelfReportedLabels(t *testing.T) {
	real := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os", "jdk")
	decoy := obs("reg.test/base/decoy:v1", "2026-01-01T00:00:00Z", "other")
	app := obs("reg.test/apps/payments:v1", "2026-02-01T00:00:00Z", "os", "jdk", "app")
	// The image claims the decoy is its base. Layer proof says otherwise.
	app.Labels["org.opencontainers.image.base.digest"] = decoy.ManifestDigest

	graph := graphOf(t, GraphOptions{}, real, decoy, app)

	edge := edgeFor(t, graph, "reg.test/apps/payments:v1")
	if edge.Method != MethodLayerPrefix {
		t.Fatalf("Method = %q, want layer proof to beat a self-reported label", edge.Method)
	}
	if edge.BaseRepository != "reg.test/base/java21" {
		t.Fatalf("BaseRepository = %q, want the layer-proven base", edge.BaseRepository)
	}
	// Both detections should still be visible to a reviewer.
	var sawDeclared bool
	for _, signal := range edge.Signals {
		if signal.Type == MethodOCIBaseDigest {
			sawDeclared = true
		}
	}
	if !sawDeclared {
		t.Fatalf("the contradicting declared signal must stay on the edge, got %+v", edge.Signals)
	}
}

// The showcase prototype's shape (V10): an app built on a run image that was
// built on an upstream base starts with both images' layers. It is built on
// the run image, the nearest base, even though the upstream repository sorts
// first; the upstream base is the run image's base.
func TestBuildGraphAttributesAnImageToItsNearestBase(t *testing.T) {
	upstream := obs("cgr.dev/chainguard/wolfi-base:latest", "2026-01-01T00:00:00Z", "wolfi")
	run := obs("localhost:5001/platform/run-python:1", "2026-01-02T00:00:00Z", "wolfi", "python")
	app := obs("localhost:5001/apps/catalog:1", "2026-01-03T00:00:00Z", "wolfi", "python", "catalog")

	for _, order := range [][]Observation{{upstream, run, app}, {app, run, upstream}, {run, app, upstream}} {
		graph := graphOf(t, GraphOptions{}, order...)

		edge := edgeFor(t, graph, "localhost:5001/apps/catalog:1")
		if edge.BaseRepository != "localhost:5001/platform/run-python" || edge.Method != MethodLayerPrefix || edge.Drift != DriftCurrent {
			t.Fatalf("app base = %s via %s (%s), want the run image by layer proof", edge.BaseRepository, edge.Method, edge.Drift)
		}
		// The upstream base still shows as a matched signal.
		if len(edge.Signals) != 2 || edge.Signals[0].Type != MethodLayerPrefix || edge.Signals[1].Type != MethodLayerPrefix {
			t.Fatalf("app signals = %+v, want both layer-prefix matches", edge.Signals)
		}
		if e := edgeFor(t, graph, "localhost:5001/platform/run-python:1"); e.BaseRepository != "cgr.dev/chainguard/wolfi-base" {
			t.Fatalf("run image base = %s, want the upstream base", e.BaseRepository)
		}
		if len(graph.Roots) != 1 || graph.Roots[0].ImageRef != "cgr.dev/chainguard/wolfi-base:latest" {
			t.Fatalf("roots = %+v, want the upstream base", graph.Roots)
		}
		if len(graph.Bases) != 2 || graph.Bases[0].Consumers != 1 || graph.Bases[1].Repository != "localhost:5001/platform/run-python" || graph.Bases[1].Consumers != 1 {
			t.Fatalf("bases = %+v, want one consumer each", graph.Bases)
		}
	}
}

// The nearest base wins on an older version of it too: the app is behind
// its run image, not on the upstream base.
func TestBuildGraphNearestBaseOnAnOlderVersion(t *testing.T) {
	upstream := obs("cgr.dev/chainguard/wolfi-base:latest", "2026-01-01T00:00:00Z", "wolfi")
	held := obs("localhost:5001/run-python:held", "2026-01-02T00:00:00Z", "wolfi", "python-1")
	current := obs("localhost:5001/run-python:latest", "2026-01-09T00:00:00Z", "wolfi", "python-2")
	app := obs("localhost:5001/apps/catalog:1", "2026-01-03T00:00:00Z", "wolfi", "python-1", "catalog")

	graph := graphOf(t, GraphOptions{}, upstream, held, current, app)

	edge := edgeFor(t, graph, "localhost:5001/apps/catalog:1")
	if edge.BaseRepository != "localhost:5001/run-python" || edge.BaseRef != "localhost:5001/run-python:held" || edge.Drift != DriftStale || edge.DaysBehind != 7 {
		t.Fatalf("app edge = %+v, want stale on the held run image", edge)
	}
}

// Equally long prefixes are the same layers in two places (a mirror): the one
// the image's own base annotation names wins, else the first repository by
// name, so the choice never depends on input order.
func TestBuildGraphTieBetweenEqualPrefixes(t *testing.T) {
	upstream := obs("docker.io/library/debian:13", "2026-01-01T00:00:00Z", "debian")
	mirror := obs("reg.test/mirror/debian:13", "2026-01-01T00:00:00Z", "debian")
	app := obs("reg.test/apps/api:1", "2026-01-02T00:00:00Z", "debian", "api")

	for _, order := range [][]Observation{{upstream, mirror, app}, {app, mirror, upstream}} {
		if e := edgeFor(t, graphOf(t, GraphOptions{}, order...), "reg.test/apps/api:1"); e.BaseRepository != "docker.io/library/debian" {
			t.Fatalf("undeclared tie went to %s, want the first repository by name", e.BaseRepository)
		}
	}
	app.Annotations["org.opencontainers.image.base.name"] = "reg.test/mirror/debian:13"
	if e := edgeFor(t, graphOf(t, GraphOptions{}, upstream, mirror, app), "reg.test/apps/api:1"); e.BaseRepository != "reg.test/mirror/debian" || e.Method != MethodLayerPrefix {
		t.Fatalf("declared tie went to %s via %s, want the mirror the image names", e.BaseRepository, e.Method)
	}
	delete(app.Annotations, "org.opencontainers.image.base.name")
	app.Labels["org.opencontainers.image.base.digest"] = mirror.ManifestDigest
	if e := edgeFor(t, graphOf(t, GraphOptions{}, upstream, mirror, app), "reg.test/apps/api:1"); e.BaseRepository != "reg.test/mirror/debian" || e.Method != MethodLayerPrefix {
		t.Fatalf("tie declared by digest went to %s via %s, want the mirror", e.BaseRepository, e.Method)
	}
}

func TestBuildGraphIdenticalLayerSetsAreNotABaseRelationship(t *testing.T) {
	one := obs("reg.test/a/mirror:v1", "2026-01-01T00:00:00Z", "os", "jdk")
	two := obs("reg.test/b/mirror:v1", "2026-01-02T00:00:00Z", "os", "jdk")

	graph := graphOf(t, GraphOptions{}, one, two)

	if len(graph.Edges) != 0 {
		t.Fatalf("same content in two repositories is a mirror, not a layering: %+v", graph.Edges)
	}
}

func TestBuildGraphNeverLinksTagsOfTheSameRepository(t *testing.T) {
	v1 := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os")
	v2 := obs("reg.test/base/java21:v2", "2026-02-01T00:00:00Z", "os", "extra")

	graph := graphOf(t, GraphOptions{}, v1, v2)

	if len(graph.Edges) != 0 {
		t.Fatalf("versions of one repository must not form edges: %+v", graph.Edges)
	}
}

func TestBuildGraphReportsUnresolvedConsumersWithReasons(t *testing.T) {
	base := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os")
	orphan := obs("reg.test/apps/mystery:v1", "2026-02-01T00:00:00Z", "unrelated")

	graph := graphOf(t, GraphOptions{}, base, orphan)

	if len(graph.Unresolved) == 0 {
		t.Fatal("expected the orphan to be reported")
	}
	var found *GraphUnresolved
	for i := range graph.Unresolved {
		if graph.Unresolved[i].ConsumerRef == "reg.test/apps/mystery:v1" {
			found = &graph.Unresolved[i]
		}
	}
	if found == nil || len(found.Reasons) == 0 {
		t.Fatalf("unresolved entry must explain itself, got %+v", graph.Unresolved)
	}
	if !strings.Contains(strings.Join(found.Reasons, " "), "no labels") {
		t.Fatalf("expected the missing-labels reason, got %v", found.Reasons)
	}
}

func TestBuildGraphImageWithNoLayersIsUnresolvedNotDropped(t *testing.T) {
	base := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os")
	blind := obs("reg.test/apps/unreadable:v1", "2026-02-01T00:00:00Z")

	graph := graphOf(t, GraphOptions{}, base, blind)

	for _, entry := range graph.Unresolved {
		if entry.ConsumerRef == "reg.test/apps/unreadable:v1" {
			if !strings.Contains(strings.Join(entry.Reasons, " "), "no observed layers") {
				t.Fatalf("expected the no-layers reason, got %v", entry.Reasons)
			}
			return
		}
	}
	t.Fatalf("image with no layers must be reported, got %+v", graph.Unresolved)
}

func TestBuildGraphMinConfidenceDemotesWeakEdgesToUnresolved(t *testing.T) {
	base := obs("reg.test/base/rust:v1", "2026-01-01T00:00:00Z", "os")
	app := obs("reg.test/apps/tool:v1", "2026-02-01T00:00:00Z", "squashed")
	app.History = []HistoryObservation{{CreatedBy: "FROM reg.test/base/rust:v1"}}

	graph := graphOf(t, GraphOptions{MinConfidence: "verified"}, base, app)

	if len(graph.Edges) != 0 {
		t.Fatalf("weak edge must be filtered out at MinConfidence=verified: %+v", graph.Edges)
	}
	var filtered *GraphUnresolved
	for i := range graph.Unresolved {
		if graph.Unresolved[i].ConsumerRef == "reg.test/apps/tool:v1" {
			filtered = &graph.Unresolved[i]
		}
	}
	if filtered == nil {
		t.Fatalf("filtered edge must be reported as unresolved, got %+v", graph.Unresolved)
	}
	if !strings.Contains(strings.Join(filtered.Reasons, " "), "below the required minimum confidence") {
		t.Fatalf("reason should name the filter, got %v", filtered.Reasons)
	}
}

func TestBuildGraphRejectsInvalidMinConfidence(t *testing.T) {
	_, err := BuildGraph(Observations{}, GraphOptions{MinConfidence: "definitely"})
	if err == nil {
		t.Fatal("expected an error for an unknown confidence level")
	}
}

func TestBuildGraphBasePatternsNarrowWhatCanActAsABase(t *testing.T) {
	approved := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os", "jdk")
	shadow := obs("reg.test/random/thing:v1", "2026-01-01T00:00:00Z", "os")
	app := obs("reg.test/apps/payments:v1", "2026-02-01T00:00:00Z", "os", "jdk", "app")

	graph := graphOf(t, GraphOptions{BasePatterns: []string{"reg.test/base/*"}}, approved, shadow, app)

	for _, edge := range graph.Edges {
		if edge.BaseRepository == "reg.test/random/thing" {
			t.Fatalf("repository outside --base-repository must not act as a base: %+v", edge)
		}
	}
	edge := edgeFor(t, graph, "reg.test/apps/payments:v1")
	if edge.BaseRepository != "reg.test/base/java21" {
		t.Fatalf("BaseRepository = %q", edge.BaseRepository)
	}
}

func TestBuildGraphBasePatternMatchesBareRepositoryName(t *testing.T) {
	base := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os")
	app := obs("reg.test/apps/payments:v1", "2026-02-01T00:00:00Z", "os", "app")

	graph := graphOf(t, GraphOptions{BasePatterns: []string{"java21"}}, base, app)

	if len(graph.Edges) != 1 {
		t.Fatalf("bare-name pattern should select the base, got %+v", graph.Edges)
	}
}

func TestBuildGraphIsDeterministic(t *testing.T) {
	images := []Observation{
		obs("reg.test/apps/b:v1", "2026-02-01T00:00:00Z", "os", "b"),
		obs("reg.test/base/x:v1", "2026-01-01T00:00:00Z", "os"),
		obs("reg.test/apps/a:v1", "2026-02-01T00:00:00Z", "os", "a"),
	}
	first := graphOf(t, GraphOptions{}, images...)
	reversed := []Observation{images[2], images[0], images[1]}
	second := graphOf(t, GraphOptions{}, reversed...)

	if fmt.Sprint(first.Edges) != fmt.Sprint(second.Edges) {
		t.Fatalf("edge ordering is input-dependent:\n%v\n%v", first.Edges, second.Edges)
	}
	if fmt.Sprint(first.Bases) != fmt.Sprint(second.Bases) {
		t.Fatalf("base ordering is input-dependent:\n%v\n%v", first.Bases, second.Bases)
	}
}

func TestBuildGraphEmptyObservationsWarnRatherThanError(t *testing.T) {
	graph, err := BuildGraph(Observations{}, GraphOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	if len(graph.Warnings) == 0 {
		t.Fatal("expected a warning for an empty observation set")
	}
}

func TestBuildGraphFlagsUndatedVersionsOnTheBaseFamily(t *testing.T) {
	dated := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os-v1")
	undated := obs("reg.test/base/java21:v2", "", "os-v2")
	app := obs("reg.test/apps/payments:v1", "2026-02-01T00:00:00Z", "os-v1", "app")

	graph := graphOf(t, GraphOptions{}, dated, undated, app)

	if len(graph.Bases) != 1 {
		t.Fatalf("want one base family, got %+v", graph.Bases)
	}
	if len(graph.Bases[0].Warnings) == 0 {
		t.Fatal("a family with undated versions must warn that currency used tag order")
	}
}

func TestRepositoryOfHandlesPortsDigestsAndTags(t *testing.T) {
	cases := map[string]string{
		"reg.test/base/java21:v1":         "reg.test/base/java21",
		"reg.test/base/java21@sha256:abc": "reg.test/base/java21",
		"localhost:5000/app:v1":           "localhost:5000/app",
		"localhost:5000/app":              "localhost:5000/app",
		"localhost:5000/app@sha256:abc":   "localhost:5000/app",
		"reg.test/base/java21":            "reg.test/base/java21",
		"":                                "",
	}
	for input, want := range cases {
		if got := repositoryOf(input); got != want {
			t.Fatalf("repositoryOf(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBuildGraphReportsProvenBasesAsRootsNotOrphans(t *testing.T) {
	base := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os", "jdk")
	app := obs("reg.test/apps/payments:v1", "2026-02-01T00:00:00Z", "os", "jdk", "app")

	graph := graphOf(t, GraphOptions{}, base, app)

	for _, entry := range graph.Unresolved {
		if entry.ConsumerRef == "reg.test/base/java21:v1" {
			t.Fatalf("a base other images sit on must not be an orphan: %+v", entry)
		}
	}
	if len(graph.Roots) != 1 {
		t.Fatalf("want the base reported as a root, got %+v", graph.Roots)
	}
	root := graph.Roots[0]
	if root.ImageRef != "reg.test/base/java21:v1" || root.Consumers != 1 {
		t.Fatalf("root = %+v, want the java21 base with 1 consumer", root)
	}
	if !strings.Contains(root.Reason, "proven") {
		t.Fatalf("root reason should cite the proof, got %q", root.Reason)
	}
	if graph.Summary.RootImages != 1 {
		t.Fatalf("Summary.RootImages = %d, want 1", graph.Summary.RootImages)
	}
	if graph.Summary.UnresolvedConsumers != 0 {
		t.Fatalf("Summary.UnresolvedConsumers = %d, want 0", graph.Summary.UnresolvedConsumers)
	}
}

func TestBuildGraphDeclaredBaseRepositoryIsARootEvenWithNoConsumers(t *testing.T) {
	unused := obs("reg.test/base/rust:v1", "2026-01-01T00:00:00Z", "os")
	orphan := obs("reg.test/apps/mystery:v1", "2026-02-01T00:00:00Z", "unrelated")

	graph := graphOf(t, GraphOptions{BasePatterns: []string{"reg.test/base/*"}}, unused, orphan)

	var sawRoot bool
	for _, root := range graph.Roots {
		if root.ImageRef == "reg.test/base/rust:v1" {
			sawRoot = true
			if !strings.Contains(root.Reason, "--base-repository") {
				t.Fatalf("root reason should cite the operator declaration, got %q", root.Reason)
			}
		}
	}
	if !sawRoot {
		t.Fatalf("declared base must be a root, got roots=%+v unresolved=%+v", graph.Roots, graph.Unresolved)
	}
	// The genuine orphan must survive as an audit finding.
	if len(graph.Unresolved) != 1 || graph.Unresolved[0].ConsumerRef != "reg.test/apps/mystery:v1" {
		t.Fatalf("the real orphan must still be reported, got %+v", graph.Unresolved)
	}
}

func TestBuildGraphUnusedVersionOfABaseFamilyIsARoot(t *testing.T) {
	used := obs("reg.test/base/java21:v1", "2026-01-01T00:00:00Z", "os-v1")
	unused := obs("reg.test/base/java21:v2", "2026-02-01T00:00:00Z", "os-v2")
	app := obs("reg.test/apps/payments:v1", "2026-01-05T00:00:00Z", "os-v1", "app")

	graph := graphOf(t, GraphOptions{}, used, unused, app)

	if len(graph.Unresolved) != 0 {
		t.Fatalf("an unconsumed version of a base family is not an orphan: %+v", graph.Unresolved)
	}
	var sawUnused bool
	for _, root := range graph.Roots {
		if root.ImageRef == "reg.test/base/java21:v2" {
			sawUnused = true
			if !strings.Contains(root.Reason, "another version") {
				t.Fatalf("root reason = %q", root.Reason)
			}
		}
	}
	if !sawUnused {
		t.Fatalf("want the unconsumed base version reported as a root, got %+v", graph.Roots)
	}
}

func TestBuildGraphTreatsReproducibleBuilderEpochAsNoTimestamp(t *testing.T) {
	// Nix dockerTools stamps every image 1970-01-01T00:00:01Z for reproducibility.
	// Treating that as a real build date would rank every version equally old and
	// report a meaningless daysBehind.
	old := obs("reg.test/base/java21:v1", "1970-01-01T00:00:01Z", "os-v1")
	newer := obs("reg.test/base/java21:v2", "1970-01-01T00:00:01Z", "os-v2")
	app := obs("reg.test/apps/pay:v1", "1970-01-01T00:00:01Z", "os-v1", "app")

	graph := graphOf(t, GraphOptions{}, old, newer, app)

	edge := edgeFor(t, graph, "reg.test/apps/pay:v1")
	if edge.DaysBehind != 0 {
		t.Fatalf("DaysBehind = %d, want 0 when no image carries a usable timestamp", edge.DaysBehind)
	}
	if len(graph.Bases) != 1 || len(graph.Bases[0].Warnings) == 0 {
		t.Fatalf("a family with zeroed timestamps must warn, got %+v", graph.Bases)
	}
	if !strings.Contains(graph.Bases[0].Warnings[0], "zeroed by a reproducible builder") {
		t.Fatalf("warning should name the cause, got %q", graph.Bases[0].Warnings[0])
	}
	// Tag order is the documented fallback, so v2 still ranks as current.
	if edge.CurrentBaseRef != "reg.test/base/java21:v2" {
		t.Fatalf("CurrentBaseRef = %q, want the tag-order fallback to pick v2", edge.CurrentBaseRef)
	}
}

func TestParseCreatedRejectsPlaceholderEpochs(t *testing.T) {
	for _, value := range []string{"1970-01-01T00:00:01Z", "1970-01-01T00:00:00Z", "1980-01-01T00:00:00Z", ""} {
		if _, ok := parseCreated(value); ok {
			t.Fatalf("parseCreated(%q) should report no usable timestamp", value)
		}
	}
	if _, ok := parseCreated("2026-01-01T00:00:00Z"); !ok {
		t.Fatal("a real timestamp must parse")
	}
}

func TestBuildGraphSharedLayersAnswerBlastRadiusWithoutInventingParentage(t *testing.T) {
	// Two sibling images built from the same recipe: they share content, but neither
	// is a prefix of the other, so neither is the other's base.
	left := obs("reg.test/a/slim:v1", "2026-01-01T00:00:00Z", "common", "left-only")
	right := obs("reg.test/b/dev:v1", "2026-01-01T00:00:00Z", "right-first", "common", "right-only")

	graph := graphOf(t, GraphOptions{}, left, right)

	if len(graph.Edges) != 0 {
		t.Fatalf("shared content must not be reported as a base relationship: %+v", graph.Edges)
	}
	if len(graph.SharedLayers) != 1 {
		t.Fatalf("want the one shared layer, got %+v", graph.SharedLayers)
	}
	shared := graph.SharedLayers[0]
	if shared.ImageCount != 2 {
		t.Fatalf("ImageCount = %d, want 2", shared.ImageCount)
	}
	if len(shared.Images) != 2 || shared.Images[0] != "reg.test/a/slim:v1" {
		t.Fatalf("Images = %v, want both carriers sorted", shared.Images)
	}
	if graph.Summary.DistinctLayers != 4 {
		t.Fatalf("DistinctLayers = %d, want 4", graph.Summary.DistinctLayers)
	}
	if graph.Summary.WidestLayerReach != 2 {
		t.Fatalf("WidestLayerReach = %d, want 2", graph.Summary.WidestLayerReach)
	}
}

func TestBuildGraphSharedLayersRankWidestReachFirstAndRespectTheCap(t *testing.T) {
	a := obs("reg.test/a/one:v1", "2026-01-01T00:00:00Z", "everywhere", "pair", "solo-a")
	b := obs("reg.test/b/two:v1", "2026-01-01T00:00:00Z", "everywhere", "pair", "solo-b")
	c := obs("reg.test/c/three:v1", "2026-01-01T00:00:00Z", "everywhere", "solo-c")

	graph := graphOf(t, GraphOptions{}, a, b, c)
	if len(graph.SharedLayers) != 2 {
		t.Fatalf("want two shared layers, got %+v", graph.SharedLayers)
	}
	if graph.SharedLayers[0].ImageCount != 3 || graph.SharedLayers[1].ImageCount != 2 {
		t.Fatalf("shared layers must rank widest-reach first, got %+v", graph.SharedLayers)
	}

	capped := graphOf(t, GraphOptions{MaxSharedLayers: 1}, a, b, c)
	if len(capped.SharedLayers) != 1 || capped.SharedLayers[0].ImageCount != 3 {
		t.Fatalf("cap must keep the widest-reaching layer, got %+v", capped.SharedLayers)
	}

	uncapped := graphOf(t, GraphOptions{MaxSharedLayers: -1}, a, b, c)
	if len(uncapped.SharedLayers) != 2 {
		t.Fatalf("a negative cap must keep everything, got %+v", uncapped.SharedLayers)
	}
}

func TestBuildGraphSharedLayersIgnoreSingleCarrierLayers(t *testing.T) {
	only := obs("reg.test/a/one:v1", "2026-01-01T00:00:00Z", "solo-a", "solo-b")

	graph := graphOf(t, GraphOptions{}, only)

	if len(graph.SharedLayers) != 0 {
		t.Fatalf("a layer in one image is not shared: %+v", graph.SharedLayers)
	}
	if graph.Summary.DistinctLayers != 2 {
		t.Fatalf("DistinctLayers = %d, want 2", graph.Summary.DistinctLayers)
	}
}

func TestBuildGraphExplainsSharedLayersWhenNoBaseCouldBeFound(t *testing.T) {
	// Sibling images from a layer-distributing builder: lots of shared content, no
	// prefix relationship. The reason must point at the analysis that does apply
	// rather than leaving the operator at a dead end.
	left := obs("reg.test/a/slim:v1", "2026-01-01T00:00:00Z", "common-a", "common-b", "left")
	right := obs("reg.test/b/dev:v1", "2026-01-01T00:00:00Z", "right", "common-a", "common-b")

	graph := graphOf(t, GraphOptions{}, left, right)

	if len(graph.Unresolved) != 2 {
		t.Fatalf("want both siblings unresolved, got %+v", graph.Unresolved)
	}
	joined := strings.Join(graph.Unresolved[0].Reasons, " ")
	if !strings.Contains(joined, "shares 2 layer(s)") {
		t.Fatalf("reason should count the shared layers, got %v", graph.Unresolved[0].Reasons)
	}
	if !strings.Contains(joined, "buildLayeredImage") {
		t.Fatalf("reason should name the common cause, got %v", graph.Unresolved[0].Reasons)
	}
	if !strings.Contains(joined, "blast radius") {
		t.Fatalf("reason should point at the applicable analysis, got %v", graph.Unresolved[0].Reasons)
	}
}

func TestBuildGraphOmitsSharedLayerHintWhenNothingIsShared(t *testing.T) {
	lonely := obs("reg.test/a/one:v1", "2026-01-01T00:00:00Z", "solo")
	other := obs("reg.test/b/two:v1", "2026-01-01T00:00:00Z", "different")

	graph := graphOf(t, GraphOptions{}, lonely, other)

	for _, entry := range graph.Unresolved {
		if strings.Contains(strings.Join(entry.Reasons, " "), "shares") {
			t.Fatalf("no shared layers, so no shared-layer hint: %v", entry.Reasons)
		}
	}
}

// A base name or a history line names the repository, not the version, so
// the graph can't tell how far behind the image is: it doesn't pick the
// oldest observed version and call the image stale.
func TestBuildGraphNameAndHistoryEdgesHaveNoDrift(t *testing.T) {
	old := obs("reg.test/base/go:v1", "2026-01-01T00:00:00Z", "os-old")
	current := obs("reg.test/base/go:v2", "2026-03-01T00:00:00Z", "os")
	named := obs("reg.test/apps/svc:v1", "2026-04-01T00:00:00Z", "squashed")
	named.Labels["org.opencontainers.image.base.name"] = "reg.test/base/go:v2"
	hist := obs("reg.test/apps/tool:v1", "2026-04-01T00:00:00Z", "squashed2")
	hist.History = []HistoryObservation{{CreatedBy: "FROM reg.test/base/go"}}

	graph := graphOf(t, GraphOptions{}, old, current, named, hist)
	for ref, method := range map[string]string{"reg.test/apps/svc:v1": MethodOCIBaseName, "reg.test/apps/tool:v1": MethodHistory} {
		edge := edgeFor(t, graph, ref)
		if edge.Method != method || edge.Drift != DriftUnknown || edge.VersionsBehind != 0 || edge.DaysBehind != 0 || edge.BaseDigest != "" {
			t.Errorf("%s: %+v", ref, edge)
		}
	}
	if e := edgeFor(t, graph, "reg.test/apps/svc:v1"); e.BaseRef != "reg.test/base/go:v2" {
		t.Errorf("a name edge names what the image claims: %q", e.BaseRef)
	}
	if graph.Summary.StaleConsumers != 0 {
		t.Errorf("stale consumers from claims: %d", graph.Summary.StaleConsumers)
	}
}
