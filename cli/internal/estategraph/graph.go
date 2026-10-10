package estategraph

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// The base-image dependency graph answers the discovery question for an estate
// nobody has inventoried, where the whole problem is that nobody knows what is
// on what: "given these observed images, which ones are built on which?" It
// uses every signal available, ranked so that the strongest signal wins:
//
//	layer-prefix        proof. The consumer's leading layer digests ARE the base's
//	                    layers. Needs no cooperation from whoever built the image and
//	                    cannot be forged by writing a label.
//	oci-base-digest     org.opencontainers.image.base.digest, the OCI standard label
//	                    BuildKit stamps automatically. Exact, but self-reported.
//	buildpacks-metadata io.buildpacks.lifecycle.metadata runImage reference. Exact,
//	                    self-reported, and only present on buildpack-built images.
//	oci-base-name       org.opencontainers.image.base.name. Names the repository but
//	                    not the version, so it locates the family and nothing more.
//	history             the base appears in the image's build history. A hint.
//
// Only the first is evidence; the rest are claims, and the graph labels them as such
// so an auditor can tell which edges are proven and which are taken on trust.
const (
	MethodLayerPrefix        = "layer-prefix"
	MethodOCIBaseDigest      = "oci-base-digest"
	MethodBuildpacksMetadata = "buildpacks-metadata"
	MethodOCIBaseName        = "oci-base-name"
	MethodHistory            = "history"
)

// methodRank orders detection methods strongest-first. Lower is stronger.
var methodRank = map[string]int{
	MethodLayerPrefix:        0,
	MethodOCIBaseDigest:      1,
	MethodBuildpacksMetadata: 2,
	MethodOCIBaseName:        3,
	MethodHistory:            4,
}

// methodConfidence maps a detection method to the confidence an auditor should place
// in the edge. "verified" is reserved for the one method that is proof.
var methodConfidence = map[string]string{
	MethodLayerPrefix:        "verified",
	MethodOCIBaseDigest:      "declared",
	MethodBuildpacksMetadata: "declared",
	MethodOCIBaseName:        "assisted",
	MethodHistory:            "weak",
}

// Drift states for a consumer relative to the newest version of its base family.
const (
	DriftCurrent = "current"
	DriftStale   = "stale"
	DriftUnknown = "unknown"
)

// GraphOptions configures graph construction.
type GraphOptions struct {
	// GeneratedAt pins the timestamp for reproducible output.
	GeneratedAt string
	// BasePatterns are globs over a repository path. When set, only matching
	// repositories may act as bases. When empty the graph self-organizes: any image
	// whose layers are a strict prefix of another's is a base for it.
	BasePatterns []string
	// MinConfidence drops edges weaker than this ("verified", "declared",
	// "assisted", "weak"). Empty keeps everything.
	MinConfidence string
	// MaxSharedLayers caps how many shared layers are retained, widest reach first.
	// Zero applies a default; a negative value keeps all of them.
	MaxSharedLayers int
}

// Graph is the discovered base/consumer relationship set for an observed estate.
type Graph struct {
	APIVersion   string            `json:"apiVersion"`
	Kind         string            `json:"kind"`
	GeneratedAt  string            `json:"generatedAt"`
	Summary      GraphSummary      `json:"summary"`
	Bases        []GraphBase       `json:"bases"`
	Edges        []GraphEdge       `json:"edges"`
	Roots        []GraphRoot       `json:"roots"`
	SharedLayers []SharedLayer     `json:"sharedLayers"`
	Unresolved   []GraphUnresolved `json:"unresolved"`
	Warnings     []string          `json:"warnings"`
}

// GraphSummary is the headline count set an audit report leads with.
type GraphSummary struct {
	ObservedImages int `json:"observedImages"`
	// Builders records how the estate was assembled. It is here because base
	// detection only applies to stacking builders, so the same "0 resolved"
	// number means opposite things on a Docker estate and a Nix one.
	Builders            BuilderProfile `json:"builders"`
	BaseFamilies        int            `json:"baseFamilies"`
	Consumers           int            `json:"consumers"`
	RootImages          int            `json:"rootImages"`
	ResolvedConsumers   int            `json:"resolvedConsumers"`
	UnresolvedConsumers int            `json:"unresolvedConsumers"`
	StaleConsumers      int            `json:"staleConsumers"`
	CurrentConsumers    int            `json:"currentConsumers"`
	EdgesByMethod       map[string]int `json:"edgesByMethod"`
	EdgesByConfidence   map[string]int `json:"edgesByConfidence"`
	DistinctLayers      int            `json:"distinctLayers"`
	SharedLayers        int            `json:"sharedLayers"`
	WidestLayerReach    int            `json:"widestLayerReach"`
}

// GraphBase is one base repository family and its published versions.
type GraphBase struct {
	Repository     string   `json:"repository"`
	Versions       int      `json:"versions"`
	CurrentRef     string   `json:"currentRef"`
	CurrentDigest  string   `json:"currentDigest,omitempty"`
	CurrentCreated string   `json:"currentCreated,omitempty"`
	Consumers      int      `json:"consumers"`
	StaleConsumers int      `json:"staleConsumers"`
	Warnings       []string `json:"warnings,omitempty"`
}

// GraphEdge is one consumer sitting on one specific version of one base.
type GraphEdge struct {
	ConsumerID        string        `json:"consumerId"`
	ConsumerRef       string        `json:"consumerRef"`
	ConsumerDigest    string        `json:"consumerDigest,omitempty"`
	BaseRepository    string        `json:"baseRepository"`
	BaseRef           string        `json:"baseRef"`
	BaseDigest        string        `json:"baseDigest,omitempty"`
	BaseCreated       string        `json:"baseCreated,omitempty"`
	CurrentBaseRef    string        `json:"currentBaseRef,omitempty"`
	CurrentBaseDigest string        `json:"currentBaseDigest,omitempty"`
	Method            string        `json:"method"`
	Confidence        string        `json:"confidence"`
	Drift             string        `json:"drift"`
	VersionsBehind    int           `json:"versionsBehind"`
	DaysBehind        int           `json:"daysBehind"`
	Signals           []GraphSignal `json:"signals"`
	Notes             []string      `json:"notes,omitempty"`
}

// GraphSignal records one detection attempt, kept on the edge so a reviewer can see
// what was tried and what it said rather than only the verdict.
type GraphSignal struct {
	Type   string `json:"type"`
	Result string `json:"result"`
	Weight string `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// SharedLayer is one content layer that appears in more than one image.
//
// This is deliberately NOT a base relationship. Images can share layers without one
// being built on the other — Nix dockerTools.buildLayeredImage distributes store
// paths across layers by popularity, so two sibling images built from the same recipe
// share most of their content while neither is a prefix of the other. Conflating that
// with layering would invent parentage that does not exist.
//
// What it answers instead is the blast-radius question an auditor actually asks: if
// this layer carries a vulnerable package, which images ship it?
type SharedLayer struct {
	Digest     string   `json:"digest"`
	Size       int64    `json:"size,omitempty"`
	ImageCount int      `json:"imageCount"`
	Images     []string `json:"images"`
}

// GraphRoot is an image that legitimately has no parent: either it is the base other
// images were proven to sit on, or the operator named its repository as a base. A
// from-scratch base image has nothing above it, and reporting it as an orphaned
// consumer would turn the healthiest images in the estate into audit findings.
type GraphRoot struct {
	ImageID    string `json:"imageId"`
	ImageRef   string `json:"imageRef"`
	Repository string `json:"repository"`
	Reason     string `json:"reason"`
	Consumers  int    `json:"consumers"`
}

// GraphUnresolved is an image no base could be found for. It is reported rather than
// dropped: "we could not determine what this is built on" is an audit finding, not
// an absence of data.
type GraphUnresolved struct {
	ConsumerID  string   `json:"consumerId"`
	ConsumerRef string   `json:"consumerRef"`
	Reasons     []string `json:"reasons"`
}

// confidenceRank orders confidence labels strongest-first for MinConfidence filtering.
var confidenceRank = map[string]int{"verified": 0, "declared": 1, "assisted": 2, "weak": 3}

// BuildGraph derives the base/consumer graph from observed images.
//
// Every image is a candidate base and a candidate consumer; an edge forms only when
// one image is strictly layered on top of another, so a base can never be reported as
// a consumer of the thing built on it.
func BuildGraph(observations Observations, opts GraphOptions) (Graph, error) {
	generatedAt := opts.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	graph := Graph{
		APIVersion:  APIVersion,
		Kind:        "BaseImageGraph",
		GeneratedAt: generatedAt,
		Summary: GraphSummary{
			EdgesByMethod:     map[string]int{},
			EdgesByConfidence: map[string]int{},
		},
		Bases:        []GraphBase{},
		Edges:        []GraphEdge{},
		SharedLayers: []SharedLayer{},
		Unresolved:   []GraphUnresolved{},
		Warnings:     []string{},
	}
	if err := validateMinConfidence(opts.MinConfidence); err != nil {
		return Graph{}, err
	}

	images := make([]Observation, 0, len(observations.Images))
	for _, obs := range observations.Images {
		normalizeObservation(&obs)
		images = append(images, obs)
	}
	sort.SliceStable(images, func(i, j int) bool { return observationKey(images[i]) < observationKey(images[j]) })
	graph.Summary.ObservedImages = len(images)
	if len(images) == 0 {
		graph.Warnings = append(graph.Warnings, "no observations supplied; nothing to graph")
		return graph, nil
	}

	families := groupIntoFamilies(images, opts.BasePatterns)
	carriers := indexLayerCarriers(images)
	pending := []GraphUnresolved{}
	for _, obs := range images {
		ref := firstNonEmpty(obs.SourceRef, obs.DigestRef)
		if len(obs.Layers) == 0 {
			pending = append(pending, GraphUnresolved{
				ConsumerID:  obs.ID,
				ConsumerRef: ref,
				Reasons:     []string{"no observed layers; the image config could not be read"},
			})
			continue
		}
		edge, reasons := bestEdgeFor(obs, families, carriers)
		if edge == nil {
			pending = append(pending, GraphUnresolved{ConsumerID: obs.ID, ConsumerRef: ref, Reasons: reasons})
			continue
		}
		if !meetsMinConfidence(edge.Confidence, opts.MinConfidence) {
			pending = append(pending, GraphUnresolved{
				ConsumerID:  obs.ID,
				ConsumerRef: ref,
				Reasons:     []string{fmt.Sprintf("best match was %q via %s, below the required minimum confidence %q", edge.Confidence, edge.Method, opts.MinConfidence)},
			})
			continue
		}
		graph.Edges = append(graph.Edges, *edge)
	}

	// An image with no parent is only an audit finding if nothing indicates it was
	// meant to be a base. Separating roots from orphans is what keeps the report
	// readable: without it, every from-scratch base in the estate shows up as an
	// image whose provenance could not be determined.
	graph.Roots, graph.Unresolved = partitionRoots(pending, graph.Edges, opts.BasePatterns)
	graph.Summary.RootImages = len(graph.Roots)
	graph.Summary.ResolvedConsumers = len(graph.Edges)
	graph.Summary.UnresolvedConsumers = len(graph.Unresolved)
	graph.Summary.Consumers = graph.Summary.ResolvedConsumers + graph.Summary.UnresolvedConsumers

	byRepository := map[string]*GraphBase{}
	for i := range graph.Edges {
		edge := &graph.Edges[i]
		graph.Summary.EdgesByMethod[edge.Method]++
		graph.Summary.EdgesByConfidence[edge.Confidence]++
		switch edge.Drift {
		case DriftStale:
			graph.Summary.StaleConsumers++
		case DriftCurrent:
			graph.Summary.CurrentConsumers++
		}
		entry, ok := byRepository[edge.BaseRepository]
		if !ok {
			family := families[edge.BaseRepository]
			entry = &GraphBase{
				Repository:     edge.BaseRepository,
				Versions:       len(family.versions),
				CurrentRef:     edge.CurrentBaseRef,
				CurrentDigest:  edge.CurrentBaseDigest,
				CurrentCreated: family.currentCreated(),
			}
			if family.undatedVersions > 0 && len(family.versions) > 1 {
				entry.Warnings = append(entry.Warnings, fmt.Sprintf("%d of %d versions carry no usable creation timestamp (absent, or zeroed by a reproducible builder); currency was decided by tag order and daysBehind is not meaningful", family.undatedVersions, len(family.versions)))
			}
			byRepository[edge.BaseRepository] = entry
		}
		entry.Consumers++
		if edge.Drift == DriftStale {
			entry.StaleConsumers++
		}
	}
	for _, entry := range byRepository {
		graph.Bases = append(graph.Bases, *entry)
	}
	graph.Summary.BaseFamilies = len(graph.Bases)

	sort.SliceStable(graph.Bases, func(i, j int) bool { return graph.Bases[i].Repository < graph.Bases[j].Repository })
	sort.SliceStable(graph.Edges, func(i, j int) bool {
		if graph.Edges[i].BaseRepository != graph.Edges[j].BaseRepository {
			return graph.Edges[i].BaseRepository < graph.Edges[j].BaseRepository
		}
		return graph.Edges[i].ConsumerRef < graph.Edges[j].ConsumerRef
	})
	graph.SharedLayers, graph.Summary.DistinctLayers = computeSharedLayers(images, opts.MaxSharedLayers)
	graph.Summary.SharedLayers = len(graph.SharedLayers)
	if len(graph.SharedLayers) > 0 {
		graph.Summary.WidestLayerReach = graph.SharedLayers[0].ImageCount
	}

	graph.Summary.Builders = ProfileBuilders(observations)
	if note := ComposedEstateNote(graph.Summary.Builders, graph.Summary.ResolvedConsumers); note != "" {
		// Prepend: on a composed estate this reframes every other number in the
		// report, so it must not arrive after a list of things that "failed".
		graph.Warnings = append([]string{note}, graph.Warnings...)
	}

	sort.SliceStable(graph.Roots, func(i, j int) bool { return graph.Roots[i].ImageRef < graph.Roots[j].ImageRef })
	sort.SliceStable(graph.Unresolved, func(i, j int) bool {
		return graph.Unresolved[i].ConsumerRef < graph.Unresolved[j].ConsumerRef
	})
	return graph, nil
}

// indexLayerCarriers counts how many observed images ship each layer digest.
func indexLayerCarriers(images []Observation) map[string]int {
	carriers := map[string]int{}
	for _, obs := range images {
		seen := map[string]struct{}{}
		for _, layer := range obs.Layers {
			if layer.Digest == "" {
				continue
			}
			if _, dup := seen[layer.Digest]; dup {
				continue
			}
			seen[layer.Digest] = struct{}{}
			carriers[layer.Digest]++
		}
	}
	return carriers
}

// sharedLayerCount reports how many of this image's layers also appear elsewhere.
func sharedLayerCount(obs Observation, carriers map[string]int) int {
	count := 0
	seen := map[string]struct{}{}
	for _, layer := range obs.Layers {
		if _, dup := seen[layer.Digest]; dup {
			continue
		}
		seen[layer.Digest] = struct{}{}
		if carriers[layer.Digest] > 1 {
			count++
		}
	}
	return count
}

const defaultMaxSharedLayers = 100

// computeSharedLayers indexes every observed layer by the images that ship it, and
// returns the ones carried by more than one image plus the distinct-layer total.
//
// The cap keeps the widest-reaching layers, which are the ones a remediation decision
// turns on: a layer in 14 images matters more than one in 2.
func computeSharedLayers(images []Observation, max int) ([]SharedLayer, int) {
	if max == 0 {
		max = defaultMaxSharedLayers
	}
	type entry struct {
		size   int64
		images map[string]struct{}
	}
	index := map[string]*entry{}
	for _, obs := range images {
		ref := firstNonEmpty(obs.SourceRef, obs.DigestRef, obs.ID)
		for _, layer := range obs.Layers {
			if layer.Digest == "" {
				continue
			}
			item, ok := index[layer.Digest]
			if !ok {
				item = &entry{size: layer.Size, images: map[string]struct{}{}}
				index[layer.Digest] = item
			}
			item.images[ref] = struct{}{}
		}
	}
	out := make([]SharedLayer, 0, len(index))
	for digest, item := range index {
		if len(item.images) < 2 {
			continue
		}
		refs := make([]string, 0, len(item.images))
		for ref := range item.images {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		out = append(out, SharedLayer{Digest: digest, Size: item.size, ImageCount: len(refs), Images: refs})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ImageCount != out[j].ImageCount {
			return out[i].ImageCount > out[j].ImageCount
		}
		return out[i].Digest < out[j].Digest
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out, len(index)
}

// partitionRoots splits parentless images into graph roots and genuine orphans.
//
// An image is a root when other images were proven to sit on it, or when the operator
// named its repository as a base via --base-repository. Everything else stays an
// orphan: ClearCutt could not determine what it was built on, and saying so plainly
// is the point of the report.
func partitionRoots(pending []GraphUnresolved, edges []GraphEdge, basePatterns []string) ([]GraphRoot, []GraphUnresolved) {
	consumersByRef := map[string]int{}
	consumersByRepo := map[string]int{}
	for _, edge := range edges {
		consumersByRef[edge.BaseRef]++
		consumersByRepo[edge.BaseRepository]++
	}
	roots := []GraphRoot{}
	orphans := []GraphUnresolved{}
	for _, entry := range pending {
		repo := repositoryOf(entry.ConsumerRef)
		switch {
		case consumersByRef[entry.ConsumerRef] > 0:
			roots = append(roots, GraphRoot{
				ImageID:    entry.ConsumerID,
				ImageRef:   entry.ConsumerRef,
				Repository: repo,
				Reason:     "other observed images were proven to be built on this image",
				Consumers:  consumersByRef[entry.ConsumerRef],
			})
		case len(basePatterns) > 0 && repositoryAllowedAsBase(repo, basePatterns):
			roots = append(roots, GraphRoot{
				ImageID:    entry.ConsumerID,
				ImageRef:   entry.ConsumerRef,
				Repository: repo,
				Reason:     "repository was declared a base by --base-repository",
				Consumers:  consumersByRef[entry.ConsumerRef],
			})
		case consumersByRepo[repo] > 0:
			// A sibling tag of this repository is serving as a base, so this version
			// is part of a base family that simply has no consumer on it yet.
			roots = append(roots, GraphRoot{
				ImageID:    entry.ConsumerID,
				ImageRef:   entry.ConsumerRef,
				Repository: repo,
				Reason:     "another version of this repository is serving as a base",
				Consumers:  0,
			})
		default:
			orphans = append(orphans, entry)
		}
	}
	return roots, orphans
}

// baseFamily is every observed version of one base repository.
type baseFamily struct {
	repository      string
	versions        []Observation // ordered oldest-first
	undatedVersions int
}

func (f *baseFamily) current() Observation {
	if len(f.versions) == 0 {
		return Observation{}
	}
	return f.versions[len(f.versions)-1]
}

func (f *baseFamily) currentCreated() string {
	return f.current().Created
}

// groupIntoFamilies buckets observations by repository and orders each bucket
// oldest-first.
//
// Currency is decided by the image config's creation timestamp, not by tag name: tags
// lie (`latest` moves, `v2` can predate `v10`) while the timestamp is baked into the
// artifact being scanned. Tag order is only the tiebreak when timestamps are absent.
func groupIntoFamilies(images []Observation, basePatterns []string) map[string]*baseFamily {
	families := map[string]*baseFamily{}
	for _, obs := range images {
		repo := repositoryOf(firstNonEmpty(obs.SourceRef, obs.DigestRef))
		if repo == "" {
			continue
		}
		if !repositoryAllowedAsBase(repo, basePatterns) {
			continue
		}
		family, ok := families[repo]
		if !ok {
			family = &baseFamily{repository: repo}
			families[repo] = family
		}
		family.versions = append(family.versions, obs)
	}
	for _, family := range families {
		for _, version := range family.versions {
			if _, dated := parseCreated(version.Created); !dated {
				family.undatedVersions++
			}
		}
		versions := family.versions
		sort.SliceStable(versions, func(i, j int) bool {
			left, leftOK := parseCreated(versions[i].Created)
			right, rightOK := parseCreated(versions[j].Created)
			if leftOK && rightOK && !left.Equal(right) {
				return left.Before(right)
			}
			if leftOK != rightOK {
				// An undated version cannot be proven newer, so it sorts older.
				return rightOK
			}
			return observationKey(versions[i]) < observationKey(versions[j])
		})
	}
	return families
}

// bestEdgeFor finds the strongest base relationship for one consumer.
func bestEdgeFor(consumer Observation, families map[string]*baseFamily, carriers map[string]int) (*GraphEdge, []string) {
	consumerRepo := repositoryOf(firstNonEmpty(consumer.SourceRef, consumer.DigestRef))
	var best *GraphEdge
	var bestRank = len(methodRank) + 1
	signals := []GraphSignal{}
	attempted := 0

	repos := make([]string, 0, len(families))
	for repo := range families {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	for _, repo := range repos {
		if repo == consumerRepo {
			// An image is never its own base. Different tags of one repository are
			// versions of the same thing, not a layering relationship.
			continue
		}
		family := families[repo]
		for _, version := range family.versions {
			attempted++
			method, detail, ok := detectRelationship(consumer, version)
			if !ok {
				continue
			}
			signals = append(signals, GraphSignal{
				Type:   method,
				Result: "matched",
				Weight: weightForMethod(method),
				Detail: detail,
			})
			rank := methodRank[method]
			if rank >= bestRank {
				continue
			}
			bestRank = rank
			best = buildEdge(consumer, family, version, method, detail)
		}
	}
	if best == nil {
		reasons := []string{}
		switch {
		case attempted == 0:
			reasons = append(reasons, "no other observed repository could act as a base")
		default:
			reasons = append(reasons, fmt.Sprintf("no base relationship detected against %d observed base versions", attempted))
		}
		if len(consumer.Labels) == 0 {
			reasons = append(reasons, "image declares no labels, so no org.opencontainers.image.base.* or buildpacks metadata was available")
		}
		if shared := sharedLayerCount(consumer, carriers); shared > 0 {
			// The most common way to reach here is a builder that distributes content
			// across layers by popularity rather than stacking a base — Nix
			// dockerTools.buildLayeredImage, notably. Saying so turns a dead end into
			// a pointer at the analysis that does apply.
			reasons = append(reasons, fmt.Sprintf("shares %d layer(s) with other observed images but sits on none of them as a base; builders that distribute content across layers rather than stacking a base (Nix dockerTools.buildLayeredImage, for one) produce this shape — see the shared-layer blast radius", shared))
		}
		return nil, reasons
	}
	sort.SliceStable(signals, func(i, j int) bool { return methodRank[signals[i].Type] < methodRank[signals[j].Type] })
	best.Signals = signals
	return best, nil
}

// buildEdge assembles the edge, including drift against the family's current version.
func buildEdge(consumer Observation, family *baseFamily, version Observation, method, detail string) *GraphEdge {
	current := family.current()
	edge := &GraphEdge{
		ConsumerID:        consumer.ID,
		ConsumerRef:       firstNonEmpty(consumer.SourceRef, consumer.DigestRef),
		ConsumerDigest:    digestOnly(firstNonEmpty(consumer.DigestRef, consumer.ManifestDigest)),
		BaseRepository:    family.repository,
		BaseRef:           firstNonEmpty(version.SourceRef, version.DigestRef),
		BaseDigest:        digestOnly(firstNonEmpty(version.DigestRef, version.ManifestDigest)),
		BaseCreated:       version.Created,
		CurrentBaseRef:    firstNonEmpty(current.SourceRef, current.DigestRef),
		CurrentBaseDigest: digestOnly(firstNonEmpty(current.DigestRef, current.ManifestDigest)),
		Method:            method,
		Confidence:        methodConfidence[method],
		Drift:             DriftUnknown,
		Signals:           []GraphSignal{},
		Notes:             []string{},
	}
	if detail != "" {
		edge.Notes = append(edge.Notes, detail)
	}

	switch {
	case edge.BaseDigest == "" || edge.CurrentBaseDigest == "":
		edge.Notes = append(edge.Notes, "drift undetermined: a digest was missing for the matched or current base version")
	case edge.BaseDigest == edge.CurrentBaseDigest:
		edge.Drift = DriftCurrent
	default:
		edge.Drift = DriftStale
		edge.VersionsBehind = versionsBehind(family, version)
		edge.DaysBehind = daysBetween(version.Created, current.Created)
	}
	if method == MethodOCIBaseName {
		edge.Notes = append(edge.Notes, "base.name names the repository but not a digest; the specific version is inferred, not proven")
	}
	return edge
}

// detectRelationship applies each detector strongest-first and returns the first hit.
func detectRelationship(consumer, base Observation) (method, detail string, ok bool) {
	if hasStrictLayerPrefix(consumer.Layers, base.Layers) {
		return MethodLayerPrefix, fmt.Sprintf("consumer's first %d layer digests match the base exactly", len(base.Layers)), true
	}
	baseDigest := digestOnly(firstNonEmpty(base.DigestRef, base.ManifestDigest))
	if baseDigest != "" {
		if declared := strings.TrimSpace(consumer.Labels["org.opencontainers.image.base.digest"]); declared != "" {
			if digestOnly(declared) == baseDigest {
				return MethodOCIBaseDigest, "org.opencontainers.image.base.digest matches the base manifest digest", true
			}
		}
		if reference, topLayer, found := buildpacksRunImage(consumer.Labels); found {
			if reference != "" && digestOnly(reference) == baseDigest {
				return MethodBuildpacksMetadata, "buildpacks lifecycle runImage reference matches the base manifest digest", true
			}
			if topLayer != "" && len(base.Layers) > 0 && base.Layers[len(base.Layers)-1].Digest == topLayer {
				return MethodBuildpacksMetadata, "buildpacks lifecycle runImage topLayer matches the base's final layer", true
			}
		}
	}
	baseRepo := repositoryOf(firstNonEmpty(base.SourceRef, base.DigestRef))
	if baseRepo != "" {
		if declared := strings.TrimSpace(consumer.Labels["org.opencontainers.image.base.name"]); declared != "" {
			if repositoryOf(declared) == baseRepo {
				return MethodOCIBaseName, "org.opencontainers.image.base.name names this base repository", true
			}
		}
		for _, hist := range consumer.History {
			haystack := strings.ToLower(hist.CreatedBy + " " + hist.Comment)
			if haystack != " " && strings.Contains(haystack, strings.ToLower(baseRepo)) {
				return MethodHistory, "the base repository appears in the consumer's build history", true
			}
		}
	}
	return "", "", false
}

// hasStrictLayerPrefix reports a true layering relationship: the consumer starts with
// every one of the base's layers AND adds at least one of its own. Equal layer sets
// mean the two images are the same content, not a base and a consumer.
func hasStrictLayerPrefix(consumerLayers, baseLayers []LayerObservation) bool {
	if len(consumerLayers) <= len(baseLayers) {
		return false
	}
	return hasLayerPrefix(consumerLayers, baseLayers)
}

// buildpacksRunImage extracts the run-image reference and top layer from the CNB
// lifecycle metadata label. Buildpack-built images are the one place a base pointer
// is guaranteed present, so reading it lets ClearCutt govern a CNB estate without
// adopting buildpacks.
func buildpacksRunImage(labels map[string]string) (reference, topLayer string, ok bool) {
	raw := strings.TrimSpace(labels["io.buildpacks.lifecycle.metadata"])
	if raw == "" {
		return "", "", false
	}
	var metadata struct {
		RunImage struct {
			TopLayer  string `json:"topLayer"`
			Reference string `json:"reference"`
			Image     string `json:"image"`
		} `json:"runImage"`
	}
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return "", "", false
	}
	reference = firstNonEmpty(metadata.RunImage.Reference, metadata.RunImage.Image)
	return reference, metadata.RunImage.TopLayer, reference != "" || metadata.RunImage.TopLayer != ""
}

// versionsBehind counts how many published versions sit between the matched version
// and the current one.
func versionsBehind(family *baseFamily, matched Observation) int {
	matchedKey := observationKey(matched)
	for i, version := range family.versions {
		if observationKey(version) == matchedKey {
			return len(family.versions) - 1 - i
		}
	}
	return 0
}

func daysBetween(from, to string) int {
	start, okStart := parseCreated(from)
	end, okEnd := parseCreated(to)
	if !okStart || !okEnd || !end.After(start) {
		return 0
	}
	return int(end.Sub(start).Hours() / 24)
}

// reproducibleBuildEpoch is the cutoff below which a creation timestamp is a
// reproducibility placeholder rather than a build time. Reproducible builders zero
// the field on purpose: Nix dockerTools stamps 1970-01-01T00:00:01Z, and the DOS/zip
// epoch (1980-01-01) is the other common choice. Treating those as real dates would
// silently rank every version of a Nix-built estate as equally old.
var reproducibleBuildEpoch = time.Date(1980, 1, 2, 0, 0, 0, 0, time.UTC)

// parseCreated returns the image's build time, and whether it carries one at all.
func parseCreated(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err := time.Parse(layout, value)
		if err != nil {
			continue
		}
		if parsed.Before(reproducibleBuildEpoch) {
			return time.Time{}, false
		}
		return parsed, true
	}
	return time.Time{}, false
}

// repositoryOf strips the tag or digest from a reference, leaving host/path.
func repositoryOf(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// A colon is only a tag separator when it comes after the last slash; a registry
	// host may legitimately carry a port (localhost:5000/app).
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i+1:], "/") {
		ref = ref[:i]
	}
	return strings.Trim(ref, "/")
}

func repositoryAllowedAsBase(repo string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if ok, err := path.Match(pattern, repo); err == nil && ok {
			return true
		}
		// Also match the bare repository name so --base-repository java21 works
		// without the caller spelling out the full registry path.
		if ok, err := path.Match(pattern, path.Base(repo)); err == nil && ok {
			return true
		}
	}
	return false
}

func weightForMethod(method string) string {
	switch methodConfidence[method] {
	case "verified":
		return "proof"
	case "declared":
		return "strong"
	case "assisted":
		return "medium"
	default:
		return "weak"
	}
}

func validateMinConfidence(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if _, ok := confidenceRank[value]; !ok {
		return fmt.Errorf("invalid minimum confidence %q; want one of verified, declared, assisted, weak", value)
	}
	return nil
}

func meetsMinConfidence(confidence, minimum string) bool {
	if strings.TrimSpace(minimum) == "" {
		return true
	}
	return confidenceRank[confidence] <= confidenceRank[minimum]
}

// observationKey is the stable identity of an observation for sorting and lookup.
func observationKey(obs Observation) string {
	return firstNonEmpty(obs.SourceRef, obs.DigestRef, obs.ID)
}

// WriteGraph persists a graph as JSON.
func WriteGraph(path string, graph Graph) error {
	return writeJSON(path, graph)
}
