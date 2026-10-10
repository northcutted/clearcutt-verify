package estategraph

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"sigs.k8s.io/yaml"

	"github.com/northcutted/clearcutt-verify/internal/registryauth"
)

type ImageObserver interface {
	Observe(ctx context.Context, ref string) (Observation, error)
}

// DefaultObserveConcurrency is the number of images observed at once.
//
// Observation is entirely network-bound — three to five registry round trips
// per image and no meaningful CPU — so the useful ceiling is set by registry
// rate limits, not cores. Eight is deliberately modest: it turns a serial scan
// into a roughly 8x faster one while staying well inside what an anonymous
// Docker Hub or GHCR client can sustain, because the failure mode of guessing
// too high is a 429 that fails the whole scan.
const DefaultObserveConcurrency = 8

type ObserveOptions struct {
	GeneratedAt string
	Strict      bool
	// Concurrency bounds in-flight observations. Zero applies the default; one
	// forces serial observation.
	Concurrency int
	// Previous is a prior observation set to reuse. An image whose manifest
	// digest is unchanged since Previous is not re-observed: the stored
	// observation is carried forward after a single HEAD request. See
	// DigestObserver.
	Previous *Observations
}

// ObserveStats reports what the run actually did, which is the difference
// between a scan that cost 3-5 requests per image and one that cost 1.
type ObserveStats struct {
	Observed int
	Reused   int
	Failed   int
}

// DigestObserver is an optional capability on an ImageObserver: report an
// image's manifest digest without fetching its config or per-platform
// manifests.
//
// This is what makes incremental observation worth doing. A full observation is
// three to five round trips; a digest check is one HEAD. On an estate where a
// handful of images move per day, that is the difference between re-reading
// everything and re-reading what changed.
type DigestObserver interface {
	Digest(ctx context.Context, ref string) (string, error)
}

func ObserveImages(ctx context.Context, inventory ImagesFile, observer ImageObserver, opts ObserveOptions) (Observations, ObserveStats, error) {
	generatedAt := opts.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	specs := append([]ImageSpec(nil), inventory.Images...)
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].ID < specs[j].ID })

	previous := map[string]Observation{}
	if opts.Previous != nil {
		for _, obs := range opts.Previous.Images {
			if obs.SourceRef != "" {
				previous[obs.SourceRef] = obs
			}
		}
	}
	digester, canDigest := observer.(DigestObserver)

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultObserveConcurrency
	}
	if concurrency > len(specs) {
		concurrency = len(specs)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	type outcome struct {
		observation Observation
		reused      bool
		failed      bool
		err         error
	}
	// Results are written into a slice indexed by position, so output order is
	// the sorted input order regardless of completion order. Concurrency must
	// not make the snapshot non-deterministic — its digest is the thing that
	// tells an operator whether anything changed.
	outcomes := make([]outcome, len(specs))

	var wg sync.WaitGroup
	work := make(chan int)
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				spec := specs[i]
				if prior, ok := previous[spec.Image]; ok && canDigest && prior.ManifestDigest != "" {
					if digest, err := digester.Digest(ctx, spec.Image); err == nil && digest == prior.ManifestDigest {
						outcomes[i] = outcome{observation: prior, reused: true}
						continue
					}
					// A failed or mismatched digest check falls through to a
					// full observation rather than trusting stale data.
				}
				observation, err := observer.Observe(ctx, spec.Image)
				if err != nil {
					if opts.Strict {
						outcomes[i] = outcome{err: fmt.Errorf("%s: observe %s: %w", spec.ID, spec.Image, err)}
						continue
					}
					observation = baseObservation(spec.ID, spec.Image)
					observation.Warnings = append(observation.Warnings, fmt.Sprintf("observation failed: %v", err))
					outcomes[i] = outcome{observation: observation, failed: true}
					continue
				}
				outcomes[i] = outcome{observation: observation}
			}
		}()
	}
	for i := range specs {
		work <- i
	}
	close(work)
	wg.Wait()

	result := Observations{
		APIVersion:  APIVersion,
		Kind:        "ImportedFleetObservations",
		GeneratedAt: generatedAt,
		Images:      []Observation{},
	}
	stats := ObserveStats{}
	for i, out := range outcomes {
		if out.err != nil {
			return Observations{}, ObserveStats{}, out.err
		}
		observation := out.observation
		if observation.ID == "" {
			observation.ID = specs[i].ID
		}
		if observation.SourceRef == "" {
			observation.SourceRef = specs[i].Image
		}
		normalizeObservation(&observation)
		result.Images = append(result.Images, observation)
		switch {
		case out.reused:
			stats.Reused++
		case out.failed:
			stats.Failed++
		default:
			stats.Observed++
		}
	}
	return result, stats, nil
}

func ReadObservations(path string) (Observations, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Observations{}, err
	}
	var observations Observations
	if err := yaml.Unmarshal(raw, &observations); err != nil {
		return Observations{}, err
	}
	return observations, nil
}

func WriteObservations(path string, observations Observations) error {
	return writeJSON(path, observations)
}

type FixtureObserver struct {
	byID     map[string]Observation
	bySource map[string]Observation
}

func NewFixtureObserver(observations Observations) *FixtureObserver {
	observer := &FixtureObserver{byID: map[string]Observation{}, bySource: map[string]Observation{}}
	for _, obs := range observations.Images {
		normalizeObservation(&obs)
		if obs.ID != "" {
			observer.byID[obs.ID] = obs
		}
		if obs.SourceRef != "" {
			observer.bySource[obs.SourceRef] = obs
		}
	}
	return observer
}

func (f *FixtureObserver) Observe(_ context.Context, ref string) (Observation, error) {
	if obs, ok := f.bySource[ref]; ok {
		return obs, nil
	}
	return Observation{}, fmt.Errorf("no offline fixture for %s", ref)
}

// RegistryObserver reads images from their registries, with credentials from
// the Docker keychain. Options are added to every request (a shared
// transport, for instance).
type RegistryObserver struct {
	Options []remote.Option
}

func (r RegistryObserver) options(ctx context.Context) []remote.Option {
	return append([]remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(registryauth.Keychain)}, r.Options...)
}

// Digest reports the manifest digest with a single HEAD request, fetching no
// config and no per-platform manifests. It is the cheap half of incremental
// observation: unchanged images cost one round trip instead of three to five.
func (r RegistryObserver) Digest(ctx context.Context, ref string) (string, error) {
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return "", err
	}
	desc, err := remote.Head(parsed, r.options(ctx)...)
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

func (r RegistryObserver) Observe(ctx context.Context, ref string) (Observation, error) {
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return Observation{}, err
	}
	desc, err := remote.Get(parsed, r.options(ctx)...)
	if err != nil {
		return Observation{}, err
	}
	obs := baseObservation("", ref)
	obs.ManifestDigest = desc.Digest.String()
	obs.DigestRef = parsed.Context().Name() + "@" + desc.Digest.String()
	obs.Annotations = desc.Annotations
	if desc.MediaType == types.OCIImageIndex || desc.MediaType == types.DockerManifestList {
		index, err := desc.ImageIndex()
		if err == nil {
			if manifest, err := index.IndexManifest(); err == nil {
				for _, item := range manifest.Manifests {
					if item.Platform == nil {
						continue
					}
					platform := item.Platform.OS + "/" + item.Platform.Architecture
					if item.Platform.Variant != "" {
						platform += "/" + item.Platform.Variant
					}
					obs.Platforms = append(obs.Platforms, platform)
				}
			}
		}
	}
	image, err := desc.Image()
	if err != nil {
		obs.Warnings = append(obs.Warnings, fmt.Sprintf("image config unavailable: %v", err))
		return obs, nil
	}
	fillImageObservation(&obs, image)
	return obs, nil
}

func fillImageObservation(obs *Observation, image v1.Image) {
	digest, err := image.Digest()
	if err == nil && obs.ManifestDigest == "" {
		obs.ManifestDigest = digest.String()
	}
	configDigest, err := image.ConfigName()
	if err == nil {
		obs.ConfigDigest = configDigest.String()
	}
	config, err := image.ConfigFile()
	if err == nil && config != nil {
		if config.Created.Time.Unix() > 0 {
			obs.Created = config.Created.Time.UTC().Format(time.RFC3339Nano)
		}
		obs.User = config.Config.User
		obs.Entrypoint = append([]string(nil), config.Config.Entrypoint...)
		obs.Cmd = append([]string(nil), config.Config.Cmd...)
		obs.Labels = cloneStringMap(config.Config.Labels)
		if len(obs.Platforms) == 0 && config.OS != "" && config.Architecture != "" {
			obs.Platforms = []string{config.OS + "/" + config.Architecture}
		}
		for _, hist := range config.History {
			obs.History = append(obs.History, HistoryObservation{CreatedBy: hist.CreatedBy, Comment: hist.Comment, EmptyLayer: hist.EmptyLayer})
		}
	}
	layers, err := image.Layers()
	if err == nil {
		for _, layer := range layers {
			item := LayerObservation{}
			if digest, err := layer.Digest(); err == nil {
				item.Digest = digest.String()
			}
			if size, err := layer.Size(); err == nil {
				item.Size = size
			}
			if mediaType, err := layer.MediaType(); err == nil {
				item.MediaType = string(mediaType)
			}
			obs.Layers = append(obs.Layers, item)
		}
	}
	normalizeObservation(obs)
}

func baseObservation(id, sourceRef string) Observation {
	return Observation{
		ID:          id,
		SourceRef:   sourceRef,
		Platforms:   []string{},
		Entrypoint:  []string{},
		Cmd:         []string{},
		Labels:      map[string]string{},
		Annotations: map[string]string{},
		Layers:      []LayerObservation{},
		History:     []HistoryObservation{},
		Evidence:    defaultEvidenceObservation(),
		Warnings:    []string{},
	}
}

func normalizeObservation(obs *Observation) {
	if obs.Platforms == nil {
		obs.Platforms = []string{}
	}
	sort.Strings(obs.Platforms)
	if obs.Entrypoint == nil {
		obs.Entrypoint = []string{}
	}
	if obs.Cmd == nil {
		obs.Cmd = []string{}
	}
	if obs.Labels == nil {
		obs.Labels = map[string]string{}
	}
	if obs.Annotations == nil {
		obs.Annotations = map[string]string{}
	}
	if obs.Layers == nil {
		obs.Layers = []LayerObservation{}
	}
	if obs.History == nil {
		obs.History = []HistoryObservation{}
	}
	if obs.Warnings == nil {
		obs.Warnings = []string{}
	}
	if obs.Evidence.Signature.Status == "" {
		obs.Evidence = mergeEvidenceDefaults(obs.Evidence)
	}
	if downgradeUnverifiedImportedClaims(&obs.Evidence) {
		obs.Warnings = append(obs.Warnings, "verified evidence claim downgraded to observed: imported observation does not run an evidence verifier")
	}
}

func downgradeUnverifiedImportedClaims(evidence *EvidenceObservation) bool {
	downgraded := false
	channels := []*EvidenceChannel{
		&evidence.Signature,
		&evidence.SBOM,
		&evidence.Provenance,
		&evidence.VulnerabilityScan,
		&evidence.Tests,
	}
	for _, channel := range channels {
		channel.Status = strings.ToLower(strings.TrimSpace(channel.Status))
		if channel.Status != "verified" {
			continue
		}
		channel.Status = "observed"
		if strings.TrimSpace(channel.Claim) == "" {
			channel.Claim = "Evidence was supplied to imported observation but was not verified by ClearCutt"
		}
		downgraded = true
	}
	return downgraded
}

func defaultEvidenceObservation() EvidenceObservation {
	return EvidenceObservation{
		Signature:         EvidenceChannel{Status: "missing", Source: "none", Claim: "No signature evidence inferred for imported image"},
		SBOM:              EvidenceChannel{Status: "missing", Source: "none", Claim: "Observed SBOM is not build provenance"},
		Provenance:        EvidenceChannel{Status: "missing", Source: "none", Claim: "No build provenance inferred for imported image"},
		VulnerabilityScan: EvidenceChannel{Status: "missing", Source: "none"},
		Tests:             EvidenceChannel{Status: "missing", Source: "none"},
	}
}

func mergeEvidenceDefaults(e EvidenceObservation) EvidenceObservation {
	defaults := defaultEvidenceObservation()
	if e.Signature.Status == "" {
		e.Signature = defaults.Signature
	}
	if e.SBOM.Status == "" {
		e.SBOM = defaults.SBOM
	}
	if e.Provenance.Status == "" {
		e.Provenance = defaults.Provenance
	}
	if e.VulnerabilityScan.Status == "" {
		e.VulnerabilityScan = defaults.VulnerabilityScan
	}
	if e.Tests.Status == "" {
		e.Tests = defaults.Tests
	}
	return e
}

func cloneStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
