package estategraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-verify/internal/registryauth"
)

// SBOMFetcher retrieves an image's SBOM. It is an interface so the expensive
// path can be tested without a registry.
type SBOMFetcher interface {
	FetchSBOM(ctx context.Context, ref string) ([]byte, error)
}

// SBOMPlan is what fetching would cost, computed before anything is fetched.
//
// This exists so the cost is a decision rather than a surprise. An estate-wide
// SBOM fetch is the most expensive thing this tool does, and an operator should
// see the number before it happens, not in their rate-limit graphs afterwards.
type SBOMPlan struct {
	// Unresolved images whose package set could not be read for free.
	Unresolved int
	// Fetches is how many requests will actually be made after deduplication.
	Fetches int
	// Saved is how many fetches deduplication avoids.
	Saved int
}

// PlanSBOMFetch reports what enriching an observation set would cost.
//
// The saving comes from content addressing: images with the same manifest
// digest have the same packages, so a tag that points at already-fetched
// content costs nothing. On an estate with many tags per image — which is the
// normal shape, since every release re-tags the same content — this is most of
// the work avoided.
func PlanSBOMFetch(observations Observations) SBOMPlan {
	plan := SBOMPlan{}
	seen := map[string]bool{}
	for _, obs := range observations.Images {
		if len(ExtractPackages(obs).Packages) > 0 {
			continue
		}
		plan.Unresolved++
		key := obs.ManifestDigest
		if key == "" {
			key = firstNonEmpty(obs.DigestRef, obs.SourceRef, obs.ID)
		}
		if seen[key] {
			plan.Saved++
			continue
		}
		seen[key] = true
		plan.Fetches++
	}
	return plan
}

// EnrichWithSBOMs fetches SBOMs for images whose package set could not be read
// for free, and folds the result into their history so ExtractPackages finds it.
//
// Results are cached by manifest digest, so identical content is fetched once
// however many tags point at it.
func EnrichWithSBOMs(ctx context.Context, observations Observations, fetcher SBOMFetcher, concurrency int) (Observations, []string, error) {
	if concurrency <= 0 {
		concurrency = DefaultObserveConcurrency
	}
	type job struct {
		index int
		ref   string
		key   string
	}
	jobs := []job{}
	for i, obs := range observations.Images {
		if len(ExtractPackages(obs).Packages) > 0 {
			continue
		}
		ref := firstNonEmpty(obs.DigestRef, obs.SourceRef)
		if ref == "" {
			continue
		}
		key := obs.ManifestDigest
		if key == "" {
			key = ref
		}
		jobs = append(jobs, job{index: i, ref: ref, key: key})
	}
	if len(jobs) == 0 {
		return observations, nil, nil
	}

	var mu sync.Mutex
	cache := map[string][]Package{}
	failures := map[string]string{}

	// One fetch per distinct content, queued once: checking a cache when a
	// job is picked up would let concurrent workers fetch the same content.
	var unique []job
	queued := map[string]bool{}
	for _, j := range jobs {
		if !queued[j.key] {
			queued[j.key] = true
			unique = append(unique, j)
		}
	}

	var wg sync.WaitGroup
	queue := make(chan job)
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				raw, err := fetcher.FetchSBOM(ctx, j.ref)
				mu.Lock()
				if err != nil {
					failures[j.key] = err.Error()
				} else if packages := ParseSBOMPackages(raw); len(packages) > 0 {
					cache[j.key] = packages
				} else {
					failures[j.key] = "SBOM contained no recognisable packages"
				}
				mu.Unlock()
			}
		}()
	}
	for _, j := range unique {
		queue <- j
	}
	close(queue)
	wg.Wait()

	enriched := observations
	enriched.Images = append([]Observation(nil), observations.Images...)
	applied := 0
	for _, j := range jobs {
		packages, ok := cache[j.key]
		if !ok {
			continue
		}
		enriched.Images[j.index] = withSBOMPackages(enriched.Images[j.index], packages)
		applied++
	}

	warnings := []string{}
	if len(failures) > 0 {
		reasons := map[string]int{}
		for _, reason := range failures {
			reasons[shortSBOMReason(reason)]++
		}
		parts := make([]string, 0, len(reasons))
		for reason, count := range reasons {
			parts = append(parts, fmt.Sprintf("%s (x%d)", reason, count))
		}
		sort.Strings(parts)
		warnings = append(warnings, fmt.Sprintf(
			"no SBOM could be read for %d distinct image(s): %s. Their packages remain UNKNOWN rather than empty.",
			len(failures), strings.Join(parts, ", ")))
	}
	if applied > 0 {
		warnings = append(warnings, fmt.Sprintf("read package sets from %d fetched SBOM(s)", len(cache)))
	}
	return enriched, warnings, nil
}

// sbomHistoryMarker tags synthesised history so the package source is
// attributable rather than being mistaken for something the builder recorded.
const sbomHistoryMarker = "clearcutt-sbom: "

// withSBOMPackages folds fetched packages into an observation.
func withSBOMPackages(obs Observation, packages []Package) Observation {
	encoded := make([]string, 0, len(packages))
	for _, pkg := range packages {
		entry := pkg.Name
		if pkg.Version != "" {
			entry += "@" + pkg.Version
		}
		encoded = append(encoded, entry)
	}
	sort.Strings(encoded)
	obs.History = append(append([]HistoryObservation(nil), obs.History...),
		HistoryObservation{Comment: sbomHistoryMarker + strings.Join(encoded, " ")})
	return obs
}

// ParseSBOMPackages reads package names and versions out of an SPDX or
// CycloneDX document. It is deliberately tolerant: an SBOM that half-parses is
// more useful than an error, and the caller reports coverage either way.
func ParseSBOMPackages(raw []byte) []Package {
	var doc struct {
		// SPDX
		Packages []struct {
			Name        string `json:"name"`
			VersionInfo string `json:"versionInfo"`
		} `json:"packages"`
		// CycloneDX
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	seen := map[string]Package{}
	add := func(name, version string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		pkg := Package{Name: name, Version: strings.TrimSpace(version)}
		seen[pkg.Key()] = pkg
	}
	for _, p := range doc.Packages {
		add(p.Name, p.VersionInfo)
	}
	for _, c := range doc.Components {
		add(c.Name, c.Version)
	}
	out := make([]Package, 0, len(seen))
	for _, pkg := range seen {
		out = append(out, pkg)
	}
	sortPackages(out)
	return out
}

func shortSBOMReason(reason string) string {
	switch {
	case strings.Contains(reason, "no recognisable packages"):
		return "SBOM had no recognisable packages"
	case strings.Contains(reason, "no SBOM"):
		return "no SBOM attached"
	case strings.Contains(reason, "MANIFEST_UNKNOWN"), strings.Contains(reason, "404"):
		return "no SBOM attached"
	default:
		return "fetch failed"
	}
}

// RegistrySBOMFetcher reads an SBOM from a registry, trying the OCI referrers
// mechanism first and falling back to the cosign sidecar tag convention.
type RegistrySBOMFetcher struct {
	remoteOpts []remote.Option
	nameOpts   []name.Option
}

func NewRegistrySBOMFetcher() *RegistrySBOMFetcher {
	return &RegistrySBOMFetcher{remoteOpts: []remote.Option{remote.WithAuthFromKeychain(registryauth.Keychain)}}
}

func NewInsecureSBOMFetcher() *RegistrySBOMFetcher {
	return &RegistrySBOMFetcher{nameOpts: []name.Option{name.Insecure}}
}

// sbomArtifactTypes are the media types an SBOM attachment identifies itself by.
var sbomArtifactTypes = map[string]bool{
	"application/spdx+json":                      true,
	"application/vnd.cyclonedx+json":             true,
	"text/spdx+json":                             true,
	"application/vnd.in-toto+json":               true,
	"application/vnd.clearcutt.evidence.v1+json": true,
}

func (f *RegistrySBOMFetcher) FetchSBOM(ctx context.Context, ref string) ([]byte, error) {
	parsed, err := name.ParseReference(ref, append([]name.Option{name.WeakValidation}, f.nameOpts...)...)
	if err != nil {
		return nil, err
	}
	opts := append([]remote.Option{remote.WithContext(ctx)}, f.remoteOpts...)
	desc, err := remote.Head(parsed, opts...)
	if err != nil {
		return nil, err
	}
	subject := parsed.Context().Digest(desc.Digest.String())

	if index, err := remote.Referrers(subject, opts...); err == nil {
		if manifest, err := index.IndexManifest(); err == nil {
			for _, entry := range manifest.Manifests {
				if !sbomArtifactTypes[entry.ArtifactType] {
					continue
				}
				if body, err := f.readFirstLayer(parsed.Context().Digest(entry.Digest.String()), opts); err == nil && len(body) > 0 {
					return body, nil
				}
			}
		}
	}
	// cosign's convention predates the Referrers API and is still the common
	// case on registries and toolchains that have not moved.
	sidecar := parsed.Context().Tag(strings.Replace(desc.Digest.String(), ":", "-", 1) + ".sbom")
	body, err := f.readFirstLayer(sidecar, opts)
	if err != nil {
		return nil, fmt.Errorf("no SBOM found via referrers or the cosign sidecar tag: %w", err)
	}
	return body, nil
}

func (f *RegistrySBOMFetcher) readFirstLayer(ref name.Reference, opts []remote.Option) ([]byte, error) {
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("attachment %s has no layers", ref)
	}
	return readSBOMLayer(layers[0])
}

func readSBOMLayer(layer v1.Layer) ([]byte, error) {
	reader, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, 64<<20))
}
