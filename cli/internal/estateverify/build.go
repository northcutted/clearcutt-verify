package estateverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

// Options configures a run.
type Options struct {
	// Name identifies the estate in the report.
	Name string
	// Version is the clearcutt-verify version writing the report.
	Version string
	Policy  report.Policy
	Sources []report.Source
	// GeneratedAt overrides the report time (RFC 3339), for reproducible output.
	GeneratedAt string
	// Concurrency bounds how many images are read at once (default 4).
	Concurrency int
	// Platforms limits which platform images are read (e.g. linux/amd64);
	// empty reads them all.
	Platforms  []string
	Discoverer *Discoverer
	Verifier   *Verifier
	// Reproducer, when set, rebuilds images from their recipes or repeats
	// their rebases (Policy.Reproduce).
	Reproducer Reproducer
	// RemoteOptions reach the registries (auth, transport).
	RemoteOptions []remote.Option
	Log           io.Writer
}

// Reproducer checks that an image rebuilds (or re-rebases) to its digest.
type Reproducer interface {
	Reproduce(ctx context.Context, ref string, signer report.Signer) (digest string, err error)
}

// Build verifies the observed estate and returns its report.
func Build(ctx context.Context, observations estategraph.Observations, opts Options) (*report.Report, error) {
	generatedAt := opts.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	graph, err := estategraph.BuildGraph(observations, estategraph.GraphOptions{GeneratedAt: generatedAt})
	if err != nil {
		return nil, fmt.Errorf("base graph: %w", err)
	}
	if opts.Discoverer == nil {
		opts.Discoverer = &Discoverer{Options: opts.RemoteOptions}
	}
	if opts.Verifier == nil {
		opts.Verifier = &Verifier{Signers: opts.Policy.TrustedSigners}
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 4
	}

	r := &report.Report{
		APIVersion: report.APIVersion,
		Kind:       report.KindReport,
		Metadata: report.Metadata{
			Name: opts.Name, GeneratedAt: generatedAt,
			Generator: report.Generator{Name: "clearcutt-verify", Version: opts.Version},
			Sources:   opts.Sources,
		},
		Policy:   opts.Policy,
		Images:   make([]report.Image, len(observations.Images)),
		Bases:    []report.Base{},
		Packages: []report.PackageUse{},
		Warnings: append([]string{}, graph.Warnings...),
	}
	if r.Metadata.Sources == nil {
		r.Metadata.Sources = []report.Source{}
	}
	if r.Policy.Required == nil {
		r.Policy.Required = []string{}
	}
	if r.Policy.TrustedSigners == nil {
		r.Policy.TrustedSigners = []report.Signer{}
	}

	ids := map[string]string{}     // digest ref / manifest digest → image ID
	created := map[string]string{} // manifest digest → creation time
	// Images that may not be made roots: ones that name a base of their
	// own, and ones whose layers couldn't be read.
	notRoots := map[string]bool{}
	for _, o := range observations.Images {
		ids[o.DigestRef] = o.ID
		ids[normalizeRepo(o.DigestRef)] = o.ID
		ids[o.ManifestDigest] = o.ID
		_, d := splitDigestRef(o.DigestRef)
		created[firstNonEmpty(d, o.ManifestDigest)] = o.Created
		created[o.ManifestDigest] = o.Created
		if len(o.Layers) == 0 {
			notRoots[o.ID] = true
		}
	}
	packagesByImage := make([][]pkg, len(observations.Images))
	namesBase := make([]bool, len(observations.Images))

	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	for i, obs := range observations.Images {
		wg.Add(1)
		go func(i int, obs estategraph.Observation) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			img, pkgs, named := buildImage(ctx, obs, graph, ids, created, opts)
			r.Images[i] = img
			packagesByImage[i] = pkgs
			namesBase[i] = named
		}(i, obs)
	}
	wg.Wait()
	for i, named := range namesBase {
		if named {
			notRoots[observations.Images[i].ID] = true
		}
	}
	sort.SliceStable(r.Images, func(i, j int) bool { return r.Images[i].ID < r.Images[j].ID })

	r.Bases = basesOf(r.Images)
	markRoots(r.Images, r.Bases, notRoots)
	r.Stacks = stacksOf(ctx, r.Images, opts)
	// Verdicts last: whether an image is a root is known only now.
	now, err := time.Parse(time.RFC3339, generatedAt)
	if err != nil {
		now = time.Now()
	}
	for i := range r.Images {
		r.Images[i].Verdict = verdictAt(r.Images[i], opts.Policy, now)
	}
	r.Packages = packageIndex(observations, packagesByImage)
	r.Summary = summarize(r)
	return r, nil
}

// buildImage verifies one image; Build decides its verdict. named says
// whether the image names a base of its own (in its annotations or its
// recipe's lock), which makes it no root.
func buildImage(ctx context.Context, obs estategraph.Observation, graph estategraph.Graph, ids, created map[string]string, opts Options) (img report.Image, pkgs []pkg, named bool) {
	repo, digest := splitDigestRef(normalizeRepo(obs.DigestRef))
	img = report.Image{
		ID: obs.ID, Repository: repo, Digest: firstNonEmpty(obs.ManifestDigest, digest), Tags: []string{},
		Created: obs.Created, Platforms: []report.Platform{}, Description: obs.Labels["org.opencontainers.image.description"],
		Warnings: append([]string{}, obs.Warnings...),
	}
	if t := tagOf(obs.SourceRef); t != "" {
		img.Tags = append(img.Tags, t)
	}
	if u := obs.Labels["org.opencontainers.image.source"]; u != "" {
		img.Source = &report.SourceRef{URL: u, Revision: obs.Labels["org.opencontainers.image.revision"], Basis: "label"}
	}
	if img.Digest == "" {
		// The image couldn't be read at all: everything about it is unknown.
		unknown := report.EvidenceItem{Status: "unknown", Detail: "The image couldn't be read; see its warnings."}
		img.Evidence = report.Evidence{Signature: unknown, SBOM: unknown, VulnerabilityScan: unknown, Provenance: unknown, Recipe: unknown, Rebase: unknown, Tests: unknown}
		img.Builder = report.Builder{Kind: "unknown", Basis: "the image couldn't be read"}
		img.Reproducibility = report.Reproducibility{Status: "not-checked", Detail: "The image couldn't be read."}
		img.Unresolved = []string{"the image couldn't be read"}
		return img, nil, false
	}

	platforms, err := platformImages(ctx, repo, img.Digest, obs, opts.RemoteOptions, opts.Platforms)
	if err != nil {
		img.Warnings = append(img.Warnings, "platform images could not be read: "+err.Error())
	}
	img.Platforms = platforms

	// The source the image claims, which signers may require the run that
	// signed to be in.
	claimedSource := firstNonEmpty(obs.Labels["org.opencontainers.image.source"], obs.Annotations["org.opencontainers.image.source"])
	ev, data := gatherEvidence(ctx, repo, img.Digest, claimedSource, platforms, opts)
	if f := data.factory; f != nil && f.Kind == "" && f.RebasedFrom != "" && data.rebaseVerified {
		test, err := originalRecipe(ctx, f, claimedSource, opts)
		if err != nil {
			img.Warnings = append(img.Warnings, "the recipe of the image it was rebased from couldn't be read: "+err.Error())
		}
		if test != "" && ev.Tests.Status == "missing" {
			// The rebase record doesn't say whether a smoke test ran, so the
			// original's declared test can't stand for the rebased image.
			ev.Tests.Detail = "No test attestation. The recipe of the image it was rebased from declares a smoke test (" + test +
				"), but the rebase record doesn't say whether the rebase ran it: clearcutt-factory runs the app's smoke test when it rebases from the app manifest (rebase -f, as its fleet workflow does), not when it rebases --image or with --no-test."
		}
	}
	baseOf(&img, obs, graph, ids, created)
	if img.Base == nil || img.Base.Strength != "proof" {
		named = claimedBase(ctx, &img, platforms, ids, data.lockBase, opts.RemoteOptions)
	}
	img.Evidence = ev
	img.Vulnerabilities = mergeVulnerabilities(data.vulns)
	if len(data.unreadableScans) > 0 {
		// Findings from some platforms only would read as the image's.
		img.Vulnerabilities = nil
		img.Warnings = append(img.Warnings, "the verified vulnerability scan of "+strings.Join(data.unreadableScans, ", ")+" couldn't be read, so its vulnerabilities are unknown")
	}
	if data.provenanceSource != nil {
		img.Source = data.provenanceSource
	}
	img.Factory = data.factory
	img.Builder = builderOf(obs, data)
	if data.packagesKnown {
		pkgs = dedupePackages(data.packages)
		n := len(pkgs)
		img.Packages = &n
		img.PackagesSource = &report.PackagesSource{Evidence: "sbom", Status: ev.SBOM.Status, Platforms: data.sbomPlatforms}
	}
	img.Reproducibility = reproduce(ctx, &img, data, opts)
	return img, pkgs, named
}

// platformImages lists the platform images of repo@digest.
func platformImages(ctx context.Context, repo, digest string, obs estategraph.Observation, ropts []remote.Option, only []string) ([]report.Platform, error) {
	ref, err := name.NewDigest(repo + "@" + digest)
	if err != nil {
		return nil, err
	}
	o := append([]remote.Option{remote.WithContext(ctx)}, ropts...)
	desc, err := remote.Get(ref, o...)
	if err != nil {
		return nil, err
	}
	describe := func(p string, img v1.Image, d string) report.Platform {
		out := report.Platform{Platform: p, Digest: d}
		if m, err := img.Manifest(); err == nil {
			out.Layers = len(m.Layers)
			for _, l := range m.Layers {
				out.Size += l.Size
			}
		}
		return out
	}
	if !desc.MediaType.IsIndex() {
		img, err := desc.Image()
		if err != nil {
			return nil, err
		}
		p := "unknown"
		if len(obs.Platforms) > 0 {
			p = obs.Platforms[0]
		}
		return []report.Platform{describe(p, img, digest)}, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var out []report.Platform
	for _, d := range im.Manifests {
		if d.Platform == nil || d.Platform.OS == "unknown" || !d.MediaType.IsImage() {
			continue // attestation manifests
		}
		p := d.Platform.OS + "/" + d.Platform.Architecture
		if d.Platform.Variant != "" {
			p += "/" + d.Platform.Variant
		}
		if len(only) > 0 && !contains(only, p) {
			continue
		}
		child, err := idx.Image(d.Digest)
		if err != nil {
			return out, err
		}
		out = append(out, describe(p, child, d.Digest.String()))
	}
	return out, nil
}

// baseOf fills the image's base, root, or unresolved reasons from the graph.
func baseOf(img *report.Image, obs estategraph.Observation, graph estategraph.Graph, ids, created map[string]string) {
	for _, e := range graph.Edges {
		if e.ConsumerID != obs.ID {
			continue
		}
		img.Base = &report.BaseLink{
			ImageID: firstNonEmpty(ids[e.BaseDigest], ids[e.BaseRepository+"@"+e.BaseDigest]), Repository: e.BaseRepository,
			Ref: e.BaseRef, Digest: e.BaseDigest, Method: e.Method, Strength: strengthOf(e.Method),
			Drift: firstNonEmpty(e.Drift, "unknown"), VersionsBehind: e.VersionsBehind, DaysBehind: e.DaysBehind,
			CurrentRef: e.CurrentBaseRef, CurrentDigest: e.CurrentBaseDigest,
		}
		if img.Base.Strength == "proof" {
			img.Base.ProvenOn = observedPlatform(obs)
		}
		// Days behind are counted between the two versions' creation times.
		img.Base.DaysBehindUnknown = e.Drift == "stale" && (!dated(e.BaseCreated) || !dated(created[e.CurrentBaseDigest]))
		return
	}
	for _, root := range graph.Roots {
		if root.ImageID == obs.ID {
			if len(obs.Layers) == 0 {
				// Nothing shows it has no base: it couldn't be read.
				img.Unresolved = []string{"no observed layers; the image config could not be read"}
				return
			}
			img.Root = root.Reason
			return
		}
	}
	for _, u := range graph.Unresolved {
		if u.ConsumerID == obs.ID {
			img.Unresolved = append([]string{}, u.Reasons...)
			return
		}
	}
}

// claimedBase checks the base an image claims, and makes the claim proof or
// rejects it: it fetches that exact base and compares layers. The claim is
// the manifest's org.opencontainers.image.base.name and .digest annotations
// (clearcutt-factory apps and other BuildKit builds record them), else the
// base pinned in a clearcutt-factory recipe's lock. This places images whose
// base tag has moved on since they were built, which comparing against the
// current tag can't. It reports whether the image names a base: one that
// does is no root, and a claim that can't be proven leaves it unresolved.
func claimedBase(ctx context.Context, img *report.Image, platforms []report.Platform, ids map[string]string, lockBase *pinnedImage, ropts []remote.Option) bool {
	if len(platforms) == 0 {
		return false
	}
	p := platforms[0]
	o := append([]remote.Option{remote.WithContext(ctx)}, ropts...)
	// unproven leaves the image without a base it names but can't be shown
	// to be built on.
	unproven := func(reason string) bool {
		if img.Base == nil {
			img.Root = ""
		}
		img.Unresolved = appendUnique(img.Unresolved, reason)
		return true
	}
	self, err := fetchManifest(img.Repository+"@"+p.Digest, o)
	if err != nil {
		if lockBase != nil {
			return unproven(fmt.Sprintf("its recipe pins %s@%s as its base, but its own manifest couldn't be read", lockBase.Ref, lockBase.Digest))
		}
		return false
	}
	baseName := self.Annotations["org.opencontainers.image.base.name"]
	baseDigest := self.Annotations["org.opencontainers.image.base.digest"]
	if (baseName == "" || baseDigest == "") && lockBase != nil {
		// The lock pins the base's index; take the image for this platform.
		baseName = lockBase.Ref
		if baseDigest, _, err = currentPlatformDigest(repoOf(lockBase.Ref)+"@"+lockBase.Digest, p.Platform, o); err != nil {
			img.Warnings = append(img.Warnings, fmt.Sprintf("the base its recipe pins (%s@%s) couldn't be read: %v", lockBase.Ref, lockBase.Digest, err))
			return unproven(fmt.Sprintf("its recipe pins %s@%s as its base, which couldn't be read", lockBase.Ref, lockBase.Digest))
		}
	}
	if baseName == "" || baseDigest == "" {
		return false
	}
	baseName = qualify(baseName)
	baseRepo := repoOf(baseName)
	base, err := fetchManifest(baseRepo+"@"+baseDigest, o)
	if err != nil {
		img.Warnings = append(img.Warnings, fmt.Sprintf("the base it names (%s@%s) couldn't be read: %v", baseRepo, baseDigest, err))
		return unproven(fmt.Sprintf("it names %s@%s as its base, which couldn't be read", baseRepo, baseDigest))
	}
	if !layerPrefix(base.Layers, self.Layers) {
		return unproven(fmt.Sprintf("its annotations name %s@%s as its base, but it doesn't start with that image's layers", baseRepo, baseDigest))
	}
	link := &report.BaseLink{
		Repository: baseRepo, Ref: baseName, Digest: baseDigest, Platform: p.Platform, ProvenOn: p.Platform,
		Method: estategraph.MethodLayerPrefix, Strength: "proof", Drift: "unknown",
		ImageID: ids[baseRepo+"@"+baseDigest],
	}
	// Where the base's tag points now, for the same platform.
	if current, created, err := currentPlatformDigest(baseName, p.Platform, o); err == nil {
		link.CurrentRef, link.CurrentDigest = baseName, current
		if current == baseDigest {
			link.Drift = "current"
		} else {
			link.Drift, link.VersionsBehind = "stale", 1
			if then, err := configCreated(baseRepo+"@"+baseDigest, o); err == nil && datedTime(created) && datedTime(then) {
				link.DaysBehind = max(0, int(created.Sub(then).Hours()/24))
			} else {
				link.DaysBehindUnknown = true
			}
		}
	}
	img.Base, img.Root, img.Unresolved = link, "", nil
	return true
}

// reproducibleEpoch is the cutoff below which a creation time is a
// reproducible build's placeholder (Nix stamps 1970-01-01T00:00:01Z, others
// the 1980 DOS epoch), not when the image was built.
var reproducibleEpoch = time.Date(1980, 1, 2, 0, 0, 0, 0, time.UTC)

// datedTime reports whether t is a real creation time.
func datedTime(t time.Time) bool {
	return !t.IsZero() && !t.Before(reproducibleEpoch)
}

// dated reports whether an RFC 3339 creation time is a real one.
func dated(s string) bool {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	return err == nil && datedTime(t)
}

func fetchManifest(ref string, o []remote.Option) (*v1.Manifest, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(r, o...)
	if err != nil {
		return nil, err
	}
	return img.Manifest()
}

func configCreated(ref string, o []remote.Option) (time.Time, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return time.Time{}, err
	}
	img, err := remote.Image(r, o...)
	if err != nil {
		return time.Time{}, err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return time.Time{}, err
	}
	return cf.Created.Time, nil
}

// currentPlatformDigest resolves ref's tag to the platform's image digest
// and its creation time.
func currentPlatformDigest(ref, platform string, o []remote.Option) (string, time.Time, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", time.Time{}, err
	}
	want, err := v1.ParsePlatform(platform)
	if err != nil {
		return "", time.Time{}, err
	}
	img, err := remote.Image(r, append(o, remote.WithPlatform(*want))...)
	if err != nil {
		return "", time.Time{}, err
	}
	d, err := img.Digest()
	if err != nil {
		return "", time.Time{}, err
	}
	var created time.Time
	if cf, err := img.ConfigFile(); err == nil {
		created = cf.Created.Time
	}
	return d.String(), created, nil
}

func layerPrefix(base, img []v1.Descriptor) bool {
	if len(base) == 0 || len(base) > len(img) {
		return false
	}
	for i := range base {
		if base[i].Digest != img[i].Digest {
			return false
		}
	}
	return true
}

// normalizeRepo names Docker Hub repositories docker.io/…, not
// index.docker.io/…, so the same repository compares equal everywhere.
func normalizeRepo(ref string) string {
	if rest, ok := strings.CutPrefix(ref, "index.docker.io/"); ok {
		return "docker.io/" + rest
	}
	return ref
}

// qualify spells out Docker Hub short names (debian:trixie-slim →
// docker.io/library/debian:trixie-slim), as observations name them.
func qualify(ref string) string {
	r, err := name.ParseReference(ref)
	if err != nil {
		return ref
	}
	repo := r.Context().Name()
	if rest, ok := strings.CutPrefix(repo, name.DefaultRegistry+"/"); ok {
		repo = "docker.io/" + rest
	}
	base, _, _ := strings.Cut(ref, "@")
	if i := strings.LastIndex(base, ":"); i > strings.LastIndex(base, "/") {
		repo += base[i:]
	}
	return repo
}

func repoOf(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

// markRoots makes an image with no base of its own a root when other images
// are built on its repository (perhaps on an older version of it): it is the
// top of their supply chain, not a gap. Images that name a base of their own,
// or whose layers couldn't be read (notRoots), stay unresolved: being built
// on doesn't show they have no base.
func markRoots(images []report.Image, bases []report.Base, notRoots map[string]bool) {
	isBase := map[string]bool{}
	for _, b := range bases {
		isBase[b.Repository] = true
	}
	for i := range images {
		img := &images[i]
		if img.Base == nil && img.Root == "" && isBase[img.Repository] && !notRoots[img.ID] {
			img.Root = "other images are proven to be built on versions of this repository"
			img.Unresolved = nil
		}
	}
}

// basesOf lists the base repositories images are built on, from the images'
// own base links.
func basesOf(images []report.Image) []report.Base {
	byRepo := map[string]*report.Base{}
	versions := map[string]map[string]bool{}
	for _, img := range images {
		b := img.Base
		if b == nil {
			continue
		}
		out, ok := byRepo[b.Repository]
		if !ok {
			out = &report.Base{Repository: b.Repository}
			byRepo[b.Repository] = out
			versions[b.Repository] = map[string]bool{}
		}
		out.Consumers++
		if b.Drift == "stale" {
			out.StaleConsumers++
		}
		versions[b.Repository][b.Digest] = true
		if out.CurrentRef == "" {
			out.CurrentRef, out.CurrentDigest, out.CurrentPlatform = firstNonEmpty(b.CurrentRef, b.Ref), b.CurrentDigest, b.Platform
		}
	}
	// The current version's creation time, when it is in the report.
	created := map[string]string{}
	for _, img := range images {
		for _, p := range img.Platforms {
			created[p.Digest] = img.Created
		}
		created[img.Digest] = img.Created
	}
	out := make([]report.Base, 0, len(byRepo))
	for repo, b := range byRepo {
		b.Versions = len(versions[repo])
		b.CurrentCreated = created[b.CurrentDigest]
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repository < out[j].Repository })
	return out
}

// observedPlatform is the platform image an observation's layers came
// from: the registry's default, linux/amd64, when the image has one.
func observedPlatform(obs estategraph.Observation) string {
	for _, p := range obs.Platforms {
		if p == "linux/amd64" {
			return p
		}
	}
	if len(obs.Platforms) > 0 {
		return obs.Platforms[0]
	}
	return ""
}

func strengthOf(method string) string {
	switch method {
	case estategraph.MethodLayerPrefix:
		return "proof"
	case estategraph.MethodOCIBaseDigest, estategraph.MethodBuildpacksMetadata:
		return "declared"
	case estategraph.MethodOCIBaseName:
		return "assisted"
	}
	return "weak"
}

// imageData is what evidence payloads told us.
type imageData struct {
	// lockBase is the base a clearcutt-factory recipe's lock pins.
	lockBase         *pinnedImage
	vulns            map[string]vulnScan
	packages         []pkg
	packagesKnown    bool
	factory          *report.Factory
	provenanceSource *report.SourceRef
	recipeSigner     *report.Signer
	rebaseSigner     *report.Signer
	recipeVerified   bool
	rebaseVerified   bool
	// sbomPlatforms are the platform images whose SBOMs were read.
	sbomPlatforms []string
	// recipeTest describes the smoke test a verified recipe declares.
	recipeTest string
	// unreadableScans are platforms whose verified vulnerability scan
	// couldn't be read.
	unreadableScans []string
	// statements are the recipes and rebase records cosign verified on the
	// image: the sha256 of each in-toto statement (the signed DSSE payload)
	// → its predicate type. Reproduction attestations name what they were
	// made from this way.
	statements map[string]string
	// attested is the reproducibility a verified reproduction attestation
	// shows; attestNote says why attached ones didn't count.
	attested   *report.Reproducibility
	attestNote string
}

// attachment is where a kind of evidence is expected.
var perPlatform = map[string]bool{KindSBOM: true, KindVulnerabilityScan: true}

// gatherEvidence discovers and verifies every kind of evidence on the image
// (index-level kinds) and its platform images (SBOMs and scans).
func gatherEvidence(ctx context.Context, repo, digest, imageSource string, platforms []report.Platform, opts Options) (report.Evidence, imageData) {
	data := imageData{vulns: map[string]vulnScan{}, statements: map[string]string{}}
	type subject struct{ platform, digest string }
	subjects := []subject{{"", digest}}
	for _, p := range platforms {
		if p.Digest != digest {
			subjects = append(subjects, subject{p.Platform, p.Digest})
		}
	}
	found := map[string][]Found{} // subject digest → evidence
	unknown := map[string]error{}
	for _, s := range subjects {
		f, err := opts.Discoverer.Discover(ctx, repo, s.digest)
		if err != nil {
			unknown[s.digest] = err
			continue
		}
		found[s.digest] = f
	}

	items := map[string]*report.EvidenceItem{}
	for _, kind := range Kinds {
		item := &report.EvidenceItem{Status: "missing"}
		items[kind] = item
		// Where to look: per-platform kinds on each platform image (or the
		// image itself when it has one platform), the rest on the top digest.
		var look []subject
		if perPlatform[kind] && len(platforms) > 0 {
			for _, p := range platforms {
				look = append(look, subject{p.Platform, p.Digest})
			}
		} else {
			look = []subject{{"", digest}}
		}
		var statuses []string
		for _, s := range look {
			st := verifyKind(ctx, repo, s.digest, kind, imageSource, found[s.digest], unknown[s.digest], opts, item, &data, s.platform)
			statuses = append(statuses, st)
			if s.platform != "" && perPlatform[kind] {
				if item.Platforms == nil {
					item.Platforms = map[string]string{}
				}
				item.Platforms[s.platform] = st
			}
		}
		item.Status = worst(statuses)
	}

	// A rebased image carries a rebase record instead of a recipe and build
	// provenance: it was never built, its layers were moved. Only a rebase
	// record a trusted signer verified (and that names the image it was
	// rebased from) stands in for the recipe: one that is present, failed,
	// or unknown is no reason to excuse a missing recipe.
	switch rebase := items[KindRebase].Status; {
	case rebase == "missing":
		items[KindRebase] = &report.EvidenceItem{Status: "not-applicable", Detail: "No rebase record: the image was built, not rebased."}
	case items[KindRecipe].Status != "missing":
	case rebase == "verified" && data.rebaseVerified:
		items[KindRecipe] = &report.EvidenceItem{Status: "not-applicable", Detail: "Rebased: the verified rebase record names the image that was built from a recipe."}
	default:
		items[KindRecipe].Detail = "No clearcutt-factory recipe. A rebase record is attached, but it is " + rebase +
			" (not a verified record naming the image it was rebased from), so it doesn't stand in for one."
	}
	if items[KindRecipe].Status == "missing" && items[KindRecipe].Detail == "" {
		items[KindRecipe].Detail = "No clearcutt-factory recipe."
	}
	if items[KindTests].Status == "missing" && data.recipeTest != "" {
		// clearcutt-factory runs the declared smoke test on every platform
		// and pushes nothing that fails it, but doesn't attest the result.
		items[KindTests] = &report.EvidenceItem{Status: "present", Source: "recipe",
			Detail: "The verified recipe declares a smoke test (" + data.recipeTest + ") that clearcutt-factory runs on every platform before it pushes; the result isn't separately attested."}
	}
	if items[KindTests].Status == "missing" {
		items[KindTests].Detail = "No test attestation."
	}
	if unknown[digest] == nil {
		data.attested, data.attestNote = attestedReproduction(ctx, repo, digest, imageSource, found[digest], opts, data.statements)
	}
	return report.Evidence{
		Signature: *items[KindSignature], SBOM: *items[KindSBOM], VulnerabilityScan: *items[KindVulnerabilityScan],
		Provenance: *items[KindProvenance], Recipe: *items[KindRecipe], Rebase: *items[KindRebase], Tests: *items[KindTests],
	}, data
}

// verifyKind verifies kind on one subject, records what the verified
// payload says, and returns the status. Only content cosign verified is
// read: an unverified copy is reported, never read.
func verifyKind(ctx context.Context, repo, digest, kind, imageSource string, found []Found, lookErr error, opts Options, item *report.EvidenceItem, data *imageData, platform string) string {
	if lookErr != nil {
		item.Detail = "The registry couldn't be read: " + lookErr.Error()
		return "unknown"
	}
	got, verified := verifyEvidence(ctx, opts.Verifier, repo, digest, kind, imageSource, found)
	if got.Status == "missing" {
		return "missing"
	}
	if item.Source == "" {
		item.Source, item.PredicateType, item.Ref, item.Timestamp, item.Signer, item.SignerWorkflow = got.Source, got.PredicateType, got.Ref, got.Timestamp, got.Signer, got.SignerWorkflow
	}
	if got.Detail != "" {
		item.Detail = got.Detail
	}
	if len(verified) == 0 {
		return got.Status
	}
	best := verified[0]
	signer := best.signer
	pred := best.Predicate()
	if kind == KindRecipe || kind == KindRebase {
		for _, c := range verified {
			data.statements[statementDigest(c.Statement)] = c.PredicateType
		}
	}
	switch kind {
	case KindVulnerabilityScan:
		if s, ok := readVulnPredicate(pred); ok {
			data.vulns[firstNonEmpty(platform, "default")] = s
		} else {
			data.unreadableScans = append(data.unreadableScans, firstNonEmpty(platform, "default"))
		}
	case KindSBOM:
		if pkgs, ok := readSBOM(pred); ok {
			data.packages = append(data.packages, pkgs...)
			data.packagesKnown = true
			if platform != "" {
				data.sbomPlatforms = append(data.sbomPlatforms, platform)
			}
		}
	case KindRecipe:
		if fi, base, ok := readRecipe(pred); ok {
			data.factory = fi
			data.recipeVerified = true
			data.recipeSigner = &signer
			data.lockBase = base
			data.recipeTest = recipeTest(pred)
		}
	case KindRebase:
		if fi, ok := readRebase(pred); ok {
			if data.factory == nil {
				data.factory = fi
			} else {
				data.factory.RebasedFrom = fi.RebasedFrom
			}
			data.rebaseVerified = true
			data.rebaseSigner = &signer
		}
	case KindProvenance:
		if s, ok := readProvenanceSource(pred); ok {
			data.provenanceSource = s
		}
	}
	return got.Status
}

// originalRecipe names a rebased image after the recipe it was first built
// from: a rebase record names only the image whose layers moved, so it
// follows verified rebase records back (an image may have been rebased more
// than once) to a verified recipe, and reads its kind, name, and stack (the
// stack version the app's layers were built with, which a rebase keeps). It
// returns the smoke test that recipe declares. Each step is read only from
// evidence cosign verified against the image signers.
func originalRecipe(ctx context.Context, f *report.Factory, imageSource string, opts Options) (test string, err error) {
	ref := f.RebasedFrom
	for range 8 {
		repo, digest := splitDigestRef(ref)
		if repo == "" || digest == "" {
			return "", fmt.Errorf("%q is not repository@digest", ref)
		}
		found, err := opts.Discoverer.Discover(ctx, repo, digest)
		if err != nil {
			return "", err
		}
		if item, verified := verifyEvidence(ctx, opts.Verifier, repo, digest, KindRecipe, imageSource, found); item.Status != "missing" {
			if len(verified) == 0 {
				return "", fmt.Errorf("recipe of %s is %s: %s", ref, item.Status, item.Detail)
			}
			pred := verified[0].Predicate()
			r, _, ok := readRecipe(pred)
			if !ok {
				return "", fmt.Errorf("recipe of %s is unreadable", ref)
			}
			f.Kind, f.Name, f.Stack, f.StackRef, f.StackDigest = r.Kind, r.Name, r.Stack, r.StackRef, r.StackDigest
			return recipeTest(pred), nil
		}
		item, verified := verifyEvidence(ctx, opts.Verifier, repo, digest, KindRebase, imageSource, found)
		if item.Status == "missing" {
			return "", fmt.Errorf("%s has neither a recipe nor a rebase record", ref)
		}
		if len(verified) == 0 {
			return "", fmt.Errorf("rebase record of %s is %s: %s", ref, item.Status, item.Detail)
		}
		r, ok := readRebase(verified[0].Predicate())
		if !ok {
			return "", fmt.Errorf("rebase record of %s is unreadable", ref)
		}
		ref = r.RebasedFrom
	}
	return "", fmt.Errorf("gave up following rebase records at %s", ref)
}

// sourceName says how evidence is stored, from what can be seen without
// reading its content.
func sourceName(f Found) string {
	switch {
	case f.Format == FormatRawReferrer:
		return "oci-referrer"
	case f.Kind == KindSignature:
		return "cosign-signature"
	}
	return "cosign-attestation"
}

// githubBuildType is the build type of the SLSA provenance GitHub artifact
// attestations carry (actions/attest-build-provenance).
const githubBuildType = "https://actions.github.io/buildtypes/workflow/v1"

// verifiedSourceName says where verified evidence came from. A GitHub
// artifact attestation (actions/attest-build-provenance, pushed to the
// registry) is a Sigstore bundle like cosign's; its verified content tells
// it apart: SLSA provenance of GitHub's workflow build type. Unverified
// copies aren't read, so they keep their storage name.
func verifiedSourceName(c verifiedCopy) string {
	if c.Kind == KindProvenance && c.Format == FormatBundle {
		var p struct {
			BuildDefinition struct {
				BuildType string `json:"buildType"`
			} `json:"buildDefinition"`
		}
		if json.Unmarshal(c.Predicate(), &p) == nil && p.BuildDefinition.BuildType == githubBuildType {
			return "github-attestation"
		}
	}
	return sourceName(c.Found)
}

// signerWorkflow is the GitHub Actions workflow a verified signer's identity
// names, without its scheme and ref (github.com/OWNER/REPO/.github/workflows/
// FILE), as gh attestation verify --signer-workflow takes it; "" for other
// signers.
func signerWorkflow(s report.Signer) string {
	if s.Issuer != githubIssuer {
		return ""
	}
	rest, ok := strings.CutPrefix(s.Identity, "https://")
	if !ok {
		return ""
	}
	wf, _, ok := strings.Cut(rest, "@")
	if !ok || !strings.Contains(wf, "/.github/workflows/") {
		return ""
	}
	return wf
}

// worst returns the most concerning status (failed, missing, unknown,
// present, verified).
func worst(statuses []string) string {
	rank := map[string]int{"verified": 0, "present": 1, "unknown": 2, "missing": 3, "failed": 4}
	out := "missing"
	best := -1
	for _, s := range statuses {
		if rank[s] > best {
			best, out = rank[s], s
		}
	}
	return out
}

func builderOf(obs estategraph.Observation, data imageData) report.Builder {
	switch {
	case data.factory != nil && data.factory.RebasedFrom != "":
		return report.Builder{Kind: "clearcutt-factory", Basis: "clearcutt-factory rebase record"}
	case data.factory != nil:
		return report.Builder{Kind: "clearcutt-factory", Basis: "clearcutt-factory recipe"}
	}
	b := estategraph.DetectBuilder(obs)
	if b.Name == "" {
		return report.Builder{Kind: "unknown", Basis: "nothing in the image's metadata identifies its builder"}
	}
	return report.Builder{Kind: b.Name, Basis: "image metadata (history, labels, layer layout)"}
}

// reproduce reports whether an image reproduces: as a verified reproduction
// attestation shows, without rebuilding it, or, when the policy asks for it,
// by rebuilding it from its verified recipe or repeating its verified rebase.
func reproduce(ctx context.Context, img *report.Image, data imageData, opts Options) report.Reproducibility {
	found := func(s string) bool { return s == "verified" || s == "present" || s == "failed" }
	hasRecipe, hasRebase := found(img.Evidence.Recipe.Status), found(img.Evidence.Rebase.Status)
	if !hasRecipe && !hasRebase {
		if img.Evidence.Recipe.Status == "unknown" || img.Evidence.Rebase.Status == "unknown" {
			return report.Reproducibility{Status: "not-checked", Detail: "Its recipe or rebase record couldn't be read."}
		}
		return report.Reproducibility{Status: "no-recipe"}
	}
	if data.attested != nil {
		return *data.attested
	}
	r := reproduceLocally(ctx, img, data, opts, hasRebase)
	if data.attestNote != "" {
		r.Detail = strings.TrimSpace(r.Detail + " " + data.attestNote)
	}
	return r
}

// reproduceLocally rebuilds an image from its verified recipe, or repeats
// its verified rebase, when the policy asks for it.
func reproduceLocally(ctx context.Context, img *report.Image, data imageData, opts Options, hasRebase bool) report.Reproducibility {
	method, verified, signer := "recipe-rebuild", data.recipeVerified, data.recipeSigner
	if hasRebase {
		method, verified, signer = "rebase-repeat", data.rebaseVerified, data.rebaseSigner
	}
	if !opts.Policy.Reproduce || opts.Reproducer == nil {
		return report.Reproducibility{Status: "not-checked", Method: method}
	}
	if !verified || signer == nil {
		return report.Reproducibility{Status: "not-checked", Method: method, Detail: "Only verified recipes and rebase records are reproduced."}
	}
	// The rebuild verifies the recipe (or rebase record) again: bind it to
	// the signer this report shows verified it, exactly.
	bound := report.Signer{Key: signer.Key, Tlog: signer.Tlog}
	if signer.Key == "" {
		bound = report.Signer{Identity: signer.Identity, Issuer: signer.Issuer, SourceRepository: signer.SourceRepository}
	}
	got, err := opts.Reproducer.Reproduce(ctx, img.Repository+"@"+img.Digest, bound)
	r := report.Reproducibility{Method: method, CheckedAt: time.Now().UTC().Format(time.RFC3339), Digest: got, Source: "rebuild"}
	switch {
	case got == img.Digest:
		r.Status = "reproduced"
	case got != "":
		r.Status, r.Detail = "not-reproduced", "Rebuilt "+got+", not "+img.Digest+"."
	default:
		// No digest: the rebuild didn't finish, so whether the image
		// reproduces is still undecided.
		r.Status, r.Detail, r.Source = "not-checked", "The rebuild couldn't finish: "+err.Error(), ""
	}
	return r
}

func dedupePackages(pkgs []pkg) []pkg {
	seen := map[string]bool{}
	var out []pkg
	for _, p := range pkgs {
		key := p.Type + "|" + p.Name + "|" + p.Version
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// packageIndex lists each package version with the images that ship it.
func packageIndex(observations estategraph.Observations, byImage [][]pkg) []report.PackageUse {
	idx := map[string]*report.PackageUse{}
	for i, pkgs := range byImage {
		id := observations.Images[i].ID
		for _, p := range pkgs {
			key := p.Type + "|" + p.Name + "|" + p.Version
			u, ok := idx[key]
			if !ok {
				u = &report.PackageUse{Name: p.Name, Version: p.Version, Type: p.Type, PURL: stripQualifiers(p.PURL), Images: []string{}}
				idx[key] = u
			}
			u.Images = appendUnique(u.Images, id)
		}
	}
	out := make([]report.PackageUse, 0, len(idx))
	for _, u := range idx {
		sort.Strings(u.Images)
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// stripQualifiers drops a purl's per-platform qualifiers (?arch=…) so one
// package version has one purl.
func stripQualifiers(purl string) string {
	p, _, _ := strings.Cut(purl, "?")
	return p
}

func splitDigestRef(ref string) (string, string) {
	repo, digest, _ := strings.Cut(ref, "@")
	return repo, digest
}

func tagOf(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[i+1:]
	}
	return ""
}
