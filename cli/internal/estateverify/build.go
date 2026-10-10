package estateverify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
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

	ids := map[string]string{} // digest ref / manifest digest → image ID
	for _, o := range observations.Images {
		ids[o.DigestRef] = o.ID
		ids[normalizeRepo(o.DigestRef)] = o.ID
		ids[o.ManifestDigest] = o.ID
	}
	packagesByImage := make([][]pkg, len(observations.Images))

	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	for i, obs := range observations.Images {
		wg.Add(1)
		go func(i int, obs estategraph.Observation) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			img, pkgs := buildImage(ctx, obs, graph, ids, opts)
			r.Images[i] = img
			packagesByImage[i] = pkgs
		}(i, obs)
	}
	wg.Wait()
	sort.SliceStable(r.Images, func(i, j int) bool { return r.Images[i].ID < r.Images[j].ID })

	r.Bases = basesOf(r.Images)
	markRoots(r.Images, r.Bases)
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

// buildImage verifies one image; Build decides its verdict.
func buildImage(ctx context.Context, obs estategraph.Observation, graph estategraph.Graph, ids map[string]string, opts Options) (report.Image, []pkg) {
	repo, digest := splitDigestRef(normalizeRepo(obs.DigestRef))
	img := report.Image{
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
		return img, nil
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
		if err := originalRecipe(ctx, f, claimedSource, opts); err != nil {
			img.Warnings = append(img.Warnings, "the recipe of the image it was rebased from couldn't be read: "+err.Error())
		}
	}
	baseOf(&img, obs, graph, ids)
	if img.Base == nil || img.Base.Strength != "proof" {
		claimedBase(ctx, &img, platforms, ids, data.lockBase, opts.RemoteOptions)
	}
	img.Evidence = ev
	img.Vulnerabilities = mergeVulnerabilities(data.vulns)
	if data.provenanceSource != nil {
		img.Source = data.provenanceSource
	}
	img.Factory = data.factory
	img.Builder = builderOf(obs, data)
	var pkgs []pkg
	if data.packagesKnown {
		pkgs = dedupePackages(data.packages)
		n := len(pkgs)
		img.Packages = &n
	}
	img.Reproducibility = reproduce(ctx, &img, data, opts)
	return img, pkgs
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
func baseOf(img *report.Image, obs estategraph.Observation, graph estategraph.Graph, ids map[string]string) {
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
		return
	}
	for _, root := range graph.Roots {
		if root.ImageID == obs.ID {
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
// current tag can't.
func claimedBase(ctx context.Context, img *report.Image, platforms []report.Platform, ids map[string]string, lockBase *pinnedImage, ropts []remote.Option) {
	if len(platforms) == 0 {
		return
	}
	p := platforms[0]
	o := append([]remote.Option{remote.WithContext(ctx)}, ropts...)
	self, err := fetchManifest(img.Repository+"@"+p.Digest, o)
	if err != nil {
		return
	}
	baseName := self.Annotations["org.opencontainers.image.base.name"]
	baseDigest := self.Annotations["org.opencontainers.image.base.digest"]
	if (baseName == "" || baseDigest == "") && lockBase != nil {
		// The lock pins the base's index; take the image for this platform.
		baseName = lockBase.Ref
		if baseDigest, _, err = currentPlatformDigest(repoOf(lockBase.Ref)+"@"+lockBase.Digest, p.Platform, o); err != nil {
			img.Warnings = append(img.Warnings, fmt.Sprintf("the base its recipe pins (%s@%s) couldn't be read: %v", lockBase.Ref, lockBase.Digest, err))
			return
		}
	}
	if baseName == "" || baseDigest == "" {
		return
	}
	baseName = qualify(baseName)
	baseRepo := repoOf(baseName)
	base, err := fetchManifest(baseRepo+"@"+baseDigest, o)
	if err != nil {
		img.Warnings = append(img.Warnings, fmt.Sprintf("the base it names (%s@%s) couldn't be read: %v", baseRepo, baseDigest, err))
		return
	}
	if !layerPrefix(base.Layers, self.Layers) {
		img.Unresolved = appendUnique(img.Unresolved, fmt.Sprintf("its annotations name %s@%s as its base, but it doesn't start with that image's layers", baseRepo, baseDigest))
		return
	}
	link := &report.BaseLink{
		Repository: baseRepo, Ref: baseName, Digest: baseDigest,
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
			if then, err := configCreated(baseRepo+"@"+baseDigest, o); err == nil && !created.IsZero() && !then.IsZero() {
				link.DaysBehind = max(0, int(created.Sub(then).Hours()/24))
			}
		}
	}
	img.Base, img.Root, img.Unresolved = link, "", nil
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
// top of their supply chain, not a gap.
func markRoots(images []report.Image, bases []report.Base) {
	isBase := map[string]bool{}
	for _, b := range bases {
		isBase[b.Repository] = true
	}
	for i := range images {
		img := &images[i]
		if img.Base == nil && img.Root == "" && isBase[img.Repository] {
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
			out.CurrentRef, out.CurrentDigest = firstNonEmpty(b.CurrentRef, b.Ref), b.CurrentDigest
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
	// claimedSource is the repository the image names as its source.
	claimedSource string
}

// attachment is where a kind of evidence is expected.
var perPlatform = map[string]bool{KindSBOM: true, KindVulnerabilityScan: true}

// gatherEvidence discovers and verifies every kind of evidence on the image
// (index-level kinds) and its platform images (SBOMs and scans).
func gatherEvidence(ctx context.Context, repo, digest, imageSource string, platforms []report.Platform, opts Options) (report.Evidence, imageData) {
	data := imageData{vulns: map[string]vulnScan{}, claimedSource: imageSource}
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
	// provenance: it was never built, its layers were moved.
	if items[KindRebase].Status == "missing" {
		items[KindRebase] = &report.EvidenceItem{Status: "not-applicable", Detail: "No rebase record: the image was built, not rebased."}
	} else if items[KindRecipe].Status == "missing" {
		items[KindRecipe] = &report.EvidenceItem{Status: "not-applicable", Detail: "Rebased: the rebase record names the image that was built from a recipe."}
	}
	if items[KindRecipe].Status == "missing" {
		items[KindRecipe].Detail = "No clearcutt-factory recipe."
	}
	if items[KindTests].Status == "missing" {
		items[KindTests].Detail = "No test attestation."
	}
	return report.Evidence{
		Signature: *items[KindSignature], SBOM: *items[KindSBOM], VulnerabilityScan: *items[KindVulnerabilityScan],
		Provenance: *items[KindProvenance], Recipe: *items[KindRecipe], Rebase: *items[KindRebase], Tests: *items[KindTests],
	}, data
}

// verifyKind finds and verifies kind on one subject, records what the
// payload says, and returns the status.
func verifyKind(ctx context.Context, repo, digest, kind, imageSource string, found []Found, lookErr error, opts Options, item *report.EvidenceItem, data *imageData, platform string) string {
	if lookErr != nil {
		item.Detail = "The registry couldn't be read: " + lookErr.Error()
		return "unknown"
	}
	f, ok := newest(found, kind, digest)
	if !ok {
		return "missing"
	}
	if item.Source == "" {
		item.Source = sourceName(f)
		item.PredicateType = f.PredicateType
		item.Ref = f.Ref
		item.Timestamp = f.Timestamp
		item.Signer = f.Signer
	}

	status, detail := check(ctx, opts.Verifier, repo+"@"+digest, f, imageSource)
	if detail != "" {
		item.Detail = detail
	}

	// Read the payload. Present evidence is still read, but the verdict
	// only credits what was verified.
	pred := f.Predicate()
	if f.Format == FormatRawReferrer {
		pred = f.Statement
	}
	switch kind {
	case KindVulnerabilityScan:
		if s, ok := readVulnPredicate(pred); ok {
			data.vulns[firstNonEmpty(platform, "default")] = s
		}
	case KindSBOM:
		if pkgs, ok := readSBOM(pred); ok {
			data.packages = append(data.packages, pkgs...)
			data.packagesKnown = true
		}
	case KindRecipe:
		if fi, base, ok := readRecipe(pred); ok {
			data.factory = fi
			data.recipeVerified = status == "verified"
			data.recipeSigner = f.Signer
			if status == "verified" {
				data.lockBase = base
			}
		}
	case KindRebase:
		if fi, ok := readRebase(pred); ok {
			if data.factory == nil {
				data.factory = fi
			} else {
				data.factory.RebasedFrom = fi.RebasedFrom
			}
			data.rebaseVerified = status == "verified"
			data.rebaseSigner = f.Signer
		}
	case KindProvenance:
		if s, ok := readProvenanceSource(pred); ok && status == "verified" {
			data.provenanceSource = s
		}
	}
	return status
}

// newest returns the newest evidence of kind on digest: republished
// evidence supersedes older copies.
func newest(found []Found, kind, digest string) (Found, bool) {
	var candidates []Found
	for _, f := range found {
		if f.Kind == kind && (f.Subject == "" || f.Subject == digest) {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		return Found{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Timestamp > candidates[j].Timestamp })
	return candidates[0], true
}

// originalRecipe names a rebased image after the recipe it was first built
// from: a rebase record names only the image whose layers moved, so it
// follows verified rebase records back (an image may have been rebased more
// than once) to a verified recipe, and reads its kind, name, and stack.
func originalRecipe(ctx context.Context, f *report.Factory, imageSource string, opts Options) error {
	ref := f.RebasedFrom
	for range 8 {
		repo, digest := splitDigestRef(ref)
		if repo == "" || digest == "" {
			return fmt.Errorf("%q is not repository@digest", ref)
		}
		found, err := opts.Discoverer.Discover(ctx, repo, digest)
		if err != nil {
			return err
		}
		if e, ok := newest(found, KindRecipe, digest); ok {
			if status, detail := check(ctx, opts.Verifier, ref, e, imageSource); status != "verified" {
				return fmt.Errorf("recipe of %s is %s: %s", ref, status, detail)
			}
			r, _, ok := readRecipe(e.Predicate())
			if !ok {
				return fmt.Errorf("recipe of %s is unreadable", ref)
			}
			f.Kind, f.Name, f.Stack = r.Kind, r.Name, r.Stack
			return nil
		}
		e, ok := newest(found, KindRebase, digest)
		if !ok {
			return fmt.Errorf("%s has neither a recipe nor a rebase record", ref)
		}
		if status, detail := check(ctx, opts.Verifier, ref, e, imageSource); status != "verified" {
			return fmt.Errorf("rebase record of %s is %s: %s", ref, status, detail)
		}
		r, ok := readRebase(e.Predicate())
		if !ok {
			return fmt.Errorf("rebase record of %s is unreadable", ref)
		}
		ref = r.RebasedFrom
	}
	return fmt.Errorf("gave up following rebase records at %s", ref)
}

// check verifies evidence found on ref and returns its status (verified,
// present, or failed) and, when it isn't verified, why.
func check(ctx context.Context, v *Verifier, ref string, f Found, imageSource string) (status, detail string) {
	if f.Format == FormatRawReferrer {
		return "present", "An unsigned document; nothing to verify."
	}
	trusted, err := v.Verify(ctx, Subject{Ref: ref, Kind: f.Kind, PredicateType: f.PredicateType, ImageSource: imageSource, Signer: f.Signer})
	switch {
	case errors.Is(err, ErrNoSigner):
		return "present", "No trusted signer is configured, so it can't be verified."
	case err != nil:
		return "failed", err.Error()
	}
	// A reusable workflow signs with its own identity wherever it is
	// called from; trusting the identity alone trusts every caller.
	if caller, ok := calledFromElsewhere(f.Signer); ok && !constrainsCaller(trusted) {
		return "present", fmt.Sprintf("Signed by %s, called from %s. The trusted signer doesn't say which calling repositories it accepts, "+
			"so a run in any repository calling that workflow would verify too: set sourceRepository, sourceRepositoryOwner, or sourceMatchesImage.", f.Signer.Identity, caller)
	}
	return "verified", ""
}

func sourceName(f Found) string {
	switch {
	case f.Format == FormatRawReferrer:
		return "oci-referrer"
	case f.Kind == KindSignature:
		return "cosign-signature"
	case f.Kind == KindProvenance && f.Signer != nil && strings.Contains(f.Signer.Identity, "/attest-build-provenance"):
		return "github-attestation"
	}
	return "cosign-attestation"
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

// reproduce rebuilds an image from its verified recipe, or repeats its
// verified rebase, when the policy asks for it.
func reproduce(ctx context.Context, img *report.Image, data imageData, opts Options) report.Reproducibility {
	found := func(s string) bool { return s == "verified" || s == "present" || s == "failed" }
	hasRecipe, hasRebase := found(img.Evidence.Recipe.Status), found(img.Evidence.Rebase.Status)
	if !hasRecipe && !hasRebase {
		if img.Evidence.Recipe.Status == "unknown" || img.Evidence.Rebase.Status == "unknown" {
			return report.Reproducibility{Status: "not-checked", Detail: "Its recipe or rebase record couldn't be read."}
		}
		return report.Reproducibility{Status: "no-recipe"}
	}
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
	trusted := trustedSignerFor(*signer, opts.Policy.TrustedSigners)
	// The rebuild verifies the recipe again; bind it to the same repository.
	if repo, err := resolveRepository(trusted, Subject{ImageSource: data.claimedSource, Signer: signer}); err == nil && repo != "" {
		trusted.SourceRepository, trusted.SourceRepositoryOwner, trusted.SourceMatchesImage = repo, "", false
	}
	got, err := opts.Reproducer.Reproduce(ctx, img.Repository+"@"+img.Digest, trusted)
	r := report.Reproducibility{Method: method, CheckedAt: time.Now().UTC().Format(time.RFC3339), Digest: got}
	switch {
	case got == img.Digest:
		r.Status = "reproduced"
	case got != "":
		r.Status, r.Detail = "not-reproduced", "Rebuilt "+got+", not "+img.Digest+"."
	default:
		// No digest: the rebuild didn't finish, so whether the image
		// reproduces is still undecided.
		r.Status, r.Detail = "not-checked", "The rebuild couldn't finish: "+err.Error()
	}
	return r
}

// trustedSignerFor returns the policy signer that matches a certificate's
// identity (what cosign is told to require when reproducing).
func trustedSignerFor(cert report.Signer, trusted []report.Signer) report.Signer {
	for _, t := range trusted {
		if t.Issuer != "" && t.Issuer != cert.Issuer {
			continue
		}
		if t.Identity != "" && t.Identity == cert.Identity {
			return t
		}
		if t.IdentityRegexp != "" {
			if re, err := regexp.Compile(t.IdentityRegexp); err == nil && re.MatchString(cert.Identity) {
				return t
			}
		}
	}
	return report.Signer{Identity: cert.Identity, Issuer: cert.Issuer}
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
