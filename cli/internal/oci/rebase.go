package oci

import (
	"fmt"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// RebaseOptions describes a `clearcutt-verify app rebase`: swap the base layers underneath
// an application image for a new base, preserving every application layer
// byte-for-byte. The old base is fetched precisely (digest-pinned) from the app's
// own LabelBaseRef unless OldBaseRef overrides it.
type RebaseOptions struct {
	AppRef         string // developer application image (--image)
	NewBaseRef     string // replacement base (--candidate-base)
	OldBaseRef     string // optional override; default reads LabelBaseRef off the app
	NewBaseID      string // new base catalog id, stamped into the rebased labels
	NewBaseVersion string // new base version, stamped into the rebased labels
	TargetRef      string // where to push the rebased artifact (--tag)
}

// RebaseResult captures everything the attestation predicate needs, plus the
// in-memory artifact (for tests to introspect before it is pushed).
type RebaseResult struct {
	SourceDigest       string
	NewDigest          string
	NewRef             string // digest-pinned reference of the pushed rebased artifact
	OldBaseDigest      string
	NewBaseDigest      string
	PreservedAppLayers []string
	RemovedBaseLayers  []string
	AddedBaseLayers    []string
	IsIndex            bool
	Image              v1.Image      // set when IsIndex is false
	Index              v1.ImageIndex // set when IsIndex is true
}

// AppMeta is the lifecycle metadata read off an application image's labels, used by
// callers to run the ABI-compatibility gate and dual-control verification before
// committing to a rebase.
type AppMeta struct {
	BaseID        string
	BaseVersion   string
	BaseRef       string
	BaseLastLayer string
	Rebasable     bool
	// SourceRef is the digest-pinned reference of the application image itself, so a
	// caller can verify the original developer signature over the exact source.
	SourceRef string
}

// ReadAppMeta resolves an application reference and returns its lifecycle labels. For
// a multi-arch app it reads the labels off the linux/amd64 child (labels are uniform
// across arches for a ClearCutt-built app).
func (c *Client) ReadAppMeta(ref string) (*AppMeta, error) {
	res, err := c.Pull(ref)
	if err != nil {
		return nil, err
	}
	img, err := c.resolveBaseImage(res)
	if err != nil {
		return nil, err
	}
	labels, err := imageLabels(img)
	if err != nil {
		return nil, err
	}
	sourceRef := ""
	if d, err := res.ManifestDigest(); err == nil {
		sourceRef = res.Ref.Context().Name() + "@" + d
	}
	return &AppMeta{
		BaseID:        labels[LabelBaseID],
		BaseVersion:   labels[LabelBaseVersion],
		BaseRef:       labels[LabelBaseRef],
		BaseLastLayer: labels[LabelBaseLastLayer],
		Rebasable:     labels[LabelRebasable] == "true",
		SourceRef:     sourceRef,
	}, nil
}

// Rebase performs the base swap and pushes the result to TargetRef. It rejects any
// app that is not marked rebasable, or whose recorded base boundary does not match
// the old base — and mutate.Rebase independently verifies (by diff_id) that the app
// layers sit exactly on top of the old base, so a tampered image cannot be rebased.
func (c *Client) Rebase(opts RebaseOptions) (*RebaseResult, error) {
	if opts.AppRef == "" || opts.NewBaseRef == "" || opts.TargetRef == "" {
		return nil, fmt.Errorf("Rebase requires AppRef, NewBaseRef and TargetRef")
	}

	app, err := c.Pull(opts.AppRef)
	if err != nil {
		return nil, err
	}
	sourceDigest, err := app.ManifestDigest()
	if err != nil {
		return nil, err
	}

	var overrideOldBase *Resolved
	if opts.OldBaseRef != "" {
		overrideOldBase, err = c.Pull(opts.OldBaseRef)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch old base override %q: %w", opts.OldBaseRef, err)
		}
	}
	newBase, err := c.Pull(opts.NewBaseRef)
	if err != nil {
		return nil, err
	}
	newBaseRepo := newBase.Ref.Context().Name()

	result := &RebaseResult{SourceDigest: sourceDigest}
	if overrideOldBase != nil && overrideOldBase.Desc != nil {
		result.OldBaseDigest = overrideOldBase.Desc.Digest.String()
	}
	if newBase.Desc != nil {
		result.NewBaseDigest = newBase.Desc.Digest.String()
	}

	acc := newLayerAccumulator()

	targetRepo := ""
	if tr, err := c.parseRef(opts.TargetRef); err == nil {
		targetRepo = tr.Context().Name()
	}

	if !app.IsIndex {
		appImg := app.Image
		plat, err := imagePlatform(appImg)
		if err != nil {
			return nil, err
		}
		oldBase, err := c.oldBaseForAppImage(opts.AppRef, appImg, overrideOldBase)
		if err != nil {
			return nil, err
		}
		if result.OldBaseDigest == "" && oldBase.Desc != nil {
			result.OldBaseDigest = oldBase.Desc.Digest.String()
		}
		rebased, err := c.rebaseOne(appImg, oldBase, newBase, plat, opts, newBaseRepo, acc)
		if err != nil {
			return nil, err
		}
		newDigest, err := c.PushImage(opts.TargetRef, rebased)
		if err != nil {
			return nil, err
		}
		result.Image = rebased
		result.NewDigest = newDigest
		result.NewRef = targetRepo + "@" + newDigest
	} else {
		im, err := app.Index.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("failed to read app index: %w", err)
		}
		adds := []mutate.IndexAddendum{}
		for _, m := range im.Manifests {
			if !m.MediaType.IsImage() {
				// Skip non-image entries (e.g. attestations); signing recreates them.
				continue
			}
			appChild, err := app.Index.Image(m.Digest)
			if err != nil {
				return nil, fmt.Errorf("failed to read app child %s: %w", m.Digest, err)
			}
			plat := m.Platform
			if plat == nil {
				plat, _ = imagePlatform(appChild)
			}
			oldBase, err := c.oldBaseForAppImage(fmt.Sprintf("%s (%s)", opts.AppRef, platformString(plat)), appChild, overrideOldBase)
			if err != nil {
				return nil, err
			}
			if result.OldBaseDigest == "" && oldBase.Desc != nil {
				result.OldBaseDigest = oldBase.Desc.Digest.String()
			}
			rebased, err := c.rebaseOne(appChild, oldBase, newBase, plat, opts, newBaseRepo, acc)
			if err != nil {
				return nil, fmt.Errorf("platform %s: %w", platformString(plat), err)
			}
			adds = append(adds, mutate.IndexAddendum{Add: rebased, Descriptor: v1.Descriptor{Platform: plat}})
		}
		if len(adds) == 0 {
			return nil, fmt.Errorf("app index %q contains no image manifests to rebase", opts.AppRef)
		}
		newIndex := mutate.AppendManifests(empty.Index, adds...)
		newIndex = mutate.IndexMediaType(newIndex, app.Desc.MediaType)
		newDigest, err := c.PushIndex(opts.TargetRef, newIndex)
		if err != nil {
			return nil, err
		}
		result.IsIndex = true
		result.Index = newIndex
		result.NewDigest = newDigest
		result.NewRef = targetRepo + "@" + newDigest
	}

	result.PreservedAppLayers = acc.preserved.slice()
	result.RemovedBaseLayers = acc.removed.slice()
	result.AddedBaseLayers = acc.added.slice()
	return result, nil
}

// oldBaseForAppImage returns the recorded old base for one concrete app image. For
// multi-arch apps this is intentionally per child, so an index can carry platform-
// specific base references when needed. An explicit --old-base override still
// applies globally, but the app child must remain marked rebasable.
func (c *Client) oldBaseForAppImage(appRef string, appImg v1.Image, override *Resolved) (*Resolved, error) {
	labels, err := imageLabels(appImg)
	if err != nil {
		return nil, err
	}
	if labels[LabelRebasable] != "true" {
		return nil, fmt.Errorf("image %q is not marked rebasable (missing %s=true)", appRef, LabelRebasable)
	}
	if labels[LabelBaseLastLayer] == "" {
		return nil, fmt.Errorf("image %q has no recorded base boundary (%s); rebuild it with `clearcutt-verify app build`", appRef, LabelBaseLastLayer)
	}
	if override != nil {
		return override, nil
	}
	baseRef := labels[LabelBaseRef]
	if baseRef == "" {
		return nil, fmt.Errorf("image %q has no recorded base reference (%s); rebuild it with `clearcutt-verify app build`", appRef, LabelBaseRef)
	}
	oldBase, err := c.Pull(baseRef)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch recorded old base %q: %w", baseRef, err)
	}
	return oldBase, nil
}

// rebaseOne swaps the base for a single concrete image (one platform), validates the
// boundary, restamps the lifecycle labels onto the new base, and records the layer
// accounting for the attestation.
func (c *Client) rebaseOne(appImg v1.Image, oldBase, newBase *Resolved, plat *v1.Platform, opts RebaseOptions, newBaseRepo string, acc *layerAccumulator) (v1.Image, error) {
	oldChild, err := resolveChild(oldBase, plat)
	if err != nil {
		return nil, fmt.Errorf("old base: %w", err)
	}
	newChild, err := resolveChild(newBase, plat)
	if err != nil {
		return nil, fmt.Errorf("new base: %w", err)
	}

	// Boundary check: the app must record the old base's final layer as its boundary.
	labels, err := imageLabels(appImg)
	if err != nil {
		return nil, err
	}
	if labels[LabelRebasable] != "true" {
		return nil, fmt.Errorf("image is not marked rebasable (missing %s=true)", LabelRebasable)
	}
	if labels[LabelBaseLastLayer] == "" {
		return nil, fmt.Errorf("image has no recorded base boundary (%s)", LabelBaseLastLayer)
	}
	oldLast, err := lastLayerDigest(oldChild)
	if err != nil {
		return nil, err
	}
	if recorded := labels[LabelBaseLastLayer]; recorded != oldLast {
		return nil, fmt.Errorf("base boundary mismatch: app records %s but old base ends at %s", recorded, oldLast)
	}

	// mutate.Rebase re-verifies (by diff_id) that the app layers are exactly the old
	// base plus the app payload, and rewrites diff_ids/history for the new base while
	// preserving the app's runtime config (entrypoint/user/env/labels).
	rebased, err := mutate.Rebase(appImg, oldChild, newChild)
	if err != nil {
		return nil, fmt.Errorf("rebase failed: %w", err)
	}

	// Restamp lifecycle labels onto the new base so the result stays rebasable.
	newChildDigest, err := newChild.Digest()
	if err != nil {
		return nil, err
	}
	newLast, err := lastLayerDigest(newChild)
	if err != nil {
		return nil, err
	}
	cfg, err := rebased.ConfigFile()
	if err != nil {
		return nil, err
	}
	cfg = cfg.DeepCopy()
	if cfg.Config.Labels == nil {
		cfg.Config.Labels = map[string]string{}
	}
	if opts.NewBaseID != "" {
		cfg.Config.Labels[LabelBaseID] = opts.NewBaseID
	}
	if opts.NewBaseVersion != "" {
		cfg.Config.Labels[LabelBaseVersion] = opts.NewBaseVersion
	}
	cfg.Config.Labels[LabelBaseRef] = newBaseRepo + "@" + newChildDigest.String()
	cfg.Config.Labels[LabelBaseLastLayer] = newLast
	cfg.Config.Labels[LabelRebasable] = "true"
	cfg.Created = v1.Time{Time: time.Now().UTC()}
	rebased, err = mutate.ConfigFile(rebased, cfg)
	if err != nil {
		return nil, err
	}

	// Layer accounting for the attestation.
	if err := acc.recordLayers(oldChild, &acc.removed); err != nil {
		return nil, err
	}
	if err := acc.recordLayers(newChild, &acc.added); err != nil {
		return nil, err
	}
	oldLayers, err := oldChild.Layers()
	if err != nil {
		return nil, err
	}
	if err := acc.recordAppLayers(appImg, len(oldLayers)); err != nil {
		return nil, err
	}
	return rebased, nil
}

// resolveChild returns the platform-matching image for a resolved reference, or the
// image itself when the reference is single-arch.
func resolveChild(res *Resolved, plat *v1.Platform) (v1.Image, error) {
	if !res.IsIndex {
		return res.Image, nil
	}
	return childImage(res.Index, plat)
}

func imagePlatform(img v1.Image) (*v1.Platform, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	p := cfg.Platform()
	if p == nil {
		p = &v1.Platform{OS: "linux", Architecture: "amd64"}
	}
	return p, nil
}

// layerAccumulator collects deduped, order-preserving sets of layer digests across
// all platforms of a (possibly multi-arch) rebase.
type layerAccumulator struct {
	preserved orderedSet
	removed   orderedSet
	added     orderedSet
}

func newLayerAccumulator() *layerAccumulator {
	return &layerAccumulator{
		preserved: newOrderedSet(),
		removed:   newOrderedSet(),
		added:     newOrderedSet(),
	}
}

func (a *layerAccumulator) recordLayers(img v1.Image, into *orderedSet) error {
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			return err
		}
		into.add(d.String())
	}
	return nil
}

func (a *layerAccumulator) recordAppLayers(appImg v1.Image, baseCount int) error {
	layers, err := appImg.Layers()
	if err != nil {
		return err
	}
	for i := baseCount; i < len(layers); i++ {
		d, err := layers[i].Digest()
		if err != nil {
			return err
		}
		a.preserved.add(d.String())
	}
	return nil
}

type orderedSet struct {
	seen  map[string]bool
	order []string
}

func newOrderedSet() orderedSet { return orderedSet{seen: map[string]bool{}} }

func (s *orderedSet) add(v string) {
	if s.seen[v] {
		return
	}
	s.seen[v] = true
	s.order = append(s.order, v)
}

func (s *orderedSet) slice() []string { return append([]string(nil), s.order...) }
