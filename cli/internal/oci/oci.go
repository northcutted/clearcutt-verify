// Package oci wraps go-containerregistry to give the `clearcutt-verify app` command group
// a small, intention-revealing surface for the few OCI operations it needs:
// pulling an image or multi-arch index, assembling an application image on top of a
// ClearCutt base, and rebasing an application onto a new base while preserving the
// application layers byte-for-byte.
//
// Everything here is daemon-free: it talks the OCI distribution protocol directly,
// so it needs no Docker/Podman running. Signing is intentionally NOT done here — it
// is delegated to the cosign CLI via internal/sign so the trust roots stay auditable
// and match the certify-app GitHub Action.
package oci

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ClearCutt application-lifecycle labels. These travel inside the image config and
// form the cryptographic-ish boundary between base and application content:
//   - LabelBaseLastLayer pins the compressed digest of the base's final layer, so a
//     rebase can prove where the base ends and the untouched app payload begins.
//   - LabelBaseRef pins the exact (digest-addressed) base artifact the app was
//     built on (image or index), so a rebase can fetch the real old base for a
//     correct history/diff_id rewrite instead of guessing a tag.
const (
	LabelBaseID        = "dev.clearcutt.app.base.id"
	LabelBaseVersion   = "dev.clearcutt.app.base.version"
	LabelBaseRef       = "dev.clearcutt.app.base.ref"
	LabelBaseLastLayer = "dev.clearcutt.app.base.last_layer_digest"
	LabelRebasable     = "dev.clearcutt.app.rebasable"
)

// Client carries the remote/name options for every registry call. The default
// client authenticates from the ambient keychain (docker config, cloud helpers) and
// speaks HTTPS. Tests construct an insecure client pointed at an in-memory registry.
type Client struct {
	remoteOpts []remote.Option
	nameOpts   []name.Option
}

// NewClient returns a registry client that authenticates from the ambient keychain.
func NewClient() *Client {
	return &Client{
		remoteOpts: []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
	}
}

// NewClientWithBasicAuth returns a registry client that authenticates with
// explicit username/password credentials instead of relying on the ambient
// Docker/keychain configuration.
func NewClientWithBasicAuth(username, password string) *Client {
	return &Client{
		remoteOpts: []remote.Option{remote.WithAuth(&authn.Basic{
			Username: username,
			Password: password,
		})},
	}
}

// NewInsecureClient returns a client that speaks plain HTTP and skips auth. It exists
// for hermetic tests against an in-process registry; do not use it for real traffic.
func NewInsecureClient() *Client {
	return &Client{nameOpts: []name.Option{name.Insecure}}
}

// Resolved is the result of pulling a reference: exactly one of Image or Index is set.
type Resolved struct {
	Ref     name.Reference
	Desc    *remote.Descriptor
	IsIndex bool
	Image   v1.Image
	Index   v1.ImageIndex
}

// ManifestDigest returns the digest of the resolved manifest (image or index).
func (r *Resolved) ManifestDigest() (string, error) {
	switch {
	case r.IsIndex:
		d, err := r.Index.Digest()
		if err != nil {
			return "", err
		}
		return d.String(), nil
	case r.Image != nil:
		d, err := r.Image.Digest()
		if err != nil {
			return "", err
		}
		return d.String(), nil
	default:
		return "", fmt.Errorf("resolved reference has neither image nor index")
	}
}

// parseRef parses a reference with the client's name options (e.g. name.Insecure).
func (c *Client) parseRef(ref string) (name.Reference, error) {
	r, err := name.ParseReference(ref, c.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference %q: %w", ref, err)
	}
	return r, nil
}

// Pull resolves a reference to either a single image or a multi-arch index.
func (c *Client) Pull(ref string) (*Resolved, error) {
	r, err := c.parseRef(ref)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(r, c.remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %q from registry: %w", ref, err)
	}
	res := &Resolved{Ref: r, Desc: desc}
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, fmt.Errorf("failed to read image index %q: %w", ref, err)
		}
		res.IsIndex = true
		res.Index = idx
		return res, nil
	}
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("failed to read image %q: %w", ref, err)
	}
	res.Image = img
	return res, nil
}

// PullImage resolves a reference to a single image, selecting the linux/amd64
// child when the reference points at a multi-arch index.
func (c *Client) PullImage(ref string) (v1.Image, error) {
	res, err := c.Pull(ref)
	if err != nil {
		return nil, err
	}
	if !res.IsIndex {
		return res.Image, nil
	}
	return childImage(res.Index, &v1.Platform{OS: "linux", Architecture: "amd64"})
}

// PushImage writes a single image to ref and returns its manifest digest.
func (c *Client) PushImage(ref string, img v1.Image) (string, error) {
	r, err := c.parseRef(ref)
	if err != nil {
		return "", err
	}
	if err := remote.Write(r, img, c.remoteOpts...); err != nil {
		return "", fmt.Errorf("failed to push image to %q: %w", ref, err)
	}
	d, err := img.Digest()
	if err != nil {
		return "", err
	}
	return d.String(), nil
}

// PushIndex writes a multi-arch index (and its child manifests) to ref and returns
// the index manifest digest.
func (c *Client) PushIndex(ref string, idx v1.ImageIndex) (string, error) {
	r, err := c.parseRef(ref)
	if err != nil {
		return "", err
	}
	if err := remote.WriteIndex(r, idx, c.remoteOpts...); err != nil {
		return "", fmt.Errorf("failed to push image index to %q: %w", ref, err)
	}
	d, err := idx.Digest()
	if err != nil {
		return "", err
	}
	return d.String(), nil
}

// imageLabels returns the config labels for an image (nil-safe).
func imageLabels(img v1.Image) (map[string]string, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to read image config: %w", err)
	}
	if cfg.Config.Labels == nil {
		return map[string]string{}, nil
	}
	return cfg.Config.Labels, nil
}

// lastLayerDigest returns the compressed (manifest descriptor) digest of an image's
// final layer — the value stamped into LabelBaseLastLayer to mark the base boundary.
func lastLayerDigest(img v1.Image) (string, error) {
	layers, err := img.Layers()
	if err != nil {
		return "", fmt.Errorf("failed to read layers: %w", err)
	}
	if len(layers) == 0 {
		return "", fmt.Errorf("image has no layers")
	}
	d, err := layers[len(layers)-1].Digest()
	if err != nil {
		return "", err
	}
	return d.String(), nil
}

// childImage selects the child of an index matching the requested platform.
func childImage(idx v1.ImageIndex, want *v1.Platform) (v1.Image, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to read index manifest: %w", err)
	}
	for _, m := range im.Manifests {
		if !m.MediaType.IsImage() {
			continue
		}
		if want == nil || platformMatches(m.Platform, want) {
			return idx.Image(m.Digest)
		}
	}
	return nil, fmt.Errorf("index has no image manifest for platform %s", platformString(want))
}

func platformMatches(have, want *v1.Platform) bool {
	if have == nil {
		return false
	}
	if want.OS != "" && have.OS != want.OS {
		return false
	}
	if want.Architecture != "" && have.Architecture != want.Architecture {
		return false
	}
	if want.Variant != "" && have.Variant != want.Variant {
		return false
	}
	return true
}

func platformString(p *v1.Platform) string {
	if p == nil {
		return "<nil>"
	}
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}
