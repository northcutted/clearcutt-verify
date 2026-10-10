// Package evidence stores release evidence — SBOMs, provenance, scan results,
// test output — in an OCI registry, attached to the image it describes.
//
// The alternative it replaces is GitHub release assets. Those work, but they
// make the evidence live somewhere the images do not, under a different auth
// model, reachable only through one vendor's API. Attaching evidence to the
// image digest instead means one storage plane, one credential, and the same
// answer on any OCI registry.
//
// # Portability
//
// Attachment uses the OCI 1.1 `subject` field. Registries that implement the
// Referrers API index it themselves; go-containerregistry falls back to the
// referrers TAG SCHEME on registries that do not, in both directions, so this
// works on registries from GHCR to a plain `registry:2` without a code path per
// vendor.
//
// # Garbage collection — the real operational risk
//
// Evidence attached to an image is a manifest like any other, and registry
// lifecycle policies can delete it. A rule that prunes untagged manifests, or
// deletes everything in a repository older than N days, will take the evidence
// with the image — and on some registries, before it. GitHub release assets do
// not behave this way, so moving to registry-native evidence trades vendor
// lock-in for a retention concern you now own.
//
// Three things follow, and this package supports all three:
//
//   - The referrers tag fallback TAGS each attachment, which protects it from
//     untagged-manifest pruning specifically. That is the common rule.
//   - Export exists (see Export) so evidence can be copied somewhere with its
//     own retention guarantees before any policy can reach it.
//   - Nothing here assumes the registry is the only copy.
package evidence

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-verify/internal/registryauth"
)

const (
	// ArtifactType marks a ClearCutt evidence bundle. It rides on the config
	// media type, which is how tools identify an artifact on registries that
	// predate OCI 1.1's artifactType field.
	ArtifactType = "application/vnd.clearcutt.evidence.v1+json"

	// BlobMediaType marks each evidence file.
	BlobMediaType = "application/vnd.clearcutt.evidence.file.v1"

	// TitleAnnotation carries the file name, per OCI convention, so generic
	// tooling (oras, crane) shows names rather than digests.
	TitleAnnotation = "org.opencontainers.image.title"

	// SubjectAnnotation records the image this evidence describes, in addition
	// to the manifest `subject` field. The field is what registries index; this
	// is what a human reads out of `crane manifest`.
	SubjectAnnotation = "dev.clearcutt.evidence.subject"

	// ReleaseAnnotation records the release tag the evidence belongs to, so a
	// catalog can group attachments without pulling them.
	ReleaseAnnotation = "dev.clearcutt.evidence.release"

	// CreatedAnnotation records when the evidence was produced.
	CreatedAnnotation = "dev.clearcutt.evidence.created"
)

// Client talks to a registry.
type Client struct {
	remoteOpts []remote.Option
	nameOpts   []name.Option
}

func NewClient() *Client {
	return &Client{remoteOpts: []remote.Option{remote.WithAuthFromKeychain(registryauth.Keychain)}}
}

// NewBasicAuthClient authenticates with explicit credentials rather than the
// ambient keychain. CI runners have registry credentials in the environment and
// no docker config, which is the common case for publishing.
func NewBasicAuthClient(username, password string) *Client {
	return &Client{remoteOpts: []remote.Option{remote.WithAuth(&authn.Basic{
		Username: username,
		Password: password,
	})}}
}

// NewInsecureClient speaks plain HTTP without auth, for hermetic tests against
// an in-process registry.
func NewInsecureClient() *Client {
	return &Client{nameOpts: []name.Option{name.Insecure}}
}

// Bundle is a set of evidence files about one image.
type Bundle struct {
	// Subject is the image the evidence describes, as a digest reference.
	Subject string
	// Release is the tag the evidence belongs to, e.g. "v1.4.0".
	Release string
	// Created is an RFC3339 timestamp.
	Created string
	// Files is keyed by file name: "sbom.json", "provenance.json", and so on.
	Files map[string][]byte
}

// Attach stores a bundle against its subject image and returns the digest it
// was stored under.
//
// The bundle is deterministic — files sorted by name — so re-attaching
// identical evidence produces the same digest and does not create a second
// attachment saying the same thing.
func (c *Client) Attach(subjectRef string, bundle Bundle) (string, error) {
	if len(bundle.Files) == 0 {
		return "", fmt.Errorf("evidence bundle for %s holds no files", subjectRef)
	}
	ref, err := name.ParseReference(subjectRef, c.nameOpts...)
	if err != nil {
		return "", fmt.Errorf("parsing subject reference %q: %w", subjectRef, err)
	}
	// The subject must be pinned by digest: evidence describes specific bytes,
	// and a tag can move to different bytes tomorrow.
	desc, err := remote.Head(ref, c.remoteOpts...)
	if err != nil {
		return "", fmt.Errorf("resolving subject %s: %w", subjectRef, err)
	}
	subjectDigest := ref.Context().Digest(desc.Digest.String())

	img, err := buildBundle(bundle, subjectDigest.String(), v1.Descriptor{
		MediaType: desc.MediaType,
		Size:      desc.Size,
		Digest:    desc.Digest,
	})
	if err != nil {
		return "", err
	}
	attachmentDigest, err := img.Digest()
	if err != nil {
		return "", err
	}
	target := ref.Context().Digest(attachmentDigest.String())
	if err := remote.Write(target, img, c.remoteOpts...); err != nil {
		return "", fmt.Errorf("attaching evidence to %s: %w", subjectDigest, err)
	}
	return attachmentDigest.String(), nil
}

func buildBundle(bundle Bundle, subject string, subjectDesc v1.Descriptor) (v1.Image, error) {
	names := make([]string, 0, len(bundle.Files))
	for fileName := range bundle.Files {
		if strings.TrimSpace(fileName) == "" {
			return nil, fmt.Errorf("evidence bundle has a file with an empty name")
		}
		names = append(names, fileName)
	}
	sort.Strings(names)

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, ArtifactType)
	addenda := make([]mutate.Addendum, 0, len(names))
	for _, fileName := range names {
		addenda = append(addenda, mutate.Addendum{
			Layer:       static.NewLayer(bundle.Files[fileName], BlobMediaType),
			MediaType:   BlobMediaType,
			Annotations: map[string]string{TitleAnnotation: fileName},
		})
	}
	withFiles, err := mutate.Append(img, addenda...)
	if err != nil {
		return nil, fmt.Errorf("assembling evidence bundle: %w", err)
	}
	annotations := map[string]string{SubjectAnnotation: subject}
	if bundle.Release != "" {
		annotations[ReleaseAnnotation] = bundle.Release
	}
	if bundle.Created != "" {
		annotations[CreatedAnnotation] = bundle.Created
	}
	annotated, ok := mutate.Annotations(withFiles, annotations).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("annotating evidence bundle did not yield an image")
	}
	return mutate.Subject(annotated, subjectDesc).(v1.Image), nil
}

// Attachment is one evidence bundle discovered on a subject.
type Attachment struct {
	Digest      string            `json:"digest"`
	Release     string            `json:"release,omitempty"`
	Created     string            `json:"created,omitempty"`
	Files       []string          `json:"files"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// List reports the evidence attached to an image. It reads referrers only, so
// listing costs no blob pulls; the file NAMES come from layer annotations in
// each attachment's manifest.
func (c *Client) List(subjectRef string) ([]Attachment, error) {
	ref, err := name.ParseReference(subjectRef, c.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing subject reference %q: %w", subjectRef, err)
	}
	desc, err := remote.Head(ref, c.remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("resolving subject %s: %w", subjectRef, err)
	}
	subjectDigest := ref.Context().Digest(desc.Digest.String())
	index, err := remote.Referrers(subjectDigest, c.remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("listing evidence for %s: %w", subjectRef, err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}
	out := []Attachment{}
	for _, entry := range manifest.Manifests {
		if entry.ArtifactType != "" && entry.ArtifactType != ArtifactType {
			continue
		}
		attachment := Attachment{Digest: entry.Digest.String()}
		// Read the attachment's own manifest for names and annotations.
		//
		// The referrers index entry is NOT the source of truth here. The OCI
		// spec lets a registry copy a manifest's annotations into the entry,
		// but nothing requires it, and go-containerregistry's tag-fallback path
		// builds the entry from media type, digest, size and artifact type
		// alone. Trusting the entry means release and created silently vanish
		// on exactly the registries the fallback exists to support.
		//
		// This costs one manifest fetch per attachment and still pulls no blobs.
		if files, annotations, err := c.describe(ref.Context().Digest(entry.Digest.String())); err == nil {
			attachment.Files = files
			attachment.Annotations = annotations
			attachment.Release = annotations[ReleaseAnnotation]
			attachment.Created = annotations[CreatedAnnotation]
		}
		out = append(out, attachment)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Created != out[j].Created {
			return out[i].Created > out[j].Created
		}
		return out[i].Digest < out[j].Digest
	})
	return out, nil
}

// describe returns an attachment's file names and manifest annotations.
func (c *Client) describe(ref name.Digest) ([]string, map[string]string, error) {
	img, err := remote.Image(ref, c.remoteOpts...)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := img.Manifest()
	if err != nil {
		return nil, nil, err
	}
	names := []string{}
	for _, layer := range manifest.Layers {
		if title := layer.Annotations[TitleAnnotation]; title != "" {
			names = append(names, title)
		}
	}
	sort.Strings(names)
	annotations := manifest.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}
	return names, annotations, nil
}

// Fetch pulls one attachment's files by its digest.
func (c *Client) Fetch(repoRef, attachmentDigest string) (Bundle, error) {
	ref, err := name.ParseReference(repoRef, c.nameOpts...)
	if err != nil {
		return Bundle{}, fmt.Errorf("parsing reference %q: %w", repoRef, err)
	}
	target := ref.Context().Digest(attachmentDigest)
	img, err := remote.Image(target, c.remoteOpts...)
	if err != nil {
		return Bundle{}, fmt.Errorf("fetching evidence %s: %w", attachmentDigest, err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		return Bundle{}, err
	}
	if got := string(manifest.Config.MediaType); got != ArtifactType {
		return Bundle{}, fmt.Errorf("%s is not a ClearCutt evidence bundle: config media type is %q", attachmentDigest, got)
	}
	layers, err := img.Layers()
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{
		Subject: manifest.Annotations[SubjectAnnotation],
		Release: manifest.Annotations[ReleaseAnnotation],
		Created: manifest.Annotations[CreatedAnnotation],
		Files:   map[string][]byte{},
	}
	for i, layer := range layers {
		fileName := ""
		if i < len(manifest.Layers) {
			fileName = manifest.Layers[i].Annotations[TitleAnnotation]
		}
		if fileName == "" {
			return Bundle{}, fmt.Errorf("evidence %s has a layer with no %s annotation", attachmentDigest, TitleAnnotation)
		}
		body, err := readLayer(layer)
		if err != nil {
			return Bundle{}, fmt.Errorf("reading evidence file %q: %w", fileName, err)
		}
		bundle.Files[fileName] = body
	}
	return bundle, nil
}

func readLayer(layer v1.Layer) ([]byte, error) {
	reader, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
