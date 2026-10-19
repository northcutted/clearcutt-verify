// Package estate persists a governance snapshot — the observations, the base
// graph, and the layer-commonality graph — as an OCI artifact in a registry.
//
// The registry is a deliberate choice of backing store rather than a convenient
// one. The evidence then lives under the same auth boundary, replication and
// retention policy as the images it describes; digests make each snapshot
// immutable and addressable; tags give history for free, so estate drift is a
// diff between two tags; and a mirrored registry carries its own evidence into
// an air gap. Nothing new has to be operated.
//
// The one caveat is worth stating rather than designing around: when the
// registry is the thing being audited, storing the audit inside it is a mild
// conflict of interest. Sign the artifact (internal/sign already wraps cosign)
// so tampering is detectable rather than merely unlikely.
package estate

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-verify/internal/registryauth"
)

const (
	// ArtifactType identifies a ClearCutt estate snapshot. go-containerregistry
	// v0.21 has no artifactType setter, so it rides on the config media type —
	// the pre-OCI-1.1 convention cosign and others use, and the one every
	// registry accepts today.
	ArtifactType = "application/vnd.clearcutt.estate.v1+json"

	// BlobMediaType marks each stored file.
	BlobMediaType = "application/vnd.clearcutt.estate.file.v1+json"

	// TitleAnnotation carries the file name, per the OCI convention, so a
	// generic tool (oras, crane) shows meaningful names instead of digests.
	TitleAnnotation = "org.opencontainers.image.title"

	// GeneratedAtAnnotation records when the snapshot was taken. It is manifest
	// level, so reading it costs one manifest fetch rather than a blob pull.
	GeneratedAtAnnotation = "dev.clearcutt.estate.generated_at"
)

// maxFileBytes bounds a single stored file. An estate snapshot is metadata —
// layer digests and labels, never image content — so a real one is a few MB even
// for a large estate. A file past this bound means something is being stored here
// that does not belong.
const maxFileBytes = 256 << 20

// Client talks to a registry. The zero value is not usable; use New* .
type Client struct {
	remoteOpts []remote.Option
	nameOpts   []name.Option
}

// NewClient authenticates from the ambient keychain (docker config, cloud
// credential helpers).
func NewClient() *Client {
	return &Client{remoteOpts: []remote.Option{remote.WithAuthFromKeychain(registryauth.Keychain)}}
}

// NewKeychainClient authenticates with keychain, which resolves each
// registry's own credentials (registryauth.ForRefs: the explicit ones in the
// environment for the registries a command names, the Docker keychain, and
// GITHUB_TOKEN for ghcr.io), so no credential is offered to a registry it
// isn't for.
func NewKeychainClient(keychain authn.Keychain) *Client {
	return &Client{remoteOpts: []remote.Option{remote.WithAuthFromKeychain(keychain)}}
}

// NewInsecureClient speaks plain HTTP without auth, for hermetic tests against
// an in-process registry. Do not use it for real traffic.
func NewInsecureClient() *Client {
	return &Client{nameOpts: []name.Option{name.Insecure}}
}

// Snapshot is the set of files in one estate artifact, keyed by file name.
type Snapshot struct {
	GeneratedAt string
	Files       map[string][]byte
}

// Build assembles the artifact for a snapshot without pushing it.
//
// The result is deterministic: files are sorted by name, so identical inputs
// produce an identical manifest digest. That is what makes "has the estate
// changed?" answerable by comparing digests instead of diffing content, and it
// means re-pushing an unchanged snapshot is a no-op rather than a new version.
func Build(snapshot Snapshot) (v1.Image, error) {
	if len(snapshot.Files) == 0 {
		return nil, fmt.Errorf("estate snapshot holds no files")
	}
	names := make([]string, 0, len(snapshot.Files))
	for fileName := range snapshot.Files {
		if strings.TrimSpace(fileName) == "" {
			return nil, fmt.Errorf("estate snapshot has a file with an empty name")
		}
		if size := len(snapshot.Files[fileName]); size > maxFileBytes {
			return nil, fmt.Errorf("estate file %q is %d bytes, over the %d-byte limit; an estate snapshot stores metadata, not image content", fileName, size, maxFileBytes)
		}
		names = append(names, fileName)
	}
	sort.Strings(names)

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, ArtifactType)

	addenda := make([]mutate.Addendum, 0, len(names))
	for _, fileName := range names {
		addenda = append(addenda, mutate.Addendum{
			Layer:       static.NewLayer(snapshot.Files[fileName], BlobMediaType),
			MediaType:   BlobMediaType,
			Annotations: map[string]string{TitleAnnotation: fileName},
		})
	}
	withFiles, err := mutate.Append(img, addenda...)
	if err != nil {
		return nil, fmt.Errorf("assembling estate artifact: %w", err)
	}
	annotations := map[string]string{}
	if generatedAt := strings.TrimSpace(snapshot.GeneratedAt); generatedAt != "" {
		annotations[GeneratedAtAnnotation] = generatedAt
	}
	if len(annotations) == 0 {
		return withFiles, nil
	}
	annotated, ok := mutate.Annotations(withFiles, annotations).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("annotating estate artifact did not yield an image")
	}
	return annotated, nil
}

// Push writes the snapshot to ref and returns the digest it was stored under.
func (c *Client) Push(ref string, snapshot Snapshot) (string, error) {
	target, err := name.ParseReference(ref, c.nameOpts...)
	if err != nil {
		return "", fmt.Errorf("parsing estate reference %q: %w", ref, err)
	}
	img, err := Build(snapshot)
	if err != nil {
		return "", err
	}
	if err := remote.Write(target, img, c.remoteOpts...); err != nil {
		return "", fmt.Errorf("pushing estate artifact to %s: %w", ref, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return "", err
	}
	return digest.String(), nil
}

// ErrNotFound means nothing is stored at a reference: the registry knows no
// such manifest or repository. Pull returns it only for the manifest; a
// manifest whose files can't be read is a failure, not nothing.
var ErrNotFound = errors.New("nothing is stored there")

// Pull fetches the snapshot stored at ref.
func (c *Client) Pull(ref string) (Snapshot, string, error) {
	target, err := name.ParseReference(ref, c.nameOpts...)
	if err != nil {
		return Snapshot{}, "", fmt.Errorf("parsing estate reference %q: %w", ref, err)
	}
	desc, err := remote.Get(target, c.remoteOpts...)
	if err != nil {
		if manifestNotFound(err) {
			return Snapshot{}, "", fmt.Errorf("fetching estate artifact %s: %w: %v", ref, ErrNotFound, err)
		}
		return Snapshot{}, "", fmt.Errorf("fetching estate artifact %s: %w", ref, err)
	}
	img, err := desc.Image()
	if err != nil {
		return Snapshot{}, "", fmt.Errorf("estate reference %s is not an artifact manifest: %w", ref, err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		return Snapshot{}, "", err
	}
	// Refuse anything that is not ours. Pulling an arbitrary image and treating
	// its layers as governance evidence would be worse than failing.
	if got := string(manifest.Config.MediaType); got != ArtifactType {
		return Snapshot{}, "", fmt.Errorf("%s is not a ClearCutt estate artifact: config media type is %q, want %q", ref, got, ArtifactType)
	}
	layers, err := img.Layers()
	if err != nil {
		return Snapshot{}, "", err
	}
	snapshot := Snapshot{
		GeneratedAt: manifest.Annotations[GeneratedAtAnnotation],
		Files:       map[string][]byte{},
	}
	for i, layer := range layers {
		fileName := ""
		if i < len(manifest.Layers) {
			fileName = manifest.Layers[i].Annotations[TitleAnnotation]
		}
		if fileName == "" {
			return Snapshot{}, "", fmt.Errorf("estate artifact %s has a layer with no %s annotation, so its file name is unknown", ref, TitleAnnotation)
		}
		reader, err := layer.Uncompressed()
		if err != nil {
			return Snapshot{}, "", fmt.Errorf("reading estate file %q: %w", fileName, err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(reader); err != nil {
			_ = reader.Close()
			return Snapshot{}, "", fmt.Errorf("reading estate file %q: %w", fileName, err)
		}
		if err := reader.Close(); err != nil {
			return Snapshot{}, "", err
		}
		snapshot.Files[fileName] = buf.Bytes()
	}
	return snapshot, desc.Digest.String(), nil
}

// manifestNotFound reports whether the registry answered a manifest request
// saying there is no such manifest or repository.
func manifestNotFound(err error) bool {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return false
	}
	if terr.StatusCode == http.StatusNotFound {
		return true
	}
	for _, d := range terr.Errors {
		if d.Code == transport.ManifestUnknownErrorCode || d.Code == transport.NameUnknownErrorCode {
			return true
		}
	}
	return false
}
