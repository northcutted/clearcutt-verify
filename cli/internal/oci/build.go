package oci

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// BuildOptions describes a `clearcutt-verify app build`: lay one prebuilt artifact on
// top of a ClearCutt base image as one deterministic layer, stamp the lifecycle
// labels, and push the result.
type BuildOptions struct {
	BaseRef      string   // registry reference of the ClearCutt base image
	BaseID       string   // catalog id (e.g. java25-distroless), stamped into a label
	BaseVersion  string   // base version (e.g. v0.6.2), stamped into a label
	ArtifactPath string   // local file or directory embedded into the app layer
	DestPath     string   // absolute path the artifact lands at inside the image
	Entrypoint   []string // OCI entrypoint (JSON-exec form)
	Cmd          []string // optional OCI cmd
	WorkingDir   string   // optional working directory
	User         string   // optional non-root user override; empty preserves the base
	Executable   bool     // mark the embedded artifact executable (static binaries)
	TargetRef    string   // where to push the assembled image
}

// BuildResult reports what `app build` produced.
type BuildResult struct {
	Digest         string // assembled image manifest digest (sha256:...)
	BaseRef        string // digest-pinned reference of the base actually used
	BaseLastLayer  string // boundary digest stamped into LabelBaseLastLayer
	AppLayerDigest string // compressed digest of the single app layer
	AppLayerDiffID string // uncompressed (diff_id) of the app layer
}

// BuildApp assembles and pushes an application image. It is single-arch by design:
// a prebuilt artifact is platform-specific, so the app layer is laid onto the base's
// linux/amd64 image (or the base itself when it is single-arch).
func (c *Client) BuildApp(opts BuildOptions) (*BuildResult, error) {
	if opts.ArtifactPath == "" || opts.DestPath == "" || opts.TargetRef == "" {
		return nil, fmt.Errorf("BuildApp requires ArtifactPath, DestPath and TargetRef")
	}
	if len(opts.Entrypoint) == 0 {
		return nil, fmt.Errorf("BuildApp requires a non-empty entrypoint")
	}

	res, err := c.Pull(opts.BaseRef)
	if err != nil {
		return nil, err
	}
	base, err := c.resolveBaseImage(res)
	if err != nil {
		return nil, err
	}

	// Digest-pin the exact base artifact so a future rebase can fetch it precisely.
	// If --base resolved to an index, keep the index digest: that lets a multi-arch
	// rebase select the right child for each platform instead of pinning only amd64.
	baseDigest, err := res.ManifestDigest()
	if err != nil {
		return nil, err
	}
	baseRefPinned := res.Ref.Context().Name() + "@" + baseDigest

	boundary, err := lastLayerDigest(base)
	if err != nil {
		return nil, fmt.Errorf("base image is unusable: %w", err)
	}

	layerMediaType, err := appLayerMediaType(base)
	if err != nil {
		return nil, err
	}
	layer, err := artifactLayer(opts.ArtifactPath, opts.DestPath, opts.Executable, layerMediaType)
	if err != nil {
		return nil, err
	}

	appImg, err := mutate.AppendLayers(base, layer)
	if err != nil {
		return nil, fmt.Errorf("failed to append application layer: %w", err)
	}

	cfg, err := appImg.ConfigFile()
	if err != nil {
		return nil, err
	}
	cfg = cfg.DeepCopy()
	cfg.Config.Entrypoint = opts.Entrypoint
	if opts.Cmd != nil {
		cfg.Config.Cmd = opts.Cmd
	}
	if opts.WorkingDir != "" {
		cfg.Config.WorkingDir = opts.WorkingDir
	}
	if opts.User != "" {
		cfg.Config.User = opts.User
	}
	if cfg.Config.Labels == nil {
		cfg.Config.Labels = map[string]string{}
	}
	cfg.Config.Labels[LabelBaseID] = opts.BaseID
	cfg.Config.Labels[LabelBaseVersion] = opts.BaseVersion
	cfg.Config.Labels[LabelBaseRef] = baseRefPinned
	cfg.Config.Labels[LabelBaseLastLayer] = boundary
	cfg.Config.Labels[LabelRebasable] = "true"
	cfg.Created = v1.Time{Time: time.Now().UTC()}

	appImg, err = mutate.ConfigFile(appImg, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to apply application config: %w", err)
	}

	digest, err := c.PushImage(opts.TargetRef, appImg)
	if err != nil {
		return nil, err
	}

	appLayerDigest, err := layer.Digest()
	if err != nil {
		return nil, err
	}
	appLayerDiffID, err := layer.DiffID()
	if err != nil {
		return nil, err
	}

	return &BuildResult{
		Digest:         digest,
		BaseRef:        baseRefPinned,
		BaseLastLayer:  boundary,
		AppLayerDigest: appLayerDigest.String(),
		AppLayerDiffID: appLayerDiffID.String(),
	}, nil
}

// resolveBaseImage returns the concrete image to build on: the resolved image, or
// the linux/amd64 child of a multi-arch base index.
func (c *Client) resolveBaseImage(res *Resolved) (v1.Image, error) {
	if !res.IsIndex {
		return res.Image, nil
	}
	return childImage(res.Index, &v1.Platform{OS: "linux", Architecture: "amd64"})
}

// appLayerMediaType matches the new layer's media type to the base manifest so we
// don't mix OCI and Docker media types within one image.
func appLayerMediaType(base v1.Image) (types.MediaType, error) {
	mt, err := base.MediaType()
	if err != nil {
		return "", err
	}
	if mt == types.OCIManifestSchema1 {
		return types.OCILayer, nil
	}
	return types.DockerLayer, nil
}

// artifactLayer builds a reproducible tar layer placing artifactPath at destPath
// inside the image. Directories are expanded under destPath while preserving a
// single OCI app layer. Tar headers are normalized (epoch mtime, uid/gid 0) so
// identical inputs always yield identical layer digests.
func artifactLayer(artifactPath, destPath string, executable bool, mt types.MediaType) (v1.Layer, error) {
	if strings.TrimSpace(destPath) == "" {
		return nil, fmt.Errorf("invalid destination path %q", destPath)
	}
	name := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(destPath)), "/")
	if name == "" || name == "." {
		return nil, fmt.Errorf("invalid destination path %q", destPath)
	}

	info, err := os.Lstat(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read artifact %q: %w", artifactPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("artifact %q is a symbolic link; only regular files and directories are supported", artifactPath)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if info.IsDir() {
		err = writeDirectoryArtifact(tw, artifactPath, name)
	} else if info.Mode().IsRegular() {
		err = writeFileArtifact(tw, artifactPath, name, info, executable, false)
	} else {
		err = fmt.Errorf("artifact %q is not a regular file or directory", artifactPath)
	}
	if err != nil {
		_ = tw.Close()
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	contents := buf.Bytes()

	return tarball.LayerFromOpener(
		func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(contents)), nil },
		tarball.WithMediaType(mt),
	)
}

func writeDirectoryArtifact(tw *tar.Writer, root, destName string) error {
	var entries []string
	if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		entries = append(entries, p)
		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk artifact directory %q: %w", root, err)
	}
	sort.Slice(entries, func(i, j int) bool {
		relI, _ := filepath.Rel(root, entries[i])
		relJ, _ := filepath.Rel(root, entries[j])
		return filepath.ToSlash(relI) < filepath.ToSlash(relJ)
	})

	for _, src := range entries {
		info, err := os.Lstat(src)
		if err != nil {
			return fmt.Errorf("failed to read artifact entry %q: %w", src, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact entry %q is a symbolic link; only regular files and directories are supported", src)
		}
		rel, err := filepath.Rel(root, src)
		if err != nil {
			return err
		}
		name := destName
		if rel != "." {
			name = path.Join(destName, filepath.ToSlash(rel))
		}

		switch {
		case info.IsDir():
			if err := writeHeader(tw, &tar.Header{
				Name:     name,
				Mode:     0o755,
				Typeflag: tar.TypeDir,
			}); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := writeFileArtifact(tw, src, name, info, false, true); err != nil {
				return err
			}
		default:
			return fmt.Errorf("artifact entry %q is not a regular file or directory", src)
		}
	}
	return nil
}

func writeFileArtifact(tw *tar.Writer, src, name string, info os.FileInfo, forceExecutable, preserveExecutable bool) error {
	mode := int64(0o644)
	if forceExecutable || (preserveExecutable && info.Mode().Perm()&0o111 != 0) {
		mode = 0o755
	}
	hdr := &tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     info.Size(),
		Typeflag: tar.TypeReg,
	}
	if err := writeHeader(tw, hdr); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open artifact %q: %w", src, err)
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func writeHeader(tw *tar.Writer, hdr *tar.Header) error {
	hdr.ModTime = time.Unix(0, 0).UTC()
	hdr.Uid = 0
	hdr.Gid = 0
	hdr.Uname = ""
	hdr.Gname = ""
	return tw.WriteHeader(hdr)
}
