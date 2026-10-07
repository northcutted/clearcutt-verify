package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ExportManifest describes what an export contains, so a bundle sitting in
// object storage two years from now can be understood without the tool that
// wrote it.
type ExportManifest struct {
	APIVersion  string             `json:"apiVersion"`
	Kind        string             `json:"kind"`
	ExportedAt  string             `json:"exportedAt"`
	Source      string             `json:"source"`
	Subject     string             `json:"subject,omitempty"`
	Attachments []ExportAttachment `json:"attachments"`
	Note        string             `json:"note"`
}

type ExportAttachment struct {
	Digest  string   `json:"digest"`
	Release string   `json:"release,omitempty"`
	Created string   `json:"created,omitempty"`
	Files   []string `json:"files"`
}

// exportNote travels with the bundle because the reason it exists is not
// obvious from its contents.
const exportNote = "Evidence exported from an OCI registry. Registry lifecycle policies can delete " +
	"attached evidence — a rule that prunes untagged manifests, or everything older than N days, will " +
	"take it. This copy exists so the evidence survives that independently of the registry's retention " +
	"settings. The oci/ directory is a standard OCI image layout and can be pushed back to any registry " +
	"with `crane push`, `oras cp`, or `clearcutt-verify evidence import`."

// Export writes every evidence attachment on a subject to a directory, as BOTH
// a standard OCI image layout and plain files.
//
// Two formats on purpose, because the two audiences want different things:
//
//   - oci/ is a byte-exact, digest-preserving copy. Push it back to any
//     registry and the attachments are restored with their original digests,
//     so signatures over them still verify.
//   - files/ is the same evidence as plain readable files. An auditor with a
//     zip and no container tooling can open sbom.json.
//
// This is the answer to registry garbage collection. Attached evidence is a
// manifest like any other and a lifecycle policy can delete it; an export is a
// copy in a store with its own retention guarantees, made before any policy can
// reach it.
func (c *Client) Export(subjectRef, dir string) (ExportManifest, error) {
	attachments, err := c.List(subjectRef)
	if err != nil {
		return ExportManifest{}, err
	}
	if len(attachments) == 0 {
		return ExportManifest{}, fmt.Errorf("no evidence attached to %s", subjectRef)
	}
	ref, err := name.ParseReference(subjectRef, c.nameOpts...)
	if err != nil {
		return ExportManifest{}, err
	}
	head, err := remote.Head(ref, c.remoteOpts...)
	if err != nil {
		return ExportManifest{}, err
	}

	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o755); err != nil {
		return ExportManifest{}, err
	}
	ociDir := filepath.Join(dir, "oci")
	if err := os.MkdirAll(ociDir, 0o755); err != nil {
		return ExportManifest{}, err
	}
	path, err := layout.Write(ociDir, empty.Index)
	if err != nil {
		return ExportManifest{}, fmt.Errorf("initialising OCI layout: %w", err)
	}

	manifest := ExportManifest{
		APIVersion: "clearcutt.dev/v1",
		Kind:       "EvidenceExport",
		Source:     subjectRef,
		Subject:    ref.Context().Digest(head.Digest.String()).String(),
		Note:       exportNote,
	}

	for _, attachment := range attachments {
		target := ref.Context().Digest(attachment.Digest)
		img, err := remote.Image(target, c.remoteOpts...)
		if err != nil {
			return ExportManifest{}, fmt.Errorf("fetching evidence %s: %w", attachment.Digest, err)
		}
		// Digest-preserving copy: the layout keeps the original manifest bytes,
		// so a signature made over this attachment still verifies after a
		// round trip through the export.
		if err := path.AppendImage(img, layout.WithAnnotations(map[string]string{
			SubjectAnnotation: manifest.Subject,
			ReleaseAnnotation: attachment.Release,
		})); err != nil {
			return ExportManifest{}, fmt.Errorf("writing evidence %s to layout: %w", attachment.Digest, err)
		}

		bundle, err := c.Fetch(subjectRef, attachment.Digest)
		if err != nil {
			return ExportManifest{}, err
		}
		// Plain files land under a per-attachment directory so two attachments
		// carrying sbom.json do not overwrite each other.
		shortDigest := strings.TrimPrefix(attachment.Digest, "sha256:")
		if len(shortDigest) > 12 {
			shortDigest = shortDigest[:12]
		}
		fileDir := filepath.Join(dir, "files", shortDigest)
		if err := os.MkdirAll(fileDir, 0o755); err != nil {
			return ExportManifest{}, err
		}
		names := make([]string, 0, len(bundle.Files))
		for fileName := range bundle.Files {
			names = append(names, fileName)
		}
		sort.Strings(names)
		for _, fileName := range names {
			safe := filepath.Base(filepath.Clean(fileName))
			if safe == "." || safe == ".." || safe == string(filepath.Separator) {
				return ExportManifest{}, fmt.Errorf("evidence %s contains an unusable file name %q", attachment.Digest, fileName)
			}
			if err := os.WriteFile(filepath.Join(fileDir, safe), bundle.Files[fileName], 0o644); err != nil {
				return ExportManifest{}, err
			}
		}
		manifest.Attachments = append(manifest.Attachments, ExportAttachment{
			Digest:  attachment.Digest,
			Release: attachment.Release,
			Created: attachment.Created,
			Files:   names,
		})
	}

	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportManifest{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "export.json"), append(raw, '\n'), 0o644); err != nil {
		return ExportManifest{}, err
	}
	return manifest, nil
}

// Import pushes an exported OCI layout back into a registry, restoring every
// attachment under its original digest.
//
// This is the other half of surviving garbage collection: an export is only
// insurance if it can be put back.
func (c *Client) Import(dir, repoRef string) ([]string, error) {
	ociDir := filepath.Join(dir, "oci")
	path, err := layout.FromPath(ociDir)
	if err != nil {
		return nil, fmt.Errorf("reading OCI layout at %s: %w", ociDir, err)
	}
	index, err := path.ImageIndex()
	if err != nil {
		return nil, err
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}
	repo, err := name.ParseReference(repoRef, c.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing target reference %q: %w", repoRef, err)
	}

	restored := []string{}
	for _, entry := range manifest.Manifests {
		img, err := index.Image(entry.Digest)
		if err != nil {
			return nil, fmt.Errorf("reading %s from layout: %w", entry.Digest, err)
		}
		digest, err := img.Digest()
		if err != nil {
			return nil, err
		}
		target := repo.Context().Digest(digest.String())
		if err := remote.Write(target, img, c.remoteOpts...); err != nil {
			return nil, fmt.Errorf("restoring evidence %s: %w", digest, err)
		}
		restored = append(restored, digest.String())
	}
	sort.Strings(restored)
	return restored, nil
}
