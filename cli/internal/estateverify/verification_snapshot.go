package estateverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const snapshotLimit = 64 << 20

// verificationSnapshot is a metadata-only Cosign local-image layout. Target
// rootfs layers are deliberately absent: verification reads its manifest digest
// and the evidence payloads, not the filesystem. All paths are generated here.
type verificationSnapshot struct {
	files   map[string][]byte
	size    int
	bundles bool
}

func captureVerification(ctx context.Context, subj Subject, found []Found, opts []remote.Option) (*verificationSnapshot, error) {
	s := &verificationSnapshot{files: map[string][]byte{}}
	legacy := false
	artifacts := map[string]Found{}
	for _, f := range found {
		if f.Format != FormatBundle && f.Format != FormatCosignTag {
			continue
		}
		if f.artifact == nil {
			return nil, errors.New("evidence has no pinned artifact")
		}
		if f.Format == FormatBundle {
			if len(f.Statement) == 0 { // MessageSignature is not a DSSE bundle.
				return nil, errors.New("message signature bundles use live verification")
			}
			s.bundles = true
		} else {
			legacy = true
		}
		digest, err := f.artifact.Digest()
		if err != nil {
			return nil, err
		}
		artifacts[f.Format+"\x00"+f.Ref+"\x00"+digest.String()] = f
	}
	if len(artifacts) == 0 || (legacy && s.bundles) {
		return nil, errors.New("empty or mixed evidence uses live verification")
	}
	ref, err := name.NewDigest(subj.Ref)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(ref, append([]remote.Option{remote.WithContext(ctx)}, opts...)...)
	if err != nil {
		return nil, err
	}
	hash, err := v1.NewHash(ref.DigestStr())
	if err != nil {
		return nil, err
	}
	if err := s.addBlob(hash, desc.Manifest); err != nil {
		return nil, err
	}
	kind := "dev.cosignproject.cosign/image"
	if !s.bundles && desc.MediaType.IsIndex() {
		kind = "dev.cosignproject.cosign/imageIndex"
	}
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex,
		Manifests: []v1.Descriptor{{MediaType: desc.MediaType, Digest: hash, Size: int64(len(desc.Manifest)), Annotations: map[string]string{"kind": kind}}}}
	for _, key := range sortedKeys(artifacts) {
		f := artifacts[key]
		raw, err := f.artifact.RawManifest()
		if err != nil {
			return nil, err
		}
		digest, err := f.artifact.Digest()
		if err != nil {
			return nil, err
		}
		if err := s.addBlob(digest, raw); err != nil {
			return nil, err
		}
		manifest, err := f.artifact.Manifest()
		if err != nil {
			return nil, err
		}
		if f.Format == FormatCosignTag {
			if manifest.Subject != nil {
				return nil, errors.New("legacy evidence with a referrer subject uses live verification")
			}
			kind := "dev.cosignproject.cosign/atts"
			if strings.HasSuffix(f.Ref, ".sig") {
				kind = "dev.cosignproject.cosign/sigs"
			}
			index.Manifests = append(index.Manifests, v1.Descriptor{Digest: digest, Size: int64(len(raw)), MediaType: manifest.MediaType, Annotations: map[string]string{"kind": kind}})
		}
		for _, layer := range manifest.Layers {
			if s.bundles && !strings.HasPrefix(string(layer.MediaType), "application/vnd.dev.sigstore.bundle") {
				continue
			}
			raw, err := readBlob(f.artifact, layer.Digest)
			if err != nil {
				return nil, err
			}
			// Cosign's local bundle reader scans every JSON blob as a possible
			// referrer manifest. A payload must not introduce another manifest
			// that live registry discovery never listed.
			var envelope struct {
				Subject json.RawMessage `json:"subject"`
			}
			if json.Unmarshal(raw, &envelope) == nil && len(envelope.Subject) > 0 && string(envelope.Subject) != "null" {
				return nil, errors.New("ambiguous evidence payload uses live verification")
			}
			if err := s.addBlob(layer.Digest, raw); err != nil {
				return nil, err
			}
		}
	}
	raw, err := json.Marshal(index)
	if err != nil {
		return nil, err
	}
	if err := s.addFile("index.json", raw); err != nil {
		return nil, err
	}
	if err := s.addFile("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *verificationSnapshot) addBlob(hash v1.Hash, raw []byte) error {
	if hash.Algorithm != "sha256" || hash.Hex != contentHash(raw) {
		return errors.New("verification snapshot blob digest mismatch or unsupported algorithm")
	}
	return s.addFile("blobs/sha256/"+hash.Hex, raw)
}

func (s *verificationSnapshot) addFile(path string, raw []byte) error {
	if previous, ok := s.files[path]; ok {
		if contentHash(previous) != contentHash(raw) {
			return errors.New("verification snapshot path collision")
		}
		return nil
	}
	if len(s.files) >= 2048 || len(raw) > snapshotLimit-s.size {
		return errors.New("verification snapshot exceeds its budget")
	}
	s.files[path] = raw
	s.size += len(raw)
	return nil
}

func (s *verificationSnapshot) identity() string {
	// Include path names as well as content: index annotations select which
	// digest Cosign checks, and must not be detached from their target bytes.
	var rows []string
	for path, raw := range s.files {
		rows = append(rows, path+"\x00"+contentHash(raw))
	}
	sort.Strings(rows)
	return contentHash([]byte(strings.Join(rows, "\n")))
}

func (s *verificationSnapshot) write(dir string) error {
	for path, raw := range s.files {
		file := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(file, raw, 0o600); err != nil {
			return fmt.Errorf("write verification snapshot: %w", err)
		}
	}
	return nil
}

func contentHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
