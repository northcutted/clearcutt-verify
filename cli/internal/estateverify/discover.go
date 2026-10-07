// Package estateverify verifies an image estate and writes the estate report
// (see contract/README.md): for every observed image it discovers the
// supply-chain evidence attached in the registry, verifies it against the
// policy's trusted signers with cosign, reads vulnerabilities, packages, and
// clearcutt-factory recipes and rebase records out of the attestations, and
// decides a verdict.
package estateverify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// Evidence kinds, as the report names them.
const (
	KindSignature         = "signature"
	KindSBOM              = "sbom"
	KindVulnerabilityScan = "vulnerabilityScan"
	KindProvenance        = "provenance"
	KindRecipe            = "recipe"
	KindRebase            = "rebase"
	KindTests             = "tests"
)

// Kinds lists every evidence kind in report order.
var Kinds = []string{KindSignature, KindSBOM, KindVulnerabilityScan, KindProvenance, KindRecipe, KindRebase, KindTests}

// Storage formats evidence is found in.
const (
	FormatBundle      = "sigstore-bundle" // cosign v3 / GitHub: a Sigstore bundle as an OCI referrer
	FormatCosignTag   = "cosign-tag"      // cosign v2: sha256-<digest>.sig / .att tags
	FormatRawReferrer = "oci-referrer"    // an unsigned document attached as a referrer (a raw SBOM)
)

// Predicate types factory and cosign use.
const (
	PredicateCosignSign = "https://sigstore.dev/cosign/sign/v1"
	PredicateVuln       = "https://cosign.sigstore.dev/attestation/vuln/v1"
	PredicateRecipe     = "https://github.com/northcutted/clearcutt-factory/recipe/v1"
	PredicateRebase     = "https://github.com/northcutted/clearcutt-factory/rebase/v1"
	// Before clearcutt-factory had its name.
	legacyPredicateRecipe = "https://github.com/northcutted/declarative-image-factory/recipe/v1"
	legacyPredicateRebase = "https://github.com/northcutted/declarative-image-factory/rebase/v1"
)

// KindOf maps an in-toto predicate type to an evidence kind ("" when the
// report has no kind for it).
func KindOf(predicateType string) string {
	pt := strings.TrimSpace(predicateType)
	switch {
	case pt == PredicateCosignSign:
		return KindSignature
	case strings.HasPrefix(pt, "https://cyclonedx.org/bom"), strings.HasPrefix(pt, "https://spdx.dev/Document"), pt == "cyclonedx", pt == "spdx", pt == "spdxjson":
		return KindSBOM
	case pt == PredicateVuln, pt == "vuln":
		return KindVulnerabilityScan
	case strings.HasPrefix(pt, "https://slsa.dev/provenance/"), pt == "slsaprovenance", pt == "slsaprovenance1":
		return KindProvenance
	case pt == PredicateRecipe, pt == legacyPredicateRecipe:
		return KindRecipe
	case pt == PredicateRebase, pt == legacyPredicateRebase:
		return KindRebase
	case strings.HasPrefix(pt, "https://in-toto.io/attestation/test-result/"):
		return KindTests
	}
	return ""
}

// Found is one piece of evidence attached to an image.
type Found struct {
	Kind          string
	PredicateType string
	Format        string
	// Ref is where it is stored (repository@digest of its manifest, or the
	// legacy tag).
	Ref string
	// Subject is the digest it is about.
	Subject string
	// Signer is who claims to have signed it, read from the certificate
	// (not yet verified).
	Signer *report.Signer
	// Timestamp is the transparency log time, or the artifact's creation time.
	Timestamp string
	// Statement is the in-toto statement (attestations), or the document
	// (raw referrers).
	Statement []byte
}

// Predicate returns the statement's predicate.
func (f Found) Predicate() json.RawMessage {
	var st struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if json.Unmarshal(f.Statement, &st) == nil {
		return st.Predicate
	}
	return nil
}

// Discoverer reads evidence from registries.
type Discoverer struct {
	Options []remote.Option
}

// ErrUnknown wraps registry failures that leave evidence unknown rather
// than missing.
var ErrUnknown = errors.New("evidence could not be read")

// Discover lists the evidence attached to repository@digest: Sigstore
// bundle referrers (cosign v3, GitHub artifact attestations), legacy cosign
// .sig/.att tags, and unsigned SBOM referrers.
func (d *Discoverer) Discover(ctx context.Context, repository, digest string) ([]Found, error) {
	subject, err := name.NewDigest(repository + "@" + digest)
	if err != nil {
		return nil, err
	}
	opts := append([]remote.Option{remote.WithContext(ctx)}, d.Options...)
	var out []Found

	// The referrers tag (what cosign writes where the registry has no
	// Referrers API) is checked with a HEAD first: registries such as Docker
	// Hub rate-limit GETs, not HEADs. Without one, ask the Referrers API.
	var idx v1.ImageIndex
	fallback := subject.Context().Tag(strings.Replace(subject.DigestStr(), ":", "-", 1))
	if _, err := remote.Head(fallback, opts...); err == nil {
		idx, err = remote.Index(fallback, opts...)
		if err != nil {
			return nil, fmt.Errorf("%w: referrers of %s: %v", ErrUnknown, subject, err)
		}
	} else if !isNotFound(err) {
		return nil, fmt.Errorf("%w: referrers of %s: %v", ErrUnknown, subject, err)
	} else if idx, err = remote.Referrers(subject, opts...); err != nil {
		if !isNotFound(err) {
			return nil, fmt.Errorf("%w: referrers of %s: %v", ErrUnknown, subject, err)
		}
		idx = nil
	}
	if idx != nil {
		im, err := idx.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnknown, err)
		}
		for _, desc := range im.Manifests {
			ref := subject.Context().Digest(desc.Digest.String())
			switch at := desc.ArtifactType; {
			// cosign v3 lists its bundles under the empty config's media
			// type; only the manifest itself says it holds a bundle.
			case strings.HasPrefix(at, "application/vnd.dev.sigstore.bundle"), at == "", at == emptyMediaType:
				f, ok, err := d.bundle(ctx, ref, opts)
				if err != nil {
					return nil, fmt.Errorf("%w: %s: %v", ErrUnknown, ref, err)
				}
				if ok {
					out = append(out, f)
				}
			case at == "application/vnd.cyclonedx+json", at == "application/spdx+json", at == "text/spdx+json":
				out = append(out, Found{Kind: KindSBOM, PredicateType: at, Format: FormatRawReferrer, Ref: ref.String(), Subject: digest,
					Timestamp: desc.Annotations["org.opencontainers.image.created"]})
			}
		}
	}

	legacy, err := d.cosignTags(ctx, subject, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	return append(out, legacy...), nil
}

const emptyMediaType = "application/vnd.oci.empty.v1+json"

// bundle reads a referrer that may hold a Sigstore bundle; ok is false when
// it holds something else.
func (d *Discoverer) bundle(ctx context.Context, ref name.Digest, opts []remote.Option) (Found, bool, error) {
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return Found{}, false, err
	}
	m, err := img.Manifest()
	if err != nil {
		return Found{}, false, err
	}
	if len(m.Layers) == 0 || !strings.HasPrefix(string(m.Layers[0].MediaType), "application/vnd.dev.sigstore.bundle") {
		return Found{}, false, nil
	}
	raw, err := readBlob(img, m.Layers[0].Digest)
	if err != nil {
		return Found{}, false, err
	}
	f, err := decodeBundle(raw)
	if err != nil {
		return Found{}, false, err
	}
	f.Ref = ref.String()
	if f.Timestamp == "" {
		f.Timestamp = m.Annotations["org.opencontainers.image.created"]
	}
	return f, true, nil
}

// decodeBundle reads a Sigstore bundle (v0.1-v0.3): its DSSE statement and
// the signer its certificate names.
func decodeBundle(raw []byte) (Found, error) {
	var b struct {
		VerificationMaterial struct {
			Certificate *struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
			X509CertificateChain *struct {
				Certificates []struct {
					RawBytes string `json:"rawBytes"`
				} `json:"certificates"`
			} `json:"x509CertificateChain"`
			PublicKey *struct {
				Hint string `json:"hint"`
			} `json:"publicKey"`
			TlogEntries []struct {
				IntegratedTime string `json:"integratedTime"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
		DSSEEnvelope *struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
		MessageSignature *struct{} `json:"messageSignature"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return Found{}, fmt.Errorf("parsing bundle: %w", err)
	}
	f := Found{Format: FormatBundle}
	if b.DSSEEnvelope != nil {
		st, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
		if err != nil {
			return Found{}, fmt.Errorf("bundle payload: %w", err)
		}
		f.Statement = st
		var s struct {
			PredicateType string `json:"predicateType"`
			Subject       []struct {
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
		}
		if err := json.Unmarshal(st, &s); err != nil {
			return Found{}, fmt.Errorf("bundle statement: %w", err)
		}
		f.PredicateType = s.PredicateType
		if len(s.Subject) > 0 {
			if h := s.Subject[0].Digest["sha256"]; h != "" {
				f.Subject = "sha256:" + h
			}
		}
	} else if b.MessageSignature != nil {
		// A plain signature over the image (no statement).
		f.PredicateType = PredicateCosignSign
	}
	f.Kind = KindOf(f.PredicateType)

	vm := b.VerificationMaterial
	var der string
	switch {
	case vm.Certificate != nil:
		der = vm.Certificate.RawBytes
	case vm.X509CertificateChain != nil && len(vm.X509CertificateChain.Certificates) > 0:
		der = vm.X509CertificateChain.Certificates[0].RawBytes
	}
	if der != "" {
		if raw, err := base64.StdEncoding.DecodeString(der); err == nil {
			if cert, err := x509.ParseCertificate(raw); err == nil {
				f.Signer = signerOf(cert)
			}
		}
	} else if vm.PublicKey != nil {
		f.Signer = &report.Signer{Key: vm.PublicKey.Hint}
	}
	if len(vm.TlogEntries) > 0 {
		if sec, err := strconv.ParseInt(vm.TlogEntries[0].IntegratedTime, 10, 64); err == nil && sec > 0 {
			f.Timestamp = time.Unix(sec, 0).UTC().Format(time.RFC3339)
		}
	}
	return f, nil
}

// Fulcio certificate extensions. The v1 ones hold raw strings, the v2 ones
// DER-encoded UTF8Strings.
var (
	oidIssuerV1           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidWorkflowRepository = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5} // v1: owner/repo
	oidWorkflowRef        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6} // v1
	oidIssuerV2           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidSourceRepository   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidSourceRef          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14}
)

// signerOf reads the identity (the URI or email SAN), the OIDC issuer, and
// the repository and ref of the run that signed from a Fulcio certificate.
func signerOf(cert *x509.Certificate) *report.Signer {
	s := &report.Signer{}
	switch {
	case len(cert.URIs) > 0:
		s.Identity = cert.URIs[0].String()
	case len(cert.EmailAddresses) > 0:
		s.Identity = cert.EmailAddresses[0]
	}
	v1, v2 := map[string]string{}, map[string]string{}
	for _, ext := range cert.Extensions {
		v1[ext.Id.String()] = string(ext.Value)
		var v string
		if _, err := asn1.Unmarshal(ext.Value, &v); err == nil {
			v2[ext.Id.String()] = v
		}
	}
	s.Issuer = firstNonEmpty(v2[oidIssuerV2.String()], v1[oidIssuerV1.String()])
	s.SourceRepository = v2[oidSourceRepository.String()]
	if r := v1[oidWorkflowRepository.String()]; s.SourceRepository == "" && r != "" && s.Issuer == githubIssuer {
		s.SourceRepository = "https://github.com/" + r
	}
	s.SourceRef = firstNonEmpty(v2[oidSourceRef.String()], v1[oidWorkflowRef.String()])
	if s.Identity == "" && s.Issuer == "" {
		return nil
	}
	return s
}

const githubIssuer = "https://token.actions.githubusercontent.com"

// cosignTags reads cosign v2's sha256-<digest>.sig and .att tags.
func (d *Discoverer) cosignTags(ctx context.Context, subject name.Digest, opts []remote.Option) ([]Found, error) {
	base := strings.Replace(subject.DigestStr(), ":", "-", 1)
	var out []Found
	for _, suffix := range []string{".sig", ".att"} {
		tag := subject.Context().Tag(base + suffix)
		if _, err := remote.Head(tag, opts...); isNotFound(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("%s: %v", tag, err)
		}
		img, err := remote.Image(tag, opts...)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", tag, err)
		}
		m, err := img.Manifest()
		if err != nil {
			return nil, err
		}
		for _, layer := range m.Layers {
			f := Found{Format: FormatCosignTag, Ref: tag.String(), Subject: subject.DigestStr(), Signer: legacySigner(layer.Annotations)}
			if suffix == ".sig" {
				f.Kind, f.PredicateType = KindSignature, PredicateCosignSign
				out = append(out, f)
				continue
			}
			f.PredicateType = layer.Annotations["predicateType"]
			raw, err := readBlob(img, layer.Digest)
			if err != nil {
				return nil, err
			}
			var env struct {
				Payload string `json:"payload"`
			}
			if json.Unmarshal(raw, &env) == nil {
				if st, err := base64.StdEncoding.DecodeString(env.Payload); err == nil {
					f.Statement = st
					var s struct {
						PredicateType string `json:"predicateType"`
					}
					if json.Unmarshal(st, &s) == nil && s.PredicateType != "" {
						f.PredicateType = s.PredicateType
					}
				}
			}
			f.Kind = KindOf(f.PredicateType)
			out = append(out, f)
		}
	}
	return out, nil
}

// legacySigner reads cosign v2's certificate annotation.
func legacySigner(ann map[string]string) *report.Signer {
	block, _ := pem.Decode([]byte(ann["dev.sigstore.cosign/certificate"]))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return signerOf(cert)
}

func readBlob(img v1.Image, digest v1.Hash) ([]byte, error) {
	l, err := img.LayerByDigest(digest)
	if err != nil {
		return nil, err
	}
	rc, err := l.Compressed()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(rc, 64<<20)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func isNotFound(err error) bool {
	var terr *transport.Error
	return errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound
}
