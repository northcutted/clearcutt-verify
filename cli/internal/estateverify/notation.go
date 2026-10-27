package estateverify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/northcutted/clearcutt-verify/internal/operation"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

const DefaultNotationTimeout = 2 * time.Minute

// NotationRunner allows tests to inspect isolated subprocess configuration.
type NotationRunner func(context.Context, string, []string, ...string) (stdout, stderr []byte, err error)

// NotationVerifier verifies one pinned signature at a time. It is intentionally
// outside persistent caching: expiry and revocation must be evaluated now.
type NotationVerifier struct {
	trust       report.NotationTrust
	roots       [][]byte
	binary      string
	timeout     time.Duration
	opts        []remote.Option
	run         NotationRunner
	unavailable string
	probeError  error
}

func validateNotationTrust(p *report.NotationTrust) error {
	if p == nil {
		return nil
	}
	if len(p.TrustedIdentities) == 0 || len(p.TrustRoots) == 0 {
		return errors.New("notation needs trustedIdentities and local trustRoots")
	}
	for _, identity := range p.TrustedIdentities {
		if !strings.HasPrefix(identity, "x509.subject:") || strings.TrimSpace(strings.TrimPrefix(identity, "x509.subject:")) == "" || strings.ContainsAny(identity, "*\r\n") {
			return fmt.Errorf("notation trusted identity %q must name an x509.subject distinguished name without wildcards", identity)
		}
	}
	for _, root := range p.TrustRoots {
		if strings.TrimSpace(root) == "" || strings.Contains(root, "://") {
			return fmt.Errorf("notation trust root %q must be a local certificate file", root)
		}
	}
	return nil
}

// NewNotationVerifier loads explicit roots once. Missing or unsupported CLIs
// leave signatures present; invalid configured certificate files are errors.
func NewNotationVerifier(ctx context.Context, trust *report.NotationTrust, binary string, timeout time.Duration, opts []remote.Option, runner NotationRunner) (*NotationVerifier, error) {
	if trust == nil {
		return nil, nil
	}
	if err := validateNotationTrust(trust); err != nil {
		return nil, err
	}
	if binary == "" {
		binary = "notation"
	}
	v := &NotationVerifier{trust: *trust, binary: binary, timeout: operation.Limit(timeout, DefaultNotationTimeout), opts: opts, run: runner}
	v.trust.TrustedIdentities = append([]string{}, trust.TrustedIdentities...)
	if runner == nil {
		if _, err := exec.LookPath(binary); err != nil {
			v.unavailable = "notation is not installed (or --notation-path is unavailable)"
			return v, nil
		}
	}
	probe, err := os.MkdirTemp("", "clearcutt-notation-probe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(probe)
	stdout, stderr, err := v.invoke(ctx, probe, "version")
	if err != nil {
		v.probeError = fmt.Errorf("notation version could not be checked: %w: %s", err, lastLine(string(stderr)))
		return v, nil
	}
	version := regexp.MustCompile(`(?m)^Version:\s+1\.3\.(\d+)\s*$`).FindSubmatch(stdout)
	if len(version) < 2 {
		v.unavailable = "Notation 1.3.2+ in the 1.3 series is required for pinned experimental OCI-layout verification"
		return v, nil
	}
	patch, _ := strconv.Atoi(string(version[1]))
	if patch < 2 {
		v.unavailable = "Notation 1.3.2 or newer in the 1.3 series is required"
		return v, nil
	}
	for _, path := range trust.TrustRoots {
		raw, err := localTrustFile(path)
		if err != nil {
			return nil, fmt.Errorf("notation trust root %s: %w", path, err)
		}
		var normalized []byte
		for len(bytes.TrimSpace(raw)) > 0 {
			block, rest := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("notation trust root %s must contain PEM certificates", path)
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("notation trust root %s: %w", path, err)
			}
			normalized = append(normalized, pem.EncodeToMemory(block)...)
			raw = rest
		}
		if len(normalized) == 0 {
			return nil, fmt.Errorf("notation trust root %s has no certificate", path)
		}
		v.roots = append(v.roots, normalized)
	}
	return v, nil
}

func notationEnvironment(dir string) []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NOTATION_") {
			env = append(env, entry)
		}
	}
	return append(env, "NOTATION_CONFIG="+filepath.Join(dir, "config"), "NOTATION_CACHE="+filepath.Join(dir, "cache"), "NOTATION_LIBEXEC="+filepath.Join(dir, "plugins"), "NOTATION_EXPERIMENTAL=1")
}

func (v *NotationVerifier) invoke(ctx context.Context, dir string, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	env := notationEnvironment(dir)
	if v.run != nil {
		stdout, stderr, err := v.run(ctx, v.binary, env, args...)
		return stdout, stderr, operation.Result(ctx, "notation "+args[0], v.timeout, err)
	}
	cmd := exec.CommandContext(ctx, v.binary, args...)
	cmd.Env, cmd.WaitDelay = env, operation.PipeWait
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), operation.Result(ctx, "notation "+args[0], v.timeout, err)
}

// Verify uses a generated STRICT policy, an empty plugin directory and exactly
// one captured signature. Aggregate registry success never verifies a claim
// belonging to another signature. Opaque CLI failures remain unknown.
func (v *NotationVerifier) Verify(ctx context.Context, subject string, f Found) (string, string) {
	if v.probeError != nil {
		return "unknown", v.probeError.Error()
	}
	if v.unavailable != "" {
		return "present", v.unavailable + "; the Notation signature is present, not verified."
	}
	if f.artifact == nil {
		return "unknown", "The Notation signature could not be pinned to its captured artifact."
	}
	dir, err := os.MkdirTemp("", "clearcutt-notation-")
	if err != nil {
		return "unknown", err.Error()
	}
	defer os.RemoveAll(dir)
	ref, err := name.NewDigest(subject)
	if err != nil {
		return "unknown", err.Error()
	}
	layout, err := v.snapshot(ctx, ref, f)
	if err != nil {
		return "unknown", "Notation evidence could not be pinned: " + err.Error()
	}
	if err := layout.write(filepath.Join(dir, "layout")); err != nil {
		return "unknown", err.Error()
	}
	rootDir := filepath.Join(dir, "config", "truststore", "x509", "ca", "clearcutt")
	for _, path := range []string{rootDir, filepath.Join(dir, "cache"), filepath.Join(dir, "plugins")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return "unknown", err.Error()
		}
	}
	for i, root := range v.roots {
		if err := os.WriteFile(filepath.Join(rootDir, fmt.Sprintf("root-%d.pem", i)), root, 0o600); err != nil {
			return "unknown", err.Error()
		}
	}
	policy := map[string]any{"version": "1.0", "trustPolicies": []any{map[string]any{
		"name": "clearcutt", "registryScopes": []string{ref.Context().Name()}, "signatureVerification": map[string]string{"level": "strict"},
		"trustStores": []string{"ca:clearcutt"}, "trustedIdentities": v.trust.TrustedIdentities}}}
	raw, _ := json.Marshal(policy)
	if err := os.WriteFile(filepath.Join(dir, "config", "trustpolicy.json"), raw, 0o600); err != nil {
		return "unknown", err.Error()
	}
	localRef := filepath.Join(dir, "layout") + "@" + ref.DigestStr()
	stdout, stderr, err := v.invoke(ctx, dir, "verify", "--oci-layout", localRef, "--scope", ref.Context().Name(), "--max-signatures", "1")
	if err != nil {
		return "unknown", fmt.Sprintf("Notation could not establish verification (a signature, certificate, expiry, revocation or operational check failed): %v: %s", err, lastLine(string(stderr)))
	}
	want := "Successfully verified signature for " + localRef
	for _, line := range strings.Split(string(stdout), "\n") {
		if strings.TrimSpace(line) == want {
			return "verified", "Notation checked this pinned signature against a strict policy."
		}
	}
	return "unknown", "Notation returned no exact success for the pinned subject; skip/audit output cannot establish verification."
}

func (v *NotationVerifier) snapshot(ctx context.Context, ref name.Digest, f Found) (*verificationSnapshot, error) {
	s := &verificationSnapshot{files: map[string][]byte{}}
	desc, err := remote.Get(ref, append([]remote.Option{remote.WithContext(ctx)}, v.opts...)...)
	if err != nil {
		return nil, err
	}
	if err := s.addBlob(desc.Digest, desc.Manifest); err != nil {
		return nil, err
	}
	m, err := f.artifact.Manifest()
	if err != nil {
		return nil, err
	}
	if m.Subject == nil || m.Subject.Digest != desc.Digest || len(m.Layers) != 1 {
		return nil, errors.New("notation manifest must describe exactly this subject and one envelope")
	}
	if m.Config.MediaType != notationArtifactType && m.ArtifactType != notationArtifactType {
		return nil, errors.New("not a Notation signature manifest")
	}
	raw, err := f.artifact.RawManifest()
	if err != nil {
		return nil, err
	}
	digest, err := f.artifact.Digest()
	if err != nil {
		return nil, err
	}
	if f.Ref != ref.Context().Digest(digest.String()).String() {
		return nil, errors.New("captured signature does not match its immutable reference")
	}
	if err := s.addBlob(digest, raw); err != nil {
		return nil, err
	}
	config, err := f.artifact.RawConfigFile()
	if err != nil {
		return nil, err
	}
	if err := s.addBlob(m.Config.Digest, config); err != nil {
		return nil, err
	}
	for _, layer := range m.Layers {
		raw, err := readBlob(f.artifact, layer.Digest)
		if err != nil {
			return nil, err
		}
		if err := s.addBlob(layer.Digest, raw); err != nil {
			return nil, err
		}
	}
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{
		desc.Descriptor, {MediaType: m.MediaType, Digest: digest, Size: int64(len(raw))}}}
	raw, err = json.Marshal(index)
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
