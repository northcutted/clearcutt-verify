package estateverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// VerificationCache stores successful Cosign answers in trusted local state.
// Discovery, caller constraints, parsers, rescans and verdicts are never cached.
type VerificationCache struct {
	dir, namespace         string
	opts                   []remote.Option
	Disabled               string
	hits, misses, bypasses atomic.Int64
}

// NewVerificationCache is best-effort: unsupported tools or unavailable/private
// storage disable reuse, never verification. Both executable hashes distinguish
// patched binaries and dev builds sharing the same version string.
func NewVerificationCache(dir, version, cosignVersion, cosignBinary string, opts []remote.Option) *VerificationCache {
	c := &VerificationCache{dir: dir, opts: opts}
	if !localCacheCosign(cosignVersion) {
		c.Disabled = "local snapshot caching needs Cosign 3.1.3 or newer in major version 3"
		return c
	}
	self, err := os.Executable()
	if err != nil {
		c.Disabled = err.Error()
		return c
	}
	cosign, err := exec.LookPath(cosignBinary)
	if err != nil {
		c.Disabled = err.Error()
		return c
	}
	appHash, err := executableHash(self)
	if err != nil {
		c.Disabled = err.Error()
		return c
	}
	cosignHash, err := executableHash(cosign)
	if err != nil {
		c.Disabled = err.Error()
		return c
	}
	c.namespace = contentHash([]byte("clearcutt-verification-cache/v1\x00" + version + "\x00" + appHash + "\x00" + cosignVersion + "\x00" + cosignHash))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		c.Disabled = err.Error()
	} else if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		c.Disabled = "cache directory must be a private directory, not a symlink (mode 0700)"
	}
	return c
}

// Stats reports cryptographic verification reuse only, never policy passes.
func (c *VerificationCache) Stats() (hits, misses, bypasses int64) {
	return c.hits.Load(), c.misses.Load(), c.bypasses.Load()
}

func localCacheCosign(version string) bool {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(parts) != 3 {
		return false
	}
	major, a := strconv.Atoi(parts[0])
	minor, b := strconv.Atoi(parts[1])
	patch, d := strconv.Atoi(parts[2])
	return a == nil && b == nil && d == nil && major == 3 && (minor > 1 || minor == 1 && patch >= 3)
}

func executableHash(path string) (string, error) {
	f, err := openVerificationFile(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("executable is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *VerificationCache) verify(ctx context.Context, v *Verifier, subj Subject, flags []string) ([][]byte, bool, error) {
	bypass := func() ([][]byte, bool, error) { c.bypasses.Add(1); return nil, false, nil }
	if c.Disabled != "" || len(v.cacheFound) == 0 {
		return bypass()
	}
	// Alternate trust-target files and remote key resolvers are not identified
	// by their paths/URIs alone. Keep those on the existing live path.
	for _, variable := range sigstoreTargetVars {
		if os.Getenv(variable) != "" {
			return bypass()
		}
	}
	if os.Getenv("COSIGN_REPOSITORY") != "" {
		return bypass()
	}
	snapshot, err := captureVerification(ctx, subj, v.cacheFound, c.opts)
	if err != nil {
		return bypass()
	}
	if !snapshot.bundles && !contains(flags, "--insecure-ignore-tlog=true") {
		return bypass()
	}
	localFlags := append([]string{}, flags...)
	for i := 0; i < len(localFlags)-1; i++ {
		if localFlags[i] == "--key" {
			raw, err := localTrustFile(localFlags[i+1])
			if err != nil {
				return bypass()
			}
			if err := snapshot.addFile("key.pem", raw); err != nil {
				return bypass()
			}
			localFlags[i+1] = "key.pem"
		}
	}
	if !contains(flags, "--insecure-ignore-tlog=true") {
		raw, err := localTrustFile(v.TrustedRoot)
		if err != nil {
			return bypass()
		}
		if err := snapshot.addFile("trusted-root.json", raw); err != nil {
			return bypass()
		}
	}
	identity := struct {
		Namespace, Snapshot string
		Subject             Subject
		Flags               []string
		Signers             any
	}{c.namespace, snapshot.identity(), subj, flags, v.Signers}
	raw, err := json.Marshal(identity)
	if err != nil {
		return bypass()
	}
	key := contentHash(raw)
	if output, ok := c.read(key); ok {
		if statements, err := cachedOutput(output, subj, snapshot.bundles); err == nil && ctx.Err() == nil {
			c.hits.Add(1)
			return statements, true, nil
		}
	}
	c.misses.Add(1)
	dir, err := os.MkdirTemp("", "clearcutt-verify-evidence-")
	if err != nil {
		return bypass()
	}
	defer os.RemoveAll(dir)
	if err := snapshot.write(dir); err != nil {
		return bypass()
	}
	for i := range localFlags {
		if localFlags[i] == "key.pem" {
			localFlags[i] = filepath.Join(dir, "key.pem")
		}
	}
	args := []string{"verify-attestation", "--type", subj.PredicateType}
	if subj.Kind == KindSignature && !snapshot.bundles {
		args = []string{"verify"}
	}
	args = append(append(args, "--output", "json"), localFlags...)
	if _, ok := snapshot.files["trusted-root.json"]; ok {
		args = append(args, "--trusted-root", filepath.Join(dir, "trusted-root.json"))
	}
	args = append(args, "--local-image", dir)
	output, err := v.run(ctx, args...)
	if couldntCheck(err) {
		return nil, true, err
	}
	if err != nil {
		return bypass()
	} // preserve live behavior for unsupported layouts
	statements, err := cachedOutput(output, subj, snapshot.bundles)
	if err != nil {
		return bypass()
	}
	c.write(key, output)
	return statements, true, nil
}

func localTrustFile(path string) ([]byte, error) {
	if path == "" || strings.Contains(path, "://") {
		return nil, errors.New("trust material is not a local file")
	}
	f, err := openVerificationFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil, errors.New("unsupported trust file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if len(raw) > 16<<20 {
		return nil, errors.New("trust file exceeds budget")
	}
	return raw, err
}

// V3 image signatures are DSSE CosignSign statements. Upstream's remote verify
// synthesizes its simple-signature answer from the FIRST signed subject. Its
// local verify path lacks that transformation, so ask the local attestation
// verifier for the exact predicate and check the same signed identity here.
func cachedOutput(output []byte, subj Subject, bundles bool) ([][]byte, error) {
	if !bundles || subj.Kind != KindSignature {
		return verifiedOutput(output, subj)
	}
	attestation := subj
	attestation.Kind, attestation.PredicateType = KindProvenance, PredicateCosignSign
	statements, err := verifiedOutput(output, attestation)
	if err != nil {
		return nil, err
	}
	_, digest, _ := strings.Cut(subj.Ref, "@")
	for _, statement := range statements {
		var signed struct {
			Subject []struct {
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
		}
		if json.Unmarshal(statement, &signed) == nil && len(signed.Subject) > 0 && len(signed.Subject[0].Digest) == 1 && "sha256:"+signed.Subject[0].Digest["sha256"] == digest {
			return nil, nil
		}
	}
	return nil, errors.New("no CosignSign statement whose first subject is this image")
}

type verificationEntry struct {
	Key      string `json:"key"`
	Output   []byte `json:"output"`
	Checksum string `json:"checksum"`
}

func (c *VerificationCache) read(key string) ([]byte, bool) {
	path := filepath.Join(c.dir, key+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > snapshotLimit {
		return nil, false
	}
	f, err := openVerificationFile(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, snapshotLimit+1))
	if err != nil || len(raw) > snapshotLimit {
		return nil, false
	}
	var entry verificationEntry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&entry) != nil || dec.Decode(new(any)) != io.EOF || entry.Key != key || entry.Checksum != contentHash(entry.Output) {
		return nil, false
	}
	return entry.Output, true
}

// Reject devices/FIFOs before opening, then check the opened descriptor too.
// Official Unix builds also open nonblocking, so swapping in a FIFO between
// the type check and open cannot escape the external-operation timeouts.
func openVerificationFile(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("verification input is not a regular file")
	}
	f, err := openVerificationPath(path)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("verification input is not a regular file")
	}
	return f, nil
}

func (c *VerificationCache) write(key string, output []byte) {
	raw, err := json.Marshal(verificationEntry{key, output, contentHash(output)})
	if err != nil || len(raw) > snapshotLimit {
		return
	}
	f, err := os.CreateTemp(c.dir, ".verification-")
	if err != nil {
		return
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		return
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return
	}
	if err = f.Close(); err != nil {
		return
	}
	_ = os.Rename(tmp, filepath.Join(c.dir, key+".json"))
}
