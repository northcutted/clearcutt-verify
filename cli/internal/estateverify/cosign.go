package estateverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// CosignMajor is the cosign major version whose formats the verifier reads:
// the Sigstore bundles cosign v3 stores as OCI referrers by default (which
// cosign v2 doesn't find without flags this verifier doesn't pass), cosign
// v2's .sig and .att tags, and cosign v3's --output json.
const CosignMajor = 3

// uncheckedError is a cosign run that decided nothing about the evidence:
// cosign couldn't run, its output couldn't be read, or it couldn't reach a
// registry, the transparency log, or its trust root. The evidence it was
// checking is unknown, not failed: whether a trusted signer signed it is
// undecided.
type uncheckedError struct{ err error }

func (e *uncheckedError) Error() string { return e.err.Error() }
func (e *uncheckedError) Unwrap() error { return e.err }

// couldntCheck reports whether err decided nothing about the evidence.
func couldntCheck(err error) bool {
	var u *uncheckedError
	return errors.As(err, &u)
}

// unchecked marks err as deciding nothing.
func unchecked(err error) error {
	if err == nil || couldntCheck(err) {
		return err
	}
	return &uncheckedError{err}
}

// operationalErrors are what Go's network stack and go-containerregistry
// (which cosign uses) say when a host can't be reached or a registry
// refuses or fails a request, as opposed to cosign saying the evidence
// doesn't verify. Each has a space in it: a certificate identity an attacker
// chooses (a URI or an email address, which cosign may repeat in its error)
// can't, so it can't make a verification failure read as a network failure.
var operationalErrors = []string{
	"dial tcp", "dial udp", "proxyconnect tcp", "connection refused", "connection reset by peer", "no such host",
	"i/o timeout", "network is unreachable", "tls handshake timeout", "context deadline exceeded",
	"client.timeout exceeded", "server misbehaving",
	"status code 401", "status code 403", "status code 408", "status code 429",
	"status code 500", "status code 502", "status code 503", "status code 504",
	"unauthorized: ", "denied: ", "toomanyrequests: ",
	// cosign couldn't get Sigstore's trusted root (the TUF repository
	// unreachable, or its cache half-written by a concurrent cosign): it then
	// has nothing to verify a certificate against. cosign v3.0.x says only
	// "trusted root is required", after warning what TUF said.
	"trusted root is required", "could not fetch trusted_root", "error from tuf", "tuf repository",
	"tuf updater", "getting live trusted root", "fetching trusted root", "loading trusted root", "error setting tuf",
	// The legacy TUF client (sigstore/sigstore, go-tuf v0.7), which cosign
	// falls back to for individual targets (Rekor and CT log keys, Fulcio
	// roots), says the same of its own cache.
	"initializing tuf", "tuf: failed to decode", "local cache may be corrupt",
}

// classify marks errors that decided nothing about the evidence: cosign
// couldn't be started, the run was cancelled, or what cosign said is a
// network or registry failure.
func classify(ctx context.Context, err error) error {
	if err == nil || couldntCheck(err) {
		return err
	}
	var execErr *exec.Error
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &execErr) {
		return unchecked(err)
	}
	msg := strings.ToLower(err.Error())
	for _, s := range operationalErrors {
		if strings.Contains(msg, s) {
			return unchecked(err)
		}
	}
	return err
}

// failure is the status and detail of evidence cosign didn't verify: unknown
// when cosign couldn't check it, else failed.
func failure(err error, detail string) (string, string) {
	if couldntCheck(err) {
		return "unknown", uncheckedDetail(err)
	}
	return "failed", detail
}

// uncheckedDetail says why evidence cosign couldn't check is unknown.
func uncheckedDetail(err error) string {
	return "cosign couldn't check it (cosign, a registry, or the transparency log failed), so whether a trusted signer signed it is unknown: " + err.Error()
}

// Sigstore variables under which cosign verifies against individual targets
// (keys and roots given by file) instead of the TUF trusted root.
var sigstoreTargetVars = []string{"SIGSTORE_ROOT_FILE", "SIGSTORE_REKOR_PUBLIC_KEY", "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", "SIGSTORE_TSA_CERTIFICATE_FILE"}

// PrepareTrustedRoot fetches Sigstore's trusted root once, before anything
// is verified, and makes every verification that needs it read it from that
// file (--trusted-root) instead of refreshing it from the TUF repository
// itself. Each cosign run refreshes TUF metadata over the network and
// rewrites the shared cache (~/.sigstore/root), so with verifications
// running concurrently one can find the repository unreachable, or a
// sibling's half-written file, and lose the trusted root; cosign v3.0.x then
// fails the evidence with "trusted root is required when using new bundle
// format", which read as a bad signature. Fetched once (cosign initialize),
// the root is the same for every verification, and a fetch that fails stops
// the run before it, as an operational error. Keyless signers need it (the
// certificate authority and the transparency log), and so do key signers
// whose evidence must be in the transparency log (its keys).
//
// It returns the file's path, or "" when no trusted root is needed: the
// policy trusts only keys that sign without a transparency log, a path was
// given (TrustedRoot), or the environment names individual Sigstore targets
// (SIGSTORE_ROOT_FILE and the like), which cosign uses instead. When cosign
// initialize succeeded but its trusted_root.json can't be found, it returns
// "" and a warning to show: each verification then fetches the root itself,
// as it did before, and evidence whose verification loses it is unknown.
func (v *Verifier) PrepareTrustedRoot(ctx context.Context) (root, warning string, err error) {
	if v.TrustedRoot != "" {
		return v.TrustedRoot, "", nil
	}
	needed := false
	for _, s := range v.Signers {
		if !ignoresTlog(s) {
			needed = true
		}
	}
	if !needed {
		return "", "", nil
	}
	for _, name := range sigstoreTargetVars {
		if os.Getenv(name) != "" {
			return "", "", nil
		}
	}
	args := []string{"initialize"}
	mirror := os.Getenv("TUF_MIRROR")
	if mirror != "" {
		args = append(args, "--mirror", mirror)
	}
	if _, err := v.run(ctx, args...); err != nil {
		return "", "", fmt.Errorf("cosign couldn't fetch Sigstore's trusted root (cosign initialize): %w. Keyless evidence (and evidence a key signed into the transparency log) can't be verified without it: check access to the TUF repository (%s), or pass --trusted-root FILE", err, firstNonEmpty(mirror, defaultTUFMirror))
	}
	cache := tufCache()
	v.TrustedRoot = cachedTrustedRoot(cache, firstNonEmpty(mirror, initializedMirror(cache), defaultTUFMirror))
	if v.TrustedRoot == "" {
		warning = fmt.Sprintf("cosign initialize fetched Sigstore's trusted root, but its trusted_root.json isn't in the TUF cache (%s) where this version of clearcutt-verify looks for it, so each verification fetches the root from the TUF repository itself, concurrently: evidence whose verification loses it is unknown, not verified. Pass --trusted-root FILE (a trusted_root.json) to verify against one root.", firstNonEmpty(cache, "$TUF_ROOT or ~/.sigstore/root"))
	}
	return v.TrustedRoot, warning, nil
}

// defaultTUFMirror is the TUF repository cosign initialize uses unless told
// otherwise.
const defaultTUFMirror = "https://tuf-repo-cdn.sigstore.dev"

// tufCache is cosign's TUF cache: $TUF_ROOT, or ~/.sigstore/root.
func tufCache() string {
	if cache := os.Getenv("TUF_ROOT"); cache != "" {
		return cache
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".sigstore", "root")
}

// initializedMirror is the mirror cosign initialize recorded in the cache
// (remote.json), or "".
func initializedMirror(cache string) string {
	raw, err := os.ReadFile(filepath.Join(cache, "remote.json"))
	if err != nil {
		return ""
	}
	var remote struct {
		Mirror string `json:"mirror"`
	}
	if json.Unmarshal(raw, &remote) != nil {
		return ""
	}
	return remote.Mirror
}

// cachedTrustedRoot is the trusted_root.json cosign initialize cached from
// mirror: <cache>/<mirror as a path>/targets/trusted_root.json, the mirror's
// scheme dropped and its slashes and colons made dashes, as sigstore-go
// names it. When it isn't there (another layout), it is the newest
// trusted_root.json in the cache: cosign initialize clears the cache before
// fetching, so that is the one it just wrote. "" when there is none.
func cachedTrustedRoot(cache, mirror string) string {
	if cache == "" {
		return ""
	}
	if file := filepath.Join(cache, tufMirrorPath(mirror), "targets", "trusted_root.json"); regularFile(file) {
		return file
	}
	var newest string
	var newestTime int64
	_ = filepath.WalkDir(cache, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "trusted_root.json" {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		// Newest first; the same time, the first path in lexical order.
		if t := info.ModTime().UnixNano(); newest == "" || t > newestTime {
			newest, newestTime = path, t
		}
		return nil
	})
	return newest
}

// tufMirrorPath is the directory sigstore-go caches mirror's metadata in
// (tuf.URLToPath).
func tufMirrorPath(mirror string) string {
	p, _ := strings.CutPrefix(mirror, "https://")
	p, _ = strings.CutPrefix(p, "http://")
	return strings.ToLower(strings.NewReplacer("/", "-", ":", "-").Replace(p))
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// cosignStderr is what cosign's standard error says went wrong: its last
// line and, before it, any line about the trusted root or TUF (cosign
// v3.0.x only warns what TUF said, then fails for the lack of a root).
func cosignStderr(stderr string) string {
	var out []string
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for _, l := range lines[:len(lines)-1] {
		if lower := strings.ToLower(l); strings.Contains(lower, "trusted_root") || strings.Contains(lower, "tuf") || strings.Contains(lower, "trusted root") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return strings.Join(append(out, strings.TrimSpace(lines[len(lines)-1])), "; ")
}

// CheckCosign checks, before anything is verified, that cosign runs here and
// is the major version whose formats the verifier reads (CosignMajor), and
// returns its version. Without it every piece of evidence would come out as
// failed or unknown for a reason that has nothing to do with the estate.
func (v *Verifier) CheckCosign(ctx context.Context) (string, error) {
	bin := v.Cosign
	if bin == "" {
		bin = "cosign"
	}
	if v.Run == nil {
		if _, err := exec.LookPath(bin); err != nil {
			return "", fmt.Errorf("cosign is not available (%s): clearcutt-verify verifies evidence with cosign v%d; install it (https://docs.sigstore.dev/cosign/system_config/installation/), or name it with --cosign-path: %w", bin, CosignMajor, err)
		}
	}
	out, err := v.run(ctx, "version", "--json")
	if err != nil {
		return "", fmt.Errorf("cosign (%s) didn't run: %w", bin, err)
	}
	var info struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.Unmarshal(out, &info); err != nil || info.GitVersion == "" {
		return "", fmt.Errorf("couldn't tell which cosign %s is (cosign version --json printed %q); clearcutt-verify needs cosign v%d", bin, strings.TrimSpace(string(out)), CosignMajor)
	}
	major, err := strconv.Atoi(strings.SplitN(strings.TrimPrefix(info.GitVersion, "v"), ".", 2)[0])
	switch {
	case err != nil:
		return "", fmt.Errorf("couldn't tell which cosign %s is (version %q); clearcutt-verify needs cosign v%d", bin, info.GitVersion, CosignMajor)
	case major < CosignMajor:
		return "", fmt.Errorf("cosign %s (%s) is too old: clearcutt-verify needs cosign v%d, which reads the Sigstore bundles cosign v3 attaches by default (cosign v2 reports them as unsigned)", info.GitVersion, bin, CosignMajor)
	case major > CosignMajor:
		return "", fmt.Errorf("cosign %s (%s) is newer than this clearcutt-verify reads: it reads cosign v%d's bundles and output; use cosign v%d, or a clearcutt-verify release that supports cosign v%d", info.GitVersion, bin, CosignMajor, CosignMajor, major)
	}
	return info.GitVersion, nil
}

// VerifySignature verifies the signature over repo@digest (an artifact, not
// an image in the estate) against v's signers, as estate verify checks an
// image's: every attached copy whose certificate names an acceptable signer
// is verified exactly, and only content cosign verified counts. The item's
// status is verified only for a signature cosign verified; anything else
// (missing, failed, present, unknown) says why in its detail.
func VerifySignature(ctx context.Context, v *Verifier, d *Discoverer, repo, digest string) report.EvidenceItem {
	found, err := d.Discover(ctx, repo, digest)
	if err != nil {
		return report.EvidenceItem{Status: "unknown", Detail: "The registry couldn't be read: " + err.Error()}
	}
	item, _ := verifyEvidence(ctx, v, repo, digest, KindSignature, "", found)
	if item.Status == "missing" {
		item.Detail = "It carries no signature."
	}
	return item
}
