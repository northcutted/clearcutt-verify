package estateverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
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
