package commands

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// withGrype stands in for grype: it says it is version (0.120.1 when empty)
// and answers every scan with run.
func withGrype(t *testing.T, version string, run func(dir string, args []string) ([]byte, []byte, error)) {
	t.Helper()
	if version == "" {
		version = "0.120.1"
	}
	old := grypeRunner
	grypeRunner = func(_ context.Context, dir, _ string, args ...string) ([]byte, []byte, error) {
		if len(args) > 0 && args[0] == "version" {
			return []byte(`{"application":"grype","version":"` + version + `"}`), nil, nil
		}
		return run(dir, args)
	}
	t.Cleanup(func() { grypeRunner = old })
}

// attestWithKey attaches a cosign v2 .att tag holding a key-signed
// attestation (no certificate) to repo@digest, and returns the statement
// cosign would print when it verifies it.
func attestWithKey(t *testing.T, repo, digest, predicateType string, predicate any) []byte {
	t.Helper()
	statement, _ := json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": predicateType, "predicate": predicate,
		"subject": []any{map[string]any{"name": repo, "digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}},
	})
	env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(statement), "signatures": []any{map[string]string{"sig": "c2ln"}}})
	img, err := mutate.Append(mutate.MediaType(empty.Image, types.OCIManifestSchema1), mutate.Addendum{
		Layer: static.NewLayer(env, "application/vnd.dsse.envelope.v1+json"), Annotations: map[string]string{"predicateType": predicateType}})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := name.ParseReference(repo + ":" + strings.Replace(digest, ":", "-", 1) + ".att")
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	return statement
}

// keyCosignAttest verifies, as cosign does with the trusted key, the
// attestations statements lists (by predicate type), and signatures.
func keyCosignAttest(statements map[string][]byte) func(args []string) ([]byte, error) {
	return func(args []string) ([]byte, error) {
		ref := args[len(args)-1]
		_, digest, _ := strings.Cut(ref, "@")
		flag := func(n string) string {
			for i := 0; i+1 < len(args); i++ {
				if args[i] == n {
					return args[i+1]
				}
			}
			return ""
		}
		if !strings.HasSuffix(flag("--key"), "trusted.pub") {
			return nil, errors.New("error during command execution: no matching signatures")
		}
		if args[0] == "verify" {
			return []byte(`[{"critical":{"image":{"docker-manifest-digest":"` + digest + `"},"type":"cosign container image signature"}}]`), nil
		}
		st, ok := statements[flag("--type")]
		if !ok {
			return nil, errors.New("error during command execution: no matching attestations")
		}
		env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": st, "signatures": []any{}})
		return append(env, '\n'), nil
	}
}

// TestEstateVerifyRescan runs --rescan end to end with a fake grype: the
// verified SBOM is scanned, the fresh scan sits beside the attested one, a
// grype that can't scan leaves the rescan unknown and, when nothing could be
// scanned, the run exits with an operational error after writing the report.
func TestEstateVerifyRescan(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := name.ParseReference(host + "/acme/app:1")
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	d, _ := img.Digest()
	digest := d.String()
	signWithKey(t, host+"/acme/app", digest)
	sbom := attestWithKey(t, host+"/acme/app", digest, "https://cyclonedx.org/bom", map[string]any{"bomFormat": "CycloneDX",
		"components": []any{map[string]string{"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}}})
	withCosign(t, "", keyCosignAttest(map[string][]byte{"https://cyclonedx.org/bom": sbom}))

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "trusted.pub"), []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(host+"/acme/app:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [signature, sbom]\ntrustedSigners:\n  - key: trusted.pub\nfailOn: high\nscanSource: rescan\nvex: [lodash.openvex.json]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lodash.openvex.json"), []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://acme.example/vex/lodash","author":"acme","timestamp":"2026-10-01T00:00:00Z","version":1,
	 "statements":[{"vulnerability":{"name":"GHSA-29mw-wpgm-hmr9"},"products":[{"@id":"pkg:npm/lodash@4.17.15"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile(filepath.Join("..", "estateverify", "testdata", "grype-sbom-scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "estate")
	args := []string{"estate", "verify", "--refs", refs, "--policy", policy, "--name", "acme", "--out", out, "--rescan", "--generated-at", "2026-10-18T12:00:00Z"}

	// Without grype, the run stops before reading anything.
	withGrype(t, "", nil)
	grypeRunner = func(_ context.Context, _, bin string, _ ...string) ([]byte, []byte, error) {
		return nil, nil, errors.New("exec: \"" + bin + "\": executable file not found in $PATH")
	}
	if _, err := runCLI(t, args...); err == nil || errors.Is(err, ErrCheckFailed) || !strings.Contains(err.Error(), "grype") {
		t.Fatalf("missing grype: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, report.ReportFile)); err == nil {
		t.Fatal("a report was written without grype")
	}
	// scanSource rescan without --rescan has nothing to gate on.
	if _, err := runCLI(t, args[:len(args)-3]...); err == nil || !strings.Contains(err.Error(), "needs --rescan") {
		t.Fatalf("scanSource without --rescan: %v", err)
	}

	// grype scans the verified SBOM, with the policy's VEX beside it.
	var seen [][]string
	withGrype(t, "", func(dir string, a []string) ([]byte, []byte, error) {
		seen = append(seen, a)
		if _, err := os.Stat(filepath.Join(dir, "sbom.json")); err != nil {
			return nil, nil, err
		}
		if _, err := os.Stat(filepath.Join(dir, "vex.json")); err != nil {
			return nil, nil, err
		}
		return recorded, nil, nil
	})
	stdout, err := runCLI(t, append(args, "--fail-on", "failed")...)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("want the gate to fail on the fresh High, got %v\n%s", err, stdout)
	}
	if len(seen) != 1 || seen[0][0] != "sbom:sbom.json" || !strings.Contains(strings.Join(seen[0], " "), "--vex vex.json") {
		t.Errorf("grype args: %v", seen)
	}
	if !strings.Contains(stdout, "rescan (grype 0.121.0): 1 images scanned") {
		t.Errorf("summary:\n%s", stdout)
	}
	var r report.Report
	readJSON(t, filepath.Join(out, report.ReportFile), &r)
	a := r.Images[0]
	if a.Rescan == nil || a.Rescan.Status != "scanned" || a.Rescan.Vulnerabilities.Counts.High != 1 || a.Vulnerabilities != nil || !r.Policy.Rescan || r.Policy.ScanSource != "rescan" {
		t.Errorf("rescan %+v, attested %v, policy %+v", a.Rescan, a.Vulnerabilities, r.Policy)
	}
	if len(r.Policy.VEX) != 1 || r.Policy.VEX[0].ID != "https://acme.example/vex/lodash" || r.Summary.Rescan == nil || r.Summary.Rescan.Scanned != 1 {
		t.Errorf("policy vex %+v, summary %+v", r.Policy.VEX, r.Summary.Rescan)
	}
	var h report.History
	readJSON(t, filepath.Join(out, report.HistoryFile), &h)
	if row := h.Entries[0].Images[0]; row.RescanVulnerabilities == nil || row.RescanVulnerabilities.High != 1 || row.Vulnerabilities != nil {
		t.Errorf("history row: %+v", row)
	}

	// grype failing every scan: the rescans are unknown, the report says so,
	// and the run is an operational failure, not a pass.
	withGrype(t, "", func(string, []string) ([]byte, []byte, error) {
		return nil, []byte("1 error occurred:\n\t* failed to load vulnerability db: unable to update vulnerability database"), errors.New("exit status 1")
	})
	stdout, err = runCLI(t, append(args, "--fail-on", "never")...)
	if err == nil || errors.Is(err, ErrCheckFailed) || !strings.Contains(err.Error(), "grype couldn't scan any image") {
		t.Fatalf("grype failing: %v\n%s", err, stdout)
	}
	readJSON(t, filepath.Join(out, report.ReportFile), &r)
	if rs := r.Images[0].Rescan; rs == nil || rs.Status != "unknown" || !strings.Contains(rs.Detail, "unable to update vulnerability database") || r.Images[0].Verdict.Status != "unverified" {
		t.Errorf("rescan after grype failed: %+v, verdict %+v", r.Images[0].Rescan, r.Images[0].Verdict)
	}
}

// Observe-only images are reported with their verdict and don't gate.
func TestEstateVerifyObserveOnly(t *testing.T) {
	withCosign(t, "", nil)
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	for _, ref := range []string{"acme/app:1", "upstream/base:latest"} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := name.ParseReference(host + "/" + ref)
		if err := remote.Write(r, img); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(host+"/acme/app:1\n"+host+"/upstream/base:latest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "estate")
	args := []string{"estate", "verify", "--refs", refs, "--name", "acme", "--out", out, "--require", "signature",
		"--trusted-identity-regexp", `^https://github\.com/acme/`, "--trusted-issuer", "https://token.actions.githubusercontent.com", "--fail-on", "failed", "--generated-at", "2026-10-18T00:00:00Z"}
	// Both unsigned: both fail, and the gate fails.
	if _, err := runCLI(t, args...); !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("want ErrCheckFailed, got %v", err)
	}
	// Observing the upstream base and the app: nothing gates.
	stdout, err := runCLI(t, append(args, "--observe", host+"/upstream/*,"+host+"/acme/app:1")...)
	if err != nil {
		t.Fatalf("observe-only images gated: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "2 images: 0 verified, 0 failed, 0 unverified, 2 observe-only (not gating)") || !strings.Contains(stdout, "failed (observe-only)") {
		t.Errorf("summary:\n%s", stdout)
	}
	var r report.Report
	readJSON(t, filepath.Join(out, report.ReportFile), &r)
	for _, img := range r.Images {
		if !img.ObserveOnly || img.Verdict.Status != "failed" {
			t.Errorf("%s: observeOnly %v verdict %+v", img.ID, img.ObserveOnly, img.Verdict)
		}
	}
	if r.Summary.Verdicts.ObserveOnly != 2 || r.Summary.Verdicts.Failed != 0 || strings.Join(r.Policy.Observe, ",") != host+"/upstream/*,"+host+"/acme/app:1" {
		t.Errorf("summary %+v policy %+v", r.Summary.Verdicts, r.Policy.Observe)
	}
	// Only the base observed: the app still fails the gate.
	if _, err := runCLI(t, append(args, "--observe", host+"/upstream/*")...); !errors.Is(err, ErrCheckFailed) {
		t.Errorf("the gating image didn't gate: %v", err)
	}
	// --policy and --observe are exclusive.
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [signature]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "estate", "verify", "--refs", refs, "--out", out, "--policy", policy, "--observe", "x"); err == nil || !strings.Contains(err.Error(), "exclusive") {
		t.Errorf("--policy with --observe: %v", err)
	}
}

// A run that could check nothing (no image readable) writes its all-unknown
// report and exits with the operational code, not 0.
func TestEstateVerifyNothingCheckedIsNotAPass(t *testing.T) {
	withCosign(t, "", nil)
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	host := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // the registry is down for the whole run
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(host+"/acme/app:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "estate")
	stdout, err := runCLI(t, "estate", "verify", "--refs", refs, "--name", "acme", "--out", out, "--fail-on", "never",
		"--trusted-identity-regexp", `^https://github\.com/acme/`, "--trusted-issuer", "https://token.actions.githubusercontent.com")
	if err == nil || errors.Is(err, ErrCheckFailed) || !strings.Contains(err.Error(), "nothing about the estate could be checked") {
		t.Fatalf("want an operational error, got %v\n%s", err, stdout)
	}
	var r report.Report
	readJSON(t, filepath.Join(out, report.ReportFile), &r)
	if len(r.Images) != 1 || r.Images[0].Evidence.Signature.Status != "unknown" || r.Images[0].Verdict.Status != "unverified" {
		t.Errorf("the report was written and says unknown: %+v", r.Images)
	}
}
