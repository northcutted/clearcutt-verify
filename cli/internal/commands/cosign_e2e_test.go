package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// TestRealCosign signs and attests images with the real cosign, in a real
// registry, and checks what estate verify and estate pull make of them, so a
// change in cosign's bundle format or output can't pass unnoticed: every
// other test fakes cosign. It runs when CLEARCUTT_E2E_REGISTRY names a
// registry to write to (CI starts one: registry:2, which has no Referrers API,
// and registry:3, which has one), with cosign v3 on PATH:
//
//	CLEARCUTT_E2E_REGISTRY=localhost:5000 go test ./internal/commands -run TestRealCosign -v
//
// It signs with key pairs and no transparency log, so it needs no network
// beyond the registry, and no OIDC identity (fork pull requests run it too).
func TestRealCosign(t *testing.T) {
	reg := os.Getenv("CLEARCUTT_E2E_REGISTRY")
	if reg == "" {
		t.Skip("CLEARCUTT_E2E_REGISTRY is not set")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Fatalf("CLEARCUTT_E2E_REGISTRY is set, but cosign isn't on PATH: %v", err)
	}
	dir := t.TempDir()
	cosign := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("cosign", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=", "COSIGN_YES=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cosign %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	t.Logf("cosign %s", strings.TrimSpace(cosign("version", "--json")))
	cosign("generate-key-pair", "--output-key-prefix", "trusted")
	cosign("generate-key-pair", "--output-key-prefix", "other")
	// A signing config naming no services: no Fulcio, no Rekor, no TSA.
	cosign("signing-config", "create", "--out", "no-tlog.json")
	sign := func(key, ref string) {
		t.Helper()
		cosign("sign", "--yes", "--key", key+".key", "--signing-config", "no-tlog.json", ref)
	}
	attest := func(key, typ, predicate, ref string) {
		t.Helper()
		cosign("attest", "--yes", "--key", key+".key", "--signing-config", "no-tlog.json", "--type", typ, "--predicate", predicate, ref)
	}
	write := func(file string, v any) {
		t.Helper()
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, file), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("sbom.json", map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []any{
		map[string]string{"type": "library", "name": "openssl", "version": "3.0.1", "purl": "pkg:apk/wolfi/openssl@3.0.1"}}})
	write("grype.json", map[string]any{
		"invocation": map[string]any{"parameters": nil, "uri": "", "event_id": "", "builder.id": ""},
		"scanner": map[string]any{"uri": "pkg:github/anchore/grype@0.100.0", "version": "0.100.0", "result": map[string]any{
			"matches": []any{map[string]any{
				"vulnerability": map[string]any{"id": "CVE-2026-0001", "severity": "High", "fix": map[string]any{"versions": []string{"3.0.2"}, "state": "fixed"}},
				"artifact":      map[string]string{"name": "openssl", "version": "3.0.1"}}},
			"descriptor": map[string]string{"name": "grype", "version": "0.100.0"}}},
		"metadata": map[string]string{"scanStartedOn": "2026-10-18T00:00:00Z", "scanFinishedOn": "2026-10-18T00:01:00Z"},
	})
	write("trivy.json", map[string]any{
		"invocation": map[string]any{"parameters": nil, "uri": "", "event_id": "", "builder.id": ""},
		"scanner": map[string]any{"uri": "pkg:github/aquasecurity/trivy@0.67.2", "version": "0.67.2", "result": map[string]any{
			"SchemaVersion": 2, "Results": []any{map[string]any{"Target": "app", "Vulnerabilities": []any{
				map[string]string{"VulnerabilityID": "CVE-2026-0002", "PkgName": "openssl", "InstalledVersion": "3.0.1", "Severity": "CRITICAL"}}}}}},
		"metadata": map[string]string{"scanStartedOn": "2026-10-18T00:00:00Z", "scanFinishedOn": "2026-10-18T00:01:00Z"},
	})
	write("provenance.json", map[string]any{"buildDefinition": map[string]any{
		"buildType":            "https://example.com/clearcutt-e2e",
		"externalParameters":   map[string]any{"workflow": map[string]string{"repository": "https://github.com/acme/app", "ref": "refs/heads/main"}},
		"resolvedDependencies": []any{map[string]any{"uri": "git+https://github.com/acme/app@refs/heads/main", "digest": map[string]string{"gitCommit": "0123456789abcdef0123456789abcdef01234567"}}},
	}, "runDetails": map[string]any{"builder": map[string]string{"id": "https://example.com/builder"}}})

	// Each image is a two-platform index, attested the way clearcutt-factory
	// attests: signature and provenance on the index, SBOM and scan on each
	// platform image.
	run := fmt.Sprint(time.Now().UnixNano())
	push := func(repo string) (index string, platforms []string) {
		t.Helper()
		var adds []mutate.IndexAddendum
		for _, arch := range []string{"amd64", "arm64"} {
			img, err := random.Image(512, 2)
			if err != nil {
				t.Fatal(err)
			}
			cf, _ := img.ConfigFile()
			cf = cf.DeepCopy()
			cf.OS, cf.Architecture = "linux", arch
			if img, err = mutate.ConfigFile(img, cf); err != nil {
				t.Fatal(err)
			}
			adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
		}
		idx := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, adds...), types.OCIImageIndex)
		ref, err := name.ParseReference(reg + "/clearcutt-e2e/" + repo + ":" + run)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.WriteIndex(ref, idx); err != nil {
			t.Fatal(err)
		}
		d, _ := idx.Digest()
		im, _ := idx.IndexManifest()
		for _, m := range im.Manifests {
			platforms = append(platforms, ref.Context().Name()+"@"+m.Digest.String())
		}
		return ref.Context().Name() + "@" + d.String(), platforms
	}
	evidence := func(repo, key, scan string) {
		t.Helper()
		index, platforms := push(repo)
		sign(key, index)
		attest(key, "slsaprovenance1", "provenance.json", index)
		for _, p := range platforms {
			attest(key, "cyclonedx", "sbom.json", p)
			attest(key, "vuln", scan, p)
		}
	}
	evidence("app", "trusted", "grype.json") // all evidence, signed by the trusted key
	evidence("evil", "other", "grype.json")  // the same evidence, signed by another key
	evidence("trivy", "trusted", "trivy.json")
	push("unsigned")

	refs := filepath.Join(dir, "refs.txt")
	var lines []string
	for _, repo := range []string{"app", "evil", "trivy", "unsigned"} {
		lines = append(lines, reg+"/clearcutt-e2e/"+repo+":"+run)
	}
	if err := os.WriteFile(refs, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte(`apiVersion: clearcutt.dev/v1
kind: VerificationPolicy
required: [signature, sbom, vulnerabilityScan, provenance]
trustedSigners:
  - key: trusted.pub
    tlog: false
failOn: critical
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "estate")
	stdout, err := runCLI(t, "estate", "verify", "--refs", refs, "--policy", policy, "--name", "e2e", "--out", out,
		"--platforms", "linux/amd64,linux/arm64", "--fail-on", "failed", "--verbose")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("estate verify: want the gate to fail (evil and unsigned), got %v\n%s", err, stdout)
	}
	t.Log(stdout)
	raw, err := os.ReadFile(filepath.Join(out, report.ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	validateAgainstContract(t, raw)
	var r report.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Metadata.Platforms, ",") != "linux/amd64,linux/arm64" {
		t.Errorf("platforms recorded: %v", r.Metadata.Platforms)
	}
	img := map[string]report.Image{}
	for _, i := range r.Images {
		img[strings.TrimPrefix(i.Repository, reg+"/clearcutt-e2e/")] = i
	}

	a := img["app"]
	for kind, item := range map[string]report.EvidenceItem{"signature": a.Evidence.Signature, "sbom": a.Evidence.SBOM, "vulnerabilityScan": a.Evidence.VulnerabilityScan, "provenance": a.Evidence.Provenance} {
		if item.Status != "verified" || item.Signer == nil || !strings.HasSuffix(item.Signer.Key, "trusted.pub") || item.Signer.Tlog == nil || *item.Signer.Tlog {
			t.Errorf("app %s, signed by the trusted key: %+v (signer %+v)", kind, item, item.Signer)
		}
	}
	if p := a.Evidence.SBOM.Platforms; p["linux/amd64"] != "verified" || p["linux/arm64"] != "verified" {
		t.Errorf("app SBOM per platform: %v", p)
	}
	if v := a.Vulnerabilities; v == nil || v.Counts.High != 1 || !strings.HasPrefix(v.Scanner, "grype") || v.ScannedAt != "2026-10-18T00:01:00Z" {
		t.Errorf("app vulnerabilities: %+v", a.Vulnerabilities)
	}
	if a.Packages == nil || *a.Packages != 1 || a.Source == nil || a.Source.Basis != "provenance" || a.Source.Revision != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("app packages %v, source %+v", a.Packages, a.Source)
	}
	if a.Verdict.Status != "verified" {
		t.Errorf("app verdict: %+v", a.Verdict)
	}

	// Signed by a key nobody trusts: not verified, and not read.
	e := img["evil"]
	if e.Evidence.Signature.Status != "failed" || e.Evidence.SBOM.Status != "failed" || e.Vulnerabilities != nil || e.Packages != nil || e.Verdict.Status != "failed" {
		t.Errorf("evil: signature %+v, sbom %+v, vulnerabilities %+v, verdict %+v", e.Evidence.Signature, e.Evidence.SBOM, e.Vulnerabilities, e.Verdict)
	}
	// A verified Trivy scan isn't read as a clean grype scan.
	tv := img["trivy"]
	if tv.Evidence.VulnerabilityScan.Status != "verified" || tv.Vulnerabilities != nil || tv.Verdict.Status != "unverified" {
		t.Errorf("trivy: scan %+v, vulnerabilities %+v, verdict %+v", tv.Evidence.VulnerabilityScan, tv.Vulnerabilities, tv.Verdict)
	}
	if u := img["unsigned"]; u.Evidence.Signature.Status != "missing" || u.Verdict.Status != "failed" {
		t.Errorf("unsigned: %+v %+v", u.Evidence.Signature, u.Verdict)
	}

	// The bundle, kept in the registry and signed, reads back only for the
	// key that signed it.
	estateRef := reg + "/clearcutt-e2e/estate:" + run
	stdout, err = runCLI(t, "estate", "push", estateRef, "--dir", out, "--file", report.ReportFile, "--file", report.HistoryFile)
	if err != nil {
		t.Fatalf("estate push: %v\n%s", err, stdout)
	}
	digest := ""
	for _, line := range strings.Split(stdout, "\n") {
		if d, ok := strings.CutPrefix(line, "[estate] digest "); ok {
			digest = strings.TrimSpace(d)
		}
	}
	repo, _, _ := strings.Cut(estateRef, ":"+run)
	sign("trusted", repo+"@"+digest)
	pulled := filepath.Join(dir, "pulled")
	stdout, err = runCLI(t, "estate", "pull", estateRef, "--output", pulled, "--key", filepath.Join(dir, "trusted.pub"), "--insecure-ignore-tlog")
	if err != nil || !strings.Contains(stdout, "signature verified") {
		t.Fatalf("estate pull, the signing key: %v\n%s", err, stdout)
	}
	if got, _ := os.ReadFile(filepath.Join(pulled, report.ReportFile)); !bytes.Equal(got, raw) {
		t.Error("the pulled report isn't the pushed one")
	}
	refused := filepath.Join(dir, "refused")
	stdout, err = runCLI(t, "estate", "pull", estateRef, "--output", refused, "--key", filepath.Join(dir, "other.pub"), "--insecure-ignore-tlog")
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("estate pull, another key: %v\n%s", err, stdout)
	}
	if _, err := os.Stat(filepath.Join(refused, report.ReportFile)); err == nil {
		t.Error("estate pull wrote a bundle another key was named for")
	}
}

// validateAgainstContract checks a report against the published schema.
func validateAgainstContract(t *testing.T, raw []byte) {
	t.Helper()
	schema, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "..", "contract", "estate-report.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(inst); err != nil {
		t.Errorf("report doesn't match the contract: %v", err)
	}
}
