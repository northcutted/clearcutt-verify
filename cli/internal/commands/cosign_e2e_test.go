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
// Evidence is stored both ways cosign v3 can: as Sigstore bundles (the
// default; referrers, or the referrers tag on registry:2) and, for the
// legacy image, as cosign v2's .sig and .att tags (--new-bundle-format=false).
//
// Two extras run when asked: CLEARCUTT_E2E_RESCAN=1 adds --rescan (grype on
// PATH; it downloads its database), and CLEARCUTT_E2E_KEYLESS=1 also signs
// an image keylessly with the ambient OIDC identity (a GitHub Actions job
// with id-token: write) against the public Sigstore, which exercises the
// trusted-root fetch (cosign initialize) and the real Fulcio, Rekor, and TUF.
// CLEARCUTT_E2E_BUNDLE_OUT names a directory to copy the bundle to, for the
// portal contract gate.
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
	// Bundles by default (a signing config naming no transparency log);
	// legacy stores cosign v2's .sig/.att tags instead, which cosign v3 writes
	// only without a signing config.
	formatFlags := func(legacy bool) []string {
		if legacy {
			return []string{"--use-signing-config=false", "--tlog-upload=false", "--new-bundle-format=false"}
		}
		return []string{"--signing-config", "no-tlog.json"}
	}
	sign := func(key, ref string, legacy bool) {
		t.Helper()
		cosign(append(append([]string{"sign", "--yes", "--key", key + ".key"}, formatFlags(legacy)...), ref)...)
	}
	attest := func(key, typ, predicate, ref string, legacy bool) {
		t.Helper()
		cosign(append(append([]string{"attest", "--yes", "--key", key + ".key", "--type", typ, "--predicate", predicate}, formatFlags(legacy)...), ref)...)
	}
	write := func(file string, v any) {
		t.Helper()
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(dir, file), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// lodash 4.17.15 has advisories grype matches by purl alone (an apk package
	// needs the distro in the SBOM), so a rescan finds something.
	write("sbom.json", map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []any{
		map[string]string{"type": "library", "name": "openssl", "version": "3.0.1", "purl": "pkg:apk/wolfi/openssl@3.0.1"},
		map[string]string{"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}}})
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
	evidence := func(repo, key, scan string, legacy bool) {
		t.Helper()
		index, platforms := push(repo)
		sign(key, index, legacy)
		attest(key, "slsaprovenance1", "provenance.json", index, legacy)
		for _, p := range platforms {
			attest(key, "cyclonedx", "sbom.json", p, legacy)
			attest(key, "vuln", scan, p, legacy)
		}
	}
	evidence("app", "trusted", "grype.json", false) // all evidence, signed by the trusted key
	evidence("evil", "other", "grype.json", false)  // the same evidence, signed by another key
	evidence("trivy", "trusted", "trivy.json", false)
	evidence("legacy", "trusted", "grype.json", true) // the same as app, as cosign v2 tags
	push("unsigned")
	repos := []string{"app", "evil", "trivy", "legacy", "unsigned"}

	keyless := os.Getenv("CLEARCUTT_E2E_KEYLESS") != ""
	if keyless {
		// The job's own identity signs, against the public Sigstore.
		index, platforms := push("keyless")
		cosign("sign", "--yes", index)
		cosign("attest", "--yes", "--type", "cyclonedx", "--predicate", "sbom.json", platforms[0])
		cosign("attest", "--yes", "--type", "cyclonedx", "--predicate", "sbom.json", platforms[1])
		repos = append(repos, "keyless")
	}
	rescan := os.Getenv("CLEARCUTT_E2E_RESCAN") != ""
	if rescan {
		if _, err := exec.LookPath("grype"); err != nil {
			t.Fatalf("CLEARCUTT_E2E_RESCAN is set, but grype isn't on PATH: %v", err)
		}
	}

	refs := filepath.Join(dir, "refs.txt")
	var lines []string
	for _, repo := range repos {
		lines = append(lines, reg+"/clearcutt-e2e/"+repo+":"+run)
	}
	if err := os.WriteFile(refs, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	policyText := `apiVersion: clearcutt.dev/v1
kind: VerificationPolicy
required: [signature, sbom, vulnerabilityScan, provenance]
trustedSigners:
  - key: trusted.pub
    tlog: false
`
	if keyless {
		// The workflow that runs this test, in this repository.
		policyText += `  - identityRegexp: ^https://github\.com/northcutted/clearcutt-verify/\.github/workflows/
    issuer: https://token.actions.githubusercontent.com
    sourceRepository: https://github.com/northcutted/clearcutt-verify
`
	}
	policyText += "failOn: critical\n"
	if err := os.WriteFile(policy, []byte(policyText), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "estate")
	verifyArgs := []string{"estate", "verify", "--refs", refs, "--policy", policy, "--name", "e2e", "--out", out,
		"--platforms", "linux/amd64,linux/arm64", "--fail-on", "failed", "--verbose"}
	if rescan {
		verifyArgs = append(verifyArgs, "--rescan")
	}
	stdout, err := runCLI(t, verifyArgs...)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("estate verify: want the gate to fail (evil and unsigned), got %v\n%s", err, stdout)
	}
	t.Log(stdout)
	if keyless && !strings.Contains(stdout, "cosign initialize fetched it once") {
		t.Errorf("keyless: the trusted root wasn't fetched once for the run:\n%s", stdout)
	}
	if bundleOut := os.Getenv("CLEARCUTT_E2E_BUNDLE_OUT"); bundleOut != "" {
		if err := os.MkdirAll(bundleOut, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{report.ReportFile, report.HistoryFile} {
			b, err := os.ReadFile(filepath.Join(out, f))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bundleOut, f), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
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
	if a.Packages == nil || *a.Packages != 2 || a.Source == nil || a.Source.Basis != "provenance" || a.Source.Revision != "0123456789abcdef0123456789abcdef01234567" {
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
	// The same evidence stored as cosign v2 tags verifies the same way, and
	// says where it is.
	l := img["legacy"]
	for kind, item := range map[string]report.EvidenceItem{"signature": l.Evidence.Signature, "sbom": l.Evidence.SBOM, "vulnerabilityScan": l.Evidence.VulnerabilityScan, "provenance": l.Evidence.Provenance} {
		want := ".att"
		if kind == "signature" {
			want = ".sig"
		}
		if item.Status != "verified" || !strings.HasSuffix(item.Ref, want) || item.Signer == nil || !strings.HasSuffix(item.Signer.Key, "trusted.pub") {
			t.Errorf("legacy %s: %+v", kind, item)
		}
	}
	if l.Verdict.Status != "verified" || l.Vulnerabilities == nil || l.Vulnerabilities.Counts.High != 1 || l.Packages == nil || *l.Packages != 2 {
		t.Errorf("legacy: verdict %+v vulnerabilities %+v packages %v", l.Verdict, l.Vulnerabilities, l.Packages)
	}
	if keyless {
		k := img["keyless"]
		for kind, item := range map[string]report.EvidenceItem{"signature": k.Evidence.Signature, "sbom": k.Evidence.SBOM} {
			if item.Status != "verified" || item.Signer == nil || item.Signer.Issuer != "https://token.actions.githubusercontent.com" || item.Signer.SourceRepository != "https://github.com/northcutted/clearcutt-verify" {
				t.Errorf("keyless %s: %+v (signer %+v)", kind, item, item.Signer)
			}
		}
		if k.Evidence.VulnerabilityScan.Status != "missing" || k.Evidence.Provenance.Status != "missing" || k.Verdict.Status != "failed" {
			t.Errorf("keyless (signature and SBOM only): %+v %+v", k.Evidence, k.Verdict)
		}
	}
	if rescan {
		// The verified SBOM (openssl 3.0.1) is rescanned; the one signed by
		// another key isn't, so evil's current vulnerabilities are unknown.
		if a.Rescan == nil || a.Rescan.Status != "scanned" || a.Rescan.Vulnerabilities == nil || len(a.Rescan.Vulnerabilities.Findings) == 0 ||
			a.Rescan.Vulnerabilities.Database == nil || a.Rescan.Vulnerabilities.Database.Built == "" || !strings.HasPrefix(a.Rescan.Vulnerabilities.Scanner, "grype ") {
			t.Errorf("app rescan: %+v", a.Rescan)
		}
		if l.Rescan == nil || l.Rescan.Status != "scanned" {
			t.Errorf("legacy rescan: %+v", l.Rescan)
		}
		if e.Rescan == nil || e.Rescan.Status != "unknown" || e.Rescan.Vulnerabilities != nil || !strings.Contains(e.Rescan.Detail, "no verified SBOM") {
			t.Errorf("evil rescan: %+v", e.Rescan)
		}
		if r.Summary.Rescan == nil || r.Summary.Rescan.Scanned < 2 || !r.Policy.Rescan {
			t.Errorf("rescan summary: %+v policy %+v", r.Summary.Rescan, r.Policy)
		}
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
	sign("trusted", repo+"@"+digest, false)
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

	// A trust policy's estate signers name the key too, for pull and for the
	// history index, which the pushing job signs like the bundle.
	trust := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trust, []byte("apiVersion: clearcutt.dev/v1\nkind: TrustPolicy\nsigners:\n  - name: estate-job\n    roles: [estate]\n    key: trusted.pub\n    tlog: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if stdout, err := runCLI(t, "estate", "pull", estateRef, "--output", filepath.Join(dir, "pulled-policy"), "--trust-policy", trust); err != nil || !strings.Contains(stdout, "signature verified") {
		t.Errorf("estate pull with the trust policy: %v\n%s", err, stdout)
	}
	historyRef := reg + "/clearcutt-e2e/estate:history-" + run
	stdout, err = runCLI(t, "estate", "push", estateRef, "--dir", out, "--file", report.ReportFile, "--history", historyRef, "--generated-at", "2026-10-26T00:00:00Z")
	if err != nil {
		t.Fatalf("estate push --history: %v\n%s", err, stdout)
	}
	historyDigest := ""
	for _, line := range strings.Split(stdout, "\n") {
		if _, rest, ok := strings.Cut(line, "appended to history "); ok {
			historyDigest = strings.TrimSuffix(strings.TrimSpace(rest[strings.LastIndex(rest, "(")+1:]), ")")
		}
	}
	if !strings.HasPrefix(historyDigest, "sha256:") {
		t.Fatalf("no history digest in:\n%s", stdout)
	}
	if _, err := runCLI(t, "estate", "history", historyRef, "--trust-policy", trust); err == nil || !strings.Contains(err.Error(), "refusing the history index") {
		t.Errorf("estate history, unsigned index: %v", err)
	}
	sign("trusted", repo+"@"+historyDigest, false)
	if stdout, err := runCLI(t, "estate", "history", historyRef, "--trust-policy", trust); err != nil || !strings.Contains(stdout, "history index signature verified") {
		t.Errorf("estate history, signed index: %v\n%s", err, stdout)
	}
	if _, err := runCLI(t, "estate", "history", historyRef, "--key", filepath.Join(dir, "other.pub"), "--insecure-ignore-tlog"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("estate history, another key: %v", err)
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
