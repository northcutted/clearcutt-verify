package commands

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/northcutted/clearcutt-verify/internal/certify"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestVerifyRebuildMatchesDigestAndEquivalentClosures(t *testing.T) {
	root := t.TempDir()
	runtimeClosure := filepath.Join(root, "runtime.txt")
	graftedClosure := filepath.Join(root, "grafted.txt")
	if err := os.WriteFile(runtimeClosure, []byte("/nix/store/b-runtime\n/nix/store/a-runtime\n/nix/store/a-runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graftedClosure, []byte("# normalized\n/nix/store/a-runtime\n/nix/store/b-runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name != "crane" || strings.Join(c.Args, " ") != "digest ghcr.io/acme/base:v1" {
			t.Fatalf("unexpected external command: %#v", c)
		}
		return "sha256:expected\n", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild",
		"--target", "java21-distroless",
		"--expected-ref", "ghcr.io/acme/base:v1",
		"--expected-digest", "sha256:expected",
		"--runtime-closure-file", runtimeClosure,
		"--grafted-closure-file", graftedClosure,
		"--require-digest-match",
		"--require-closure-equivalence",
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("verify rebuild failed: %v\n%s", err, stdout)
	}

	var predicate verifyRebuildPredicate
	if err := json.Unmarshal([]byte(stdout), &predicate); err != nil {
		t.Fatalf("predicate JSON did not parse: %v\n%s", err, stdout)
	}
	if predicate.Status != "pass" || predicate.Digest == nil || !predicate.Digest.Match || predicate.Closure == nil || !predicate.Closure.Equivalent {
		t.Fatalf("unexpected predicate: %#v", predicate)
	}
	if predicate.Closure.RuntimePaths != 2 || predicate.Closure.RuntimeHash != predicate.Closure.GraftedHash {
		t.Fatalf("closure normalization/hash mismatch: %#v", predicate.Closure)
	}
}

func TestVerifyRebuildFailsClosedOnMismatch(t *testing.T) {
	root := t.TempDir()
	runtimeClosure := filepath.Join(root, "runtime.txt")
	graftedClosure := filepath.Join(root, "grafted.txt")
	if err := os.WriteFile(runtimeClosure, []byte("/nix/store/a-runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graftedClosure, []byte("/nix/store/b-runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		return "sha256:actual\n", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild",
		"--target", "java21-distroless",
		"--expected-ref", "ghcr.io/acme/base:v1",
		"--expected-digest", "sha256:expected",
		"--runtime-closure-file", runtimeClosure,
		"--grafted-closure-file", graftedClosure,
		"--require-digest-match",
		"--require-closure-equivalence",
	)
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("expected ErrCheckFailed, got %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "digest mismatch") || !strings.Contains(stdout, "closure mismatch") {
		t.Fatalf("expected mismatch details, got:\n%s", stdout)
	}
}

func TestVerifyRebuildParsesProvenanceAndMatchesLayers(t *testing.T) {
	root := t.TempDir()
	provenance := filepath.Join(root, "provenance.json")
	if err := os.WriteFile(provenance, []byte(`{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [{"name": "ghcr.io/acme/clearcutt-java21:v1", "digest": {"sha256": "expected"}}],
  "predicate": {
    "materials": [{
      "uri": "git+https://github.com/northcutted/clearcutt@refs/heads/main",
      "digest": {"gitCommit": "abc123"}
    }]
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	layer := overlayLayer(t, map[string]string{"nix/store/a-runtime/bin/java": "runtime"})
	rebuilt := overlayDockerArchive(t, layer, "rebuilt:latest")
	registry := overlayDockerArchive(t, layer, "registry:latest")

	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		if c.Name != "crane" || strings.Join(c.Args, " ") != "digest ghcr.io/acme/clearcutt-java21:v1" {
			t.Fatalf("unexpected external command: %#v", c)
		}
		return "sha256:expected\n", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild", "ghcr.io/acme/clearcutt-java21:v1",
		"--target", "java21-distroless",
		"--provenance-file", provenance,
		"--rebuilt-archive", rebuilt,
		"--registry-archive", registry,
		"--require-digest-match",
		"--require-layer-match",
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("verify rebuild failed: %v\n%s", err, stdout)
	}
	var predicate verifyRebuildPredicate
	if err := json.Unmarshal([]byte(stdout), &predicate); err != nil {
		t.Fatalf("predicate JSON did not parse: %v\n%s", err, stdout)
	}
	if predicate.Provenance == nil || predicate.Provenance.SourceRepo != "https://github.com/northcutted/clearcutt" || predicate.Provenance.SourceCommit != "abc123" {
		t.Fatalf("unexpected provenance: %#v", predicate.Provenance)
	}
	if len(predicate.Subject) != 1 || predicate.Subject[0].Digest["sha256"] != "expected" {
		t.Fatalf("unexpected subject: %#v", predicate.Subject)
	}
	if predicate.Layers == nil || !predicate.Layers.Match || len(predicate.Layers.RebuiltLayerDigests) != 1 {
		t.Fatalf("unexpected layer result: %#v", predicate.Layers)
	}
}

func TestVerifyRebuildCheckoutAndNixBuildFromPinnedProvenance(t *testing.T) {
	root := t.TempDir()
	provenance := filepath.Join(root, "provenance.json")
	if err := os.WriteFile(provenance, []byte(`{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "materials": [{
      "uri": "git+https://github.com/northcutted/clearcutt@refs/tags/v1",
      "digest": {"gitCommit": "def456"}
    }]
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	checkout := filepath.Join(root, "checkout")
	outLink := filepath.Join(root, "rebuilt.tar")
	var calls []string
	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		calls = append(calls, c.Name+" "+strings.Join(c.Args, " ")+" @ "+c.Dir)
		return "", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild",
		"--target", "java21-distroless",
		"--provenance-file", provenance,
		"--rebuild",
		"--checkout-dir", checkout,
		"--out-link", outLink,
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("verify rebuild failed: %v\n%s", err, stdout)
	}
	flat := strings.Join(calls, "\n")
	for _, needle := range []string{
		"git clone https://github.com/northcutted/clearcutt " + checkout,
		"git fetch --depth 1 origin def456 @ " + checkout,
		"git checkout --detach def456 @ " + checkout,
		"nix --extra-experimental-features nix-command flakes build .#java21-distroless --out-link " + outLink + " @ " + filepath.Join(checkout, "core"),
	} {
		if !strings.Contains(flat, needle) {
			t.Fatalf("missing command %q in:\n%s", needle, flat)
		}
	}
}

func TestVerifyRebuildDownloadsProvenanceWhenDigestComesFromSubject(t *testing.T) {
	statement := `{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [{"name": "ghcr.io/acme/clearcutt-java21:v1", "digest": {"sha256": "expected"}}],
  "predicate": {
    "materials": [{
      "uri": "git+https://github.com/northcutted/clearcutt@refs/heads/main",
      "digest": {"gitCommit": "abc123"}
    }]
  }
}`
	envelope := `{"payload":"` + base64.StdEncoding.EncodeToString([]byte(statement)) + `"}`
	var calls []string
	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		calls = append(calls, c.Name+" "+strings.Join(c.Args, " "))
		switch c.Name {
		case "cosign":
			return envelope, nil
		case "crane":
			return "sha256:expected\n", nil
		default:
			t.Fatalf("unexpected external command: %#v", c)
			return "", nil
		}
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	stdout, err := runCLI(t,
		"verify", "rebuild", "ghcr.io/acme/clearcutt-java21:v1",
		"--target", "java21-distroless",
		"--require-digest-match",
		"--output-predicate",
	)
	if err != nil {
		t.Fatalf("verify rebuild failed: %v\n%s", err, stdout)
	}
	flat := strings.Join(calls, "\n")
	if !strings.Contains(flat, "cosign download attestation --predicate-type https://slsa.dev/provenance/v1 ghcr.io/acme/clearcutt-java21:v1") {
		t.Fatalf("expected cosign provenance download, got:\n%s", flat)
	}
	var predicate verifyRebuildPredicate
	if err := json.Unmarshal([]byte(stdout), &predicate); err != nil {
		t.Fatalf("predicate JSON did not parse: %v\n%s", err, stdout)
	}
	if predicate.Provenance == nil || predicate.Provenance.SourceCommit != "abc123" || predicate.Digest == nil || !predicate.Digest.Match {
		t.Fatalf("unexpected downloaded provenance predicate: %#v", predicate)
	}
}

func TestVerifyRebuildDigestNormalizationAndDiffoscopeBranches(t *testing.T) {
	if got := normalizeGitURI(" git+https://github.com/acme/repo.git@refs/heads/main "); got != "https://github.com/acme/repo" {
		t.Fatalf("unexpected https git URI normalization: %q", got)
	}
	if got := normalizeGitURI("git@github.com:acme/repo.git"); got != "https://github.com/acme/repo" {
		t.Fatalf("unexpected ssh git URI normalization: %q", got)
	}
	if got := normalizeGitURI("   "); got != "" {
		t.Fatalf("blank git URI should normalize to empty, got %q", got)
	}

	for name, tc := range map[string]struct {
		value any
		want  string
	}{
		"sha256":          {map[string]any{"sha256": "abc123"}, "sha256:abc123"},
		"prefixed-sha1":   {map[string]any{"sha1": "sha1:def456"}, "sha1:def456"},
		"git-commit":      {map[string]any{"gitCommit": "feedface"}, "gitCommit:feedface"},
		"sorted-fallback": {map[string]any{"z": "last", "a": "first"}, "a:first"},
		"non-map":         {"sha256:abc123", ""},
		"empty":           {map[string]any{"sha256": " "}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := rebuildDigest(tc.value); got != tc.want {
				t.Fatalf("rebuildDigest() = %q, want %q", got, tc.want)
			}
		})
	}
	if got := firstRebuildDigestValue(map[string]any{"sha256": "sha256:abc123"}, "sha256"); got != "abc123" {
		t.Fatalf("unexpected first digest value: %q", got)
	}

	root := t.TempDir()
	var calls []string
	oldCapture := captureExternalOutput
	captureExternalOutput = func(c externalCommand) (string, error) {
		calls = append(calls, c.Name+" "+strings.Join(c.Args, " "))
		if strings.Contains(strings.Join(c.Args, " "), "--html") {
			if err := os.WriteFile(filepath.Join(root, "report.html"), []byte("diff"), 0o644); err != nil {
				t.Fatal(err)
			}
			return "", errors.New("diffoscope exited non-zero after writing report")
		}
		return "", nil
	}
	t.Cleanup(func() { captureExternalOutput = oldCapture })

	if err := runDiffoscope("left.tar", "right.tar", filepath.Join(root, "report.html")); err != nil {
		t.Fatalf("html diffoscope report should tolerate non-zero exit after writing output: %v", err)
	}
	if err := runDiffoscope("left.tar", "right.tar", filepath.Join(root, "report.txt")); err != nil {
		t.Fatalf("text diffoscope report should succeed: %v", err)
	}
	flat := strings.Join(calls, "\n")
	for _, want := range []string{
		"diffoscope --html " + filepath.Join(root, "report.html") + " left.tar right.tar",
		"diffoscope --text " + filepath.Join(root, "report.txt") + " left.tar right.tar",
	} {
		if !strings.Contains(flat, want) {
			t.Fatalf("missing diffoscope call %q in:\n%s", want, flat)
		}
	}
}

// overlayLayer builds an uncompressed tar layer from a name->content map.
func overlayLayer(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := []byte(files[name])
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}); err != nil {
			t.Fatalf("write layer header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("write layer content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer: %v", err)
	}
	return buf.Bytes()
}

// overlayDockerArchive wraps a layer in a single-image docker-archive tarball.
func overlayDockerArchive(t *testing.T, layer []byte, tag string) string {
	t.Helper()
	manifest, err := json.Marshal([]certify.DockerManifest{{
		Config:   "config.json",
		RepoTags: []string{tag},
		Layers:   []string{"layer.tar"},
	}})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	config := []byte(`{"config":{"User":"10001:10001"}}`)
	path := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for _, item := range []struct {
		name string
		body []byte
	}{{"manifest.json", manifest}, {"config.json", config}, {"layer.tar", layer}} {
		if err := tw.WriteHeader(&tar.Header{Name: item.name, Mode: 0o600, Size: int64(len(item.body))}); err != nil {
			t.Fatalf("write archive header: %v", err)
		}
		if _, err := tw.Write(item.body); err != nil {
			t.Fatalf("write archive body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close archive writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return path
}
