package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/northcutted/clearcutt-verify/internal/estategraph"
)

// stampCreated fixes an image's creation time so base currency is decided by the
// timestamp under test rather than by whatever the clock did during the run.
func stampCreated(t *testing.T, img v1.Image, created time.Time) v1.Image {
	t.Helper()
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.Created = v1.Time{Time: created}
	cfg.OS = "linux"
	cfg.Architecture = "amd64"
	out, err := mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	return out
}

// TestRegistryScanToGraphEndToEnd drives the whole discovery path against a real
// (in-process) registry through the actual CLI commands: enumerate the registry,
// observe what it holds, and derive the base/consumer graph. It is the proof that
// the three commands compose, and that layer-digest matching finds a relationship
// nobody declared anywhere.
func TestRegistryScanToGraphEndToEnd(t *testing.T) {
	client, host := commandTestRegistry(t)

	baseV1 := stampCreated(t, commandTestImage(t, 901), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if _, err := client.PushImage(host+"/bases/java:v1.0.0", baseV1); err != nil {
		t.Fatalf("push base v1: %v", err)
	}
	baseV2 := stampCreated(t, commandTestImage(t, 902), time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	if _, err := client.PushImage(host+"/bases/java:v2.0.0", baseV2); err != nil {
		t.Fatalf("push base v2: %v", err)
	}

	// The app sits on base v1 and adds one layer. Nothing anywhere declares this
	// relationship: no base labels, no buildpacks metadata, no history entry. Only
	// the layer digests can find it.
	appLayer, err := random.Layer(128, "application/vnd.oci.image.layer.v1.tar+gzip")
	if err != nil {
		t.Fatalf("random layer: %v", err)
	}
	app, err := mutate.AppendLayers(baseV1, appLayer)
	if err != nil {
		t.Fatalf("append app layer: %v", err)
	}
	app = stampCreated(t, app, time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC))
	if _, err := client.PushImage(host+"/apps/payments:v9.0.0", app); err != nil {
		t.Fatalf("push app: %v", err)
	}

	dir := t.TempDir()
	images := filepath.Join(dir, "images.yaml")
	observations := filepath.Join(dir, "observations.json")
	graphPath := filepath.Join(dir, "graph.json")
	report := filepath.Join(dir, "inventory.md")

	stdout, err := runCLI(t, "registry", "scan",
		"--registry", host,
		"--repository", "bases/java",
		"--repository", "apps/payments",
		"--output", images,
		"--generated-at", "2026-06-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("registry scan: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "wrote 3 image(s)") {
		t.Fatalf("expected 3 discovered images, got:\n%s", stdout)
	}

	if stdout, err = runCLI(t, "import", "observe",
		"--images", images, "--output", observations,
		"--generated-at", "2026-06-01T00:00:00Z", "--strict",
	); err != nil {
		t.Fatalf("import observe: %v\n%s", err, stdout)
	}

	if stdout, err = runCLI(t, "graph", "build",
		"--observations", observations,
		"--output", graphPath,
		"--report", report,
		"--generated-at", "2026-06-01T00:00:00Z",
	); err != nil {
		t.Fatalf("graph build: %v\n%s", err, stdout)
	}

	raw, err := os.ReadFile(graphPath)
	if err != nil {
		t.Fatalf("read graph: %v", err)
	}
	var graph estategraph.Graph
	if err := json.Unmarshal(raw, &graph); err != nil {
		t.Fatalf("decode graph: %v", err)
	}

	if len(graph.Edges) != 1 {
		t.Fatalf("want exactly one discovered edge, got %+v", graph.Edges)
	}
	edge := graph.Edges[0]
	if edge.Method != estategraph.MethodLayerPrefix {
		t.Fatalf("Method = %q, want the relationship found by layer digests", edge.Method)
	}
	if edge.Confidence != "verified" {
		t.Fatalf("Confidence = %q, want verified", edge.Confidence)
	}
	if !strings.HasSuffix(edge.ConsumerRef, "/apps/payments:v9.0.0") {
		t.Fatalf("ConsumerRef = %q", edge.ConsumerRef)
	}
	if !strings.HasSuffix(edge.BaseRef, "/bases/java:v1.0.0") {
		t.Fatalf("BaseRef = %q, want the v1 base the app was actually built on", edge.BaseRef)
	}
	if edge.Drift != estategraph.DriftStale {
		t.Fatalf("Drift = %q, want stale (v2.0.0 is newer)", edge.Drift)
	}
	if edge.VersionsBehind != 1 {
		t.Fatalf("VersionsBehind = %d, want 1", edge.VersionsBehind)
	}
	if edge.DaysBehind != 59 {
		t.Fatalf("DaysBehind = %d, want 59 (2026-01-01 to 2026-03-01)", edge.DaysBehind)
	}
	if !strings.HasSuffix(edge.CurrentBaseRef, "/bases/java:v2.0.0") {
		t.Fatalf("CurrentBaseRef = %q, want v2.0.0", edge.CurrentBaseRef)
	}

	// Both base versions are roots, and neither is an orphan.
	if graph.Summary.UnresolvedConsumers != 0 {
		t.Fatalf("UnresolvedConsumers = %d, want 0; unresolved=%+v", graph.Summary.UnresolvedConsumers, graph.Unresolved)
	}
	if graph.Summary.RootImages != 2 {
		t.Fatalf("RootImages = %d, want 2 (both base versions)", graph.Summary.RootImages)
	}
	if graph.Summary.StaleConsumers != 1 {
		t.Fatalf("StaleConsumers = %d, want 1", graph.Summary.StaleConsumers)
	}

	markdown, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	for _, want := range []string{
		"# Base Image Governance Inventory",
		"Consumers on a stale base",
		"Only `layer-prefix` is proof",
		"What this report does not prove",
	} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("report is missing %q:\n%s", want, markdown)
		}
	}
}

// TestGraphBuildFailOnStaleGatesCI proves the command can act as a CI gate with the
// same exit-code contract as ClearCutt's other gates.
func TestGraphBuildFailOnStaleGatesCI(t *testing.T) {
	client, host := commandTestRegistry(t)

	baseV1 := stampCreated(t, commandTestImage(t, 911), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if _, err := client.PushImage(host+"/bases/go:v1.0.0", baseV1); err != nil {
		t.Fatalf("push base v1: %v", err)
	}
	baseV2 := stampCreated(t, commandTestImage(t, 912), time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if _, err := client.PushImage(host+"/bases/go:v2.0.0", baseV2); err != nil {
		t.Fatalf("push base v2: %v", err)
	}
	appLayer, err := random.Layer(64, "application/vnd.oci.image.layer.v1.tar+gzip")
	if err != nil {
		t.Fatalf("random layer: %v", err)
	}
	app, err := mutate.AppendLayers(baseV1, appLayer)
	if err != nil {
		t.Fatalf("append app layer: %v", err)
	}
	if _, err := client.PushImage(host+"/apps/svc:v1", stampCreated(t, app, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("push app: %v", err)
	}

	dir := t.TempDir()
	images := filepath.Join(dir, "images.yaml")
	observations := filepath.Join(dir, "observations.json")
	graphPath := filepath.Join(dir, "graph.json")

	if stdout, err := runCLI(t, "registry", "scan", "--registry", host,
		"--repository", "bases/go", "--repository", "apps/svc", "--output", images); err != nil {
		t.Fatalf("registry scan: %v\n%s", err, stdout)
	}
	if stdout, err := runCLI(t, "import", "observe", "--images", images, "--output", observations, "--strict"); err != nil {
		t.Fatalf("import observe: %v\n%s", err, stdout)
	}

	stdout, err := runCLI(t, "graph", "build", "--observations", observations,
		"--output", graphPath, "--fail-on-stale")
	if err == nil {
		t.Fatalf("expected the stale gate to fail, got success:\n%s", stdout)
	}
	if !strings.Contains(stdout, "FAIL") {
		t.Fatalf("expected a FAIL line explaining the gate, got:\n%s", stdout)
	}
	// The graph must still be written: a gate failure is a verdict, not a crash.
	if _, statErr := os.Stat(graphPath); statErr != nil {
		t.Fatalf("graph output should exist even when the gate fails: %v", statErr)
	}
}

// TestRegistryScanRefusesToClobberExistingOutput guards the flag contract shared by
// every ClearCutt generator command.
func TestRegistryScanRefusesToClobberExistingOutput(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "images.yaml")
	if err := os.WriteFile(existing, []byte("images: []\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	_, err := runCLI(t, "registry", "scan", "--registry", "reg.invalid", "--output", existing)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected a refusal naming --force, got %v", err)
	}
}

// TestRegistryScanRequiresPairedCredentialFlags keeps the token out of argv: the
// password only ever arrives through an environment variable.
func TestRegistryScanRequiresPairedCredentialFlags(t *testing.T) {
	dir := t.TempDir()
	_, err := runCLI(t, "registry", "scan", "--registry", "reg.invalid",
		"--username", "someone", "--output", filepath.Join(dir, "images.yaml"))
	if err == nil || !strings.Contains(err.Error(), "--password-env") {
		t.Fatalf("expected the paired-flag error, got %v", err)
	}

	t.Setenv("CC_TEST_EMPTY_TOKEN", "")
	_, err = runCLI(t, "registry", "scan", "--registry", "reg.invalid",
		"--username", "someone", "--password-env", "CC_TEST_EMPTY_TOKEN",
		"--output", filepath.Join(dir, "images2.yaml"))
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected an empty-credential error, got %v", err)
	}
}

// TestRegistryScanEnumeratesCatalogWithoutExplicitRepositories covers the path for
// registries that do implement the _catalog endpoint.
func TestRegistryScanEnumeratesCatalogWithoutExplicitRepositories(t *testing.T) {
	client, host := commandTestRegistry(t)
	for _, ref := range []string{"acme/base/java:v1", "acme/apps/web:v1", "unrelated/thing:v1"} {
		if _, err := client.PushImage(host+"/"+ref, commandTestImage(t, 921)); err != nil {
			t.Fatalf("push %s: %v", ref, err)
		}
	}
	dir := t.TempDir()
	images := filepath.Join(dir, "images.yaml")

	stdout, err := runCLI(t, "registry", "scan", "--registry", host,
		"--namespace", "acme", "--output", images, "--refs-output", filepath.Join(dir, "refs.txt"))
	if err != nil {
		t.Fatalf("registry scan: %v\n%s", err, stdout)
	}
	refs, err := os.ReadFile(filepath.Join(dir, "refs.txt"))
	if err != nil {
		t.Fatalf("read refs: %v", err)
	}
	if strings.Contains(string(refs), "unrelated/thing") {
		t.Fatalf("namespace filter leaked into the ref list:\n%s", refs)
	}
	if !strings.Contains(string(refs), "acme/base/java:v1") || !strings.Contains(string(refs), "acme/apps/web:v1") {
		t.Fatalf("expected both acme repositories, got:\n%s", refs)
	}
}

// TestRegistryScanJSONOutputCarriesScanRecord covers the structured-output branch.
func TestRegistryScanJSONOutputCarriesScanRecord(t *testing.T) {
	client, host := commandTestRegistry(t)
	if _, err := client.PushImage(host+"/acme/app:v1", commandTestImage(t, 931)); err != nil {
		t.Fatalf("push: %v", err)
	}
	dir := t.TempDir()
	stdout, err := runCLI(t, "--format", "json", "registry", "scan", "--registry", host,
		"--repository", "acme/app", "--output", filepath.Join(dir, "images.yaml"),
		"--scan-output", filepath.Join(dir, "scan.json"))
	if err != nil {
		t.Fatalf("registry scan: %v\n%s", err, stdout)
	}
	var payload struct {
		Refs      []string `json:"refs"`
		Inventory string   `json:"inventory"`
		Images    int      `json:"images"`
		Summary   struct {
			TagsSelected int `json:"tagsSelected"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode json output: %v\n%s", err, stdout)
	}
	if payload.Images != 1 || payload.Summary.TagsSelected != 1 || len(payload.Refs) != 1 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if _, err := os.Stat(filepath.Join(dir, "scan.json")); err != nil {
		t.Fatalf("--scan-output not written: %v", err)
	}
}

// TestGraphBuildBaseRepositoryAndMinConfidenceFlagsReachTheEngine exercises the two
// narrowing flags through real flag parsing.
func TestGraphBuildBaseRepositoryAndMinConfidenceFlagsReachTheEngine(t *testing.T) {
	client, host := commandTestRegistry(t)
	base := stampCreated(t, commandTestImage(t, 941), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if _, err := client.PushImage(host+"/bases/rust:v1", base); err != nil {
		t.Fatalf("push base: %v", err)
	}
	layer, err := random.Layer(64, "application/vnd.oci.image.layer.v1.tar+gzip")
	if err != nil {
		t.Fatalf("random layer: %v", err)
	}
	app, err := mutate.AppendLayers(base, layer)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := client.PushImage(host+"/apps/tool:v1", stampCreated(t, app, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("push app: %v", err)
	}

	dir := t.TempDir()
	images := filepath.Join(dir, "images.yaml")
	observations := filepath.Join(dir, "observations.json")
	graphPath := filepath.Join(dir, "graph.json")

	if stdout, err := runCLI(t, "registry", "scan", "--registry", host,
		"--repository", "bases/rust", "--repository", "apps/tool", "--output", images); err != nil {
		t.Fatalf("registry scan: %v\n%s", err, stdout)
	}
	if stdout, err := runCLI(t, "import", "observe", "--images", images, "--output", observations, "--strict"); err != nil {
		t.Fatalf("import observe: %v\n%s", err, stdout)
	}
	stdout, err := runCLI(t, "--format", "json", "graph", "build",
		"--observations", observations, "--output", graphPath,
		"--base-repository", "*/bases/rust", "--min-confidence", "verified")
	if err != nil {
		t.Fatalf("graph build: %v\n%s", err, stdout)
	}
	var graph estategraph.Graph
	if err := json.Unmarshal([]byte(stdout), &graph); err != nil {
		t.Fatalf("decode graph: %v\n%s", err, stdout)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].Confidence != "verified" {
		t.Fatalf("want one verified edge, got %+v", graph.Edges)
	}
}

// TestGraphBuildRejectsInvalidMinConfidenceThroughTheCLI keeps the engine's
// validation reachable from the flag surface.
func TestGraphBuildRejectsInvalidMinConfidenceThroughTheCLI(t *testing.T) {
	dir := t.TempDir()
	observations := filepath.Join(dir, "observations.json")
	if err := os.WriteFile(observations, []byte(`{"images":[]}`), 0o644); err != nil {
		t.Fatalf("seed observations: %v", err)
	}
	_, err := runCLI(t, "graph", "build", "--observations", observations,
		"--output", filepath.Join(dir, "graph.json"), "--min-confidence", "extremely")
	if err == nil || !strings.Contains(err.Error(), "invalid minimum confidence") {
		t.Fatalf("expected the validation error, got %v", err)
	}
}

// TestGraphBuildFailOnUnknownGatesUndeterminedBases covers the second gate.
func TestGraphBuildFailOnUnknownGatesUndeterminedBases(t *testing.T) {
	client, host := commandTestRegistry(t)
	// Two unrelated images: neither is layered on the other, so neither can be
	// placed and neither qualifies as a root.
	for i, ref := range []string{"acme/one:v1", "acme/two:v1"} {
		if _, err := client.PushImage(host+"/"+ref, commandTestImage(t, int64(951+i))); err != nil {
			t.Fatalf("push %s: %v", ref, err)
		}
	}
	dir := t.TempDir()
	images := filepath.Join(dir, "images.yaml")
	observations := filepath.Join(dir, "observations.json")

	if stdout, err := runCLI(t, "registry", "scan", "--registry", host,
		"--repository", "acme/one", "--repository", "acme/two", "--output", images); err != nil {
		t.Fatalf("registry scan: %v\n%s", err, stdout)
	}
	if stdout, err := runCLI(t, "import", "observe", "--images", images, "--output", observations, "--strict"); err != nil {
		t.Fatalf("import observe: %v\n%s", err, stdout)
	}
	stdout, err := runCLI(t, "graph", "build", "--observations", observations,
		"--output", filepath.Join(dir, "graph.json"), "--fail-on-unknown")
	if err == nil {
		t.Fatalf("expected the unknown-base gate to fail:\n%s", stdout)
	}
	if !strings.Contains(stdout, "undetermined base") {
		t.Fatalf("expected the gate to name the finding, got:\n%s", stdout)
	}
}

// TestGraphLayersEndToEnd drives the commonality analysis through the real CLI
// against images pushed to an in-process registry, including the two republished
// tags that should be reported as content-identical.
func TestGraphLayersEndToEnd(t *testing.T) {
	client, host := commandTestRegistry(t)

	base := stampCreated(t, commandTestImage(t, 961), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	// Same content published under two tags: the "release that changed nothing" case.
	for _, tag := range []string{"v1.0.0", "v1.1.0"} {
		if _, err := client.PushImage(host+"/bases/java:"+tag, base); err != nil {
			t.Fatalf("push base %s: %v", tag, err)
		}
	}
	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	if err != nil {
		t.Fatalf("random layer: %v", err)
	}
	app, err := mutate.AppendLayers(base, layer)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := client.PushImage(host+"/apps/pay:v1", stampCreated(t, app, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("push app: %v", err)
	}

	dir := t.TempDir()
	images := filepath.Join(dir, "images.yaml")
	observations := filepath.Join(dir, "observations.json")
	layersPath := filepath.Join(dir, "layers.json")
	report := filepath.Join(dir, "commonality.md")
	diagram := filepath.Join(dir, "graph.mmd")

	if stdout, err := runCLI(t, "registry", "scan", "--registry", host,
		"--repository", "bases/java", "--repository", "apps/pay", "--output", images); err != nil {
		t.Fatalf("registry scan: %v\n%s", err, stdout)
	}
	if stdout, err := runCLI(t, "import", "observe", "--images", images, "--output", observations, "--strict"); err != nil {
		t.Fatalf("import observe: %v\n%s", err, stdout)
	}
	stdout, err := runCLI(t, "graph", "layers", "--observations", observations,
		"--output", layersPath, "--report", report, "--mermaid", diagram,
		"--generated-at", "2026-06-01T00:00:00Z")
	if err != nil {
		t.Fatalf("graph layers: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "carry byte-identical content") {
		t.Fatalf("expected the republished tags to be reported:\n%s", stdout)
	}

	raw, err := os.ReadFile(layersPath)
	if err != nil {
		t.Fatalf("read layers: %v", err)
	}
	var graph estategraph.LayerGraph
	if err := json.Unmarshal(raw, &graph); err != nil {
		t.Fatalf("decode layer graph: %v", err)
	}
	if graph.Summary.Images != 3 {
		t.Fatalf("Images = %d, want 3", graph.Summary.Images)
	}
	if len(graph.Identical) != 1 || len(graph.Identical[0].Images) != 2 {
		t.Fatalf("want the two identical base tags grouped, got %+v", graph.Identical)
	}
	// The base's layers are in all three images; the app layer is in one.
	if graph.Summary.CoreLayers == 0 {
		t.Fatalf("expected a fleet core, got %+v", graph.Summary)
	}
	if graph.Summary.UniqueLayers != 1 {
		t.Fatalf("UniqueLayers = %d, want 1 (the app layer)", graph.Summary.UniqueLayers)
	}
	if graph.Summary.SharingRatio <= 0 {
		t.Fatalf("SharingRatio = %.2f, want a positive saving", graph.Summary.SharingRatio)
	}

	for path, want := range map[string]string{
		report:  "# Fleet Layer Commonality",
		diagram: "```mermaid",
	} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(content), want) {
			t.Fatalf("%s missing %q:\n%s", path, want, content)
		}
	}
}

// TestGraphLayersRejectsOutOfRangeCoverage keeps the engine validation reachable
// through the flag surface.
func TestGraphLayersRejectsOutOfRangeCoverage(t *testing.T) {
	dir := t.TempDir()
	observations := filepath.Join(dir, "observations.json")
	if err := os.WriteFile(observations, []byte(`{"images":[]}`), 0o644); err != nil {
		t.Fatalf("seed observations: %v", err)
	}
	_, err := runCLI(t, "graph", "layers", "--observations", observations,
		"--output", filepath.Join(dir, "layers.json"), "--coverage", "1.5")
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected the coverage range error, got %v", err)
	}
}

// TestGraphLayersReportsWhenThereIsNoDiagramToDraw keeps --mermaid honest instead of
// writing an empty file.
func TestGraphLayersReportsWhenThereIsNoDiagramToDraw(t *testing.T) {
	client, host := commandTestRegistry(t)
	for i, ref := range []string{"solo/one:v1", "solo/two:v1"} {
		if _, err := client.PushImage(host+"/"+ref, commandTestImage(t, int64(971+i))); err != nil {
			t.Fatalf("push %s: %v", ref, err)
		}
	}
	dir := t.TempDir()
	images := filepath.Join(dir, "images.yaml")
	observations := filepath.Join(dir, "observations.json")
	diagram := filepath.Join(dir, "graph.mmd")

	if stdout, err := runCLI(t, "registry", "scan", "--registry", host,
		"--repository", "solo/one", "--repository", "solo/two", "--output", images); err != nil {
		t.Fatalf("registry scan: %v\n%s", err, stdout)
	}
	if stdout, err := runCLI(t, "import", "observe", "--images", images, "--output", observations, "--strict"); err != nil {
		t.Fatalf("import observe: %v\n%s", err, stdout)
	}
	stdout, err := runCLI(t, "graph", "layers", "--observations", observations,
		"--output", filepath.Join(dir, "layers.json"), "--mermaid", diagram)
	if err != nil {
		t.Fatalf("graph layers: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "no diagram written") {
		t.Fatalf("expected an explanation instead of an empty diagram:\n%s", stdout)
	}
	if _, statErr := os.Stat(diagram); statErr == nil {
		t.Fatal("an empty diagram file should not be written")
	}
}
