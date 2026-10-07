package catalogbuild

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

// TestBuildIndexStampsKindOnEveryV2ImageSummary guards the v2 index contract:
// catalog-index.v2.schema.json requires kind on every image summary, but the
// runtime gather path never sets it on records. When a service image flips the
// index to v2, the runtime entries must still be emitted with an explicit kind.
func TestBuildIndexStampsKindOnEveryV2ImageSummary(t *testing.T) {
	imagesDir := filepath.Join("..", "testdata", "mixed-catalog", "images")
	entries, err := os.ReadDir(imagesDir)
	if err != nil {
		t.Fatal(err)
	}
	files := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) < 2 {
		t.Fatalf("expected mixed-catalog fixture to hold at least two image records, got %v", files)
	}
	images := []ImageRecord{}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(imagesDir, file))
		if err != nil {
			t.Fatal(err)
		}
		var img ImageRecord
		if err := json.Unmarshal(data, &img); err != nil {
			t.Fatalf("unmarshal %s: %v", file, err)
		}
		if img.Kind == "runtime" {
			// Runtime gather targets never populate kind on the record;
			// strip it to mirror the live build path.
			img.Kind = ""
		}
		images = append(images, img)
	}

	index := BuildIndex(
		"test-owner",
		"test-repo",
		"ghcr.io/test-owner/test-repo",
		"2026-06-05T20:00:00Z",
		[]Release{{Tag: "v1.0.0", PublishedAt: "2026-06-05T20:00:00Z"}},
		images,
	)
	if index.SchemaVersion != catalog.CatalogIndexSchemaVersionV2 {
		t.Fatalf("expected mixed catalog index schemaVersion %q, got %q", catalog.CatalogIndexSchemaVersionV2, index.SchemaVersion)
	}

	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		SchemaVersion string `json:"schemaVersion"`
		Images        []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"images"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.SchemaVersion != catalog.CatalogIndexSchemaVersionV2 {
		t.Fatalf("expected marshalled schemaVersion %q, got %q", catalog.CatalogIndexSchemaVersionV2, parsed.SchemaVersion)
	}
	if len(parsed.Images) != len(images) {
		t.Fatalf("expected %d image summaries, got %d", len(images), len(parsed.Images))
	}
	kinds := map[string]string{}
	for _, img := range parsed.Images {
		if img.Kind == "" {
			t.Errorf("image %s is missing kind in marshalled v2 index", img.ID)
		}
		kinds[img.ID] = img.Kind
	}
	if kinds["java21-distroless"] != "runtime" {
		t.Errorf("expected java21-distroless kind %q, got %q", "runtime", kinds["java21-distroless"])
	}
	if kinds["postgres16"] != "service" {
		t.Errorf("expected postgres16 kind %q, got %q", "service", kinds["postgres16"])
	}
}

// TestBuildIndexAppendsServiceTierForServiceImages guards the tier list: a
// catalog containing service images must surface the service tier entry so
// images[].tier always resolves against tiers[], while runtime-only catalogs
// keep the plain three-tier list.
func TestBuildIndexAppendsServiceTierForServiceImages(t *testing.T) {
	release := []Release{{Tag: "v1.0.0", PublishedAt: "2026-06-05T20:00:00Z"}}
	runtimeOnly := BuildIndex("o", "r", "ghcr.io/o/r", "2026-06-05T20:00:00Z", release, []ImageRecord{
		{ID: "java21-distroless", Tier: Tier{ID: "distroless"}},
	})
	for _, tier := range runtimeOnly.Tiers {
		if tier.ID == "service" {
			t.Fatalf("runtime-only catalog must not list the service tier, got %#v", runtimeOnly.Tiers)
		}
	}

	withService := BuildIndex("o", "r", "ghcr.io/o/r", "2026-06-05T20:00:00Z", release, []ImageRecord{
		{ID: "java21-distroless", Tier: Tier{ID: "distroless"}},
		{ID: "postgres16", Kind: "service", Tier: serviceTier, Service: &catalog.ServiceInfo{Template: "postgres", Version: "16"}},
	})
	found := false
	for _, tier := range withService.Tiers {
		if tier.ID == "service" {
			found = true
			if tier != serviceTier {
				t.Fatalf("service tier entry %#v does not match canonical %#v", tier, serviceTier)
			}
		}
	}
	if !found {
		t.Fatalf("catalog with service images must list the service tier, got %#v", withService.Tiers)
	}
}
