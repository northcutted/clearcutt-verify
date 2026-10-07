package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/config"
)

func TestCatalogEnrichFleetConfigAndTagBranches(t *testing.T) {
	oldOpts := catalogEnrichOpts
	defer func() { catalogEnrichOpts = oldOpts }()

	catalogEnrichOpts = catalogEnrichFlags{}
	if err := applyCatalogEnrichConfig(false, false); err != nil {
		t.Fatalf("blank enrich config should be ignored: %v", err)
	}

	missingConfig := filepath.Join(t.TempDir(), "missing.yaml")
	catalogEnrichOpts = catalogEnrichFlags{config: missingConfig}
	if err := applyCatalogEnrichConfig(false, false); err != nil {
		t.Fatalf("implicit missing enrich config should be ignored: %v", err)
	}
	if err := applyCatalogEnrichConfig(true, false); err == nil {
		t.Fatal("explicit missing enrich config should fail")
	}

	root := t.TempDir()
	cfg := config.DefaultConfig("acme", "platform")
	cfg.Catalog.ReleaseLimit = 7
	cfg.Matrix.Languages = []string{"java21", "node24"}
	cfg.Services = []config.ServiceImage{{ID: "postgres16", Template: "postgres", Version: "16"}}
	raw, err := config.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fleet config: %v", err)
	}
	configPath := filepath.Join(root, config.DefaultConfigPath)
	if err := os.WriteFile(configPath, raw, 0o644); err != nil {
		t.Fatalf("write fleet config: %v", err)
	}

	catalogEnrichOpts = catalogEnrichFlags{config: configPath, includeServices: true}
	if err := applyCatalogEnrichConfig(false, false); err != nil {
		t.Fatalf("apply enrich fleet defaults: %v", err)
	}
	if catalogEnrichOpts.owner != "acme" ||
		catalogEnrichOpts.repo != "platform" ||
		catalogEnrichOpts.registryBase != "ghcr.io/acme/platform" ||
		catalogEnrichOpts.imagePrefix != "platform" ||
		!strings.Contains(catalogEnrichOpts.targets, "java21-dev") ||
		!strings.Contains(catalogEnrichOpts.targets, "node24-distroless") ||
		!strings.Contains(catalogEnrichOpts.targets, "postgres16") ||
		catalogEnrichOpts.limit != 7 {
		t.Fatalf("fleet defaults were not applied: %#v", catalogEnrichOpts)
	}

	catalogEnrichOpts = catalogEnrichFlags{
		config:       configPath,
		owner:        "keep-owner",
		repo:         "keep-repo",
		registryBase: "registry.example.com/keep",
		imagePrefix:  "keep-prefix",
		targets:      "keep-target",
		limit:        3,
	}
	if err := applyCatalogEnrichConfig(false, true); err != nil {
		t.Fatalf("apply enrich fleet defaults with explicit values: %v", err)
	}
	if catalogEnrichOpts.owner != "keep-owner" ||
		catalogEnrichOpts.repo != "keep-repo" ||
		catalogEnrichOpts.registryBase != "registry.example.com/keep" ||
		catalogEnrichOpts.imagePrefix != "keep-prefix" ||
		catalogEnrichOpts.targets != "keep-target" ||
		catalogEnrichOpts.limit != 3 {
		t.Fatalf("explicit enrich values should be preserved: %#v", catalogEnrichOpts)
	}

	catalogEnrichOpts = catalogEnrichFlags{tags: " v1.0.0, ,v1.1.0 "}
	tags, err := catalogEnrichTags("acme", "platform")
	if err != nil {
		t.Fatalf("explicit enrich tags failed: %v", err)
	}
	if strings.Join(tags, ",") != "v1.0.0,v1.1.0" {
		t.Fatalf("tags were not cleaned: %#v", tags)
	}
}
