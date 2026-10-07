package catalog_test

import (
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func TestValidateImageRecord_RejectsUnknownEnums(t *testing.T) {
	rec := &catalog.ImageRecord{
		ID:       "x",
		Language: catalog.LanguageInfo{ID: "java"},
		Tier:     catalog.TierInfo{ID: "bogus-tier"},
	}
	if err := catalog.ValidateImageRecord(rec); err == nil {
		t.Error("expected an error for an unknown tier")
	}

	rec.Tier.ID = "distroless"
	rec.Releases = []catalog.ReleaseEntry{{Tag: "v1", Lifecycle: catalog.Lifecycle{Status: "typoed-status"}}}
	if err := catalog.ValidateImageRecord(rec); err == nil {
		t.Error("expected an error for an unknown release lifecycle status")
	}

	rec.Releases[0].Lifecycle.Status = "active"
	if err := catalog.ValidateImageRecord(rec); err != nil {
		t.Errorf("valid record rejected: %v", err)
	}
}

func TestValidateCatalogIndex_RejectsUnknownStatus(t *testing.T) {
	idx := &catalog.CatalogIndex{
		GeneratedAt: "2026-01-01",
		Owner:       "o",
		Repo:        "r",
		Images: []catalog.CatalogImageSummary{
			{ID: "a", Tier: "slim", Lifecycle: catalog.Lifecycle{Status: "not-a-status"}},
		},
	}
	if err := catalog.ValidateCatalogIndex(idx); err == nil {
		t.Error("expected an error for an unknown lifecycle status in the index")
	}

	idx.Images[0].Lifecycle.Status = "active"
	if err := catalog.ValidateCatalogIndex(idx); err != nil {
		t.Errorf("valid index rejected: %v", err)
	}
}
