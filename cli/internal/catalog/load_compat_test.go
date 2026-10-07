package catalog_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func TestLoadCatalogNormalizesLegacyEvidenceBooleans(t *testing.T) {
	catalogDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(catalogDir, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	indexJSON := []byte(`{
  "images": [{
    "id": "imported-java",
    "evidence": {
      "signature": true,
      "provenance": false,
      "sbom": true,
      "tests": false,
      "vulnerabilities": false
    }
  }]
}`)
	recordJSON := []byte(`{
  "id": "imported-java",
  "releases": [{
    "tag": "latest",
    "evidence": {
      "signature": false,
      "provenance": false,
      "sbom": true,
      "tests": false,
      "vulnerabilities": true
    }
  }]
}`)
	if err := os.WriteFile(filepath.Join(catalogDir, "index.json"), indexJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(catalogDir, "images", "imported-java.json"), recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := catalog.LoadCatalogIndex(catalogDir)
	if err != nil {
		t.Fatalf("LoadCatalogIndex failed: %v", err)
	}
	summaryEvidence := index.Images[0].Evidence
	if summaryEvidence == nil || summaryEvidence.Statuses == nil {
		t.Fatalf("expected normalized summary statuses: %#v", summaryEvidence)
	}
	if got := summaryEvidence.Statuses.Signature.Status; got != catalog.EvidenceStatusVerified {
		t.Fatalf("legacy true signature normalized to %q, want verified", got)
	}
	if got := summaryEvidence.Statuses.Provenance.Status; got != catalog.EvidenceStatusMissing {
		t.Fatalf("legacy false provenance normalized to %q, want missing", got)
	}

	record, err := catalog.LoadImageRecord(catalogDir, "imported-java")
	if err != nil {
		t.Fatalf("LoadImageRecord failed: %v", err)
	}
	releaseEvidence := record.Releases[0].Evidence
	if releaseEvidence == nil || releaseEvidence.Statuses == nil {
		t.Fatalf("expected normalized release statuses: %#v", releaseEvidence)
	}
	if got := releaseEvidence.Statuses.SBOM.Status; got != catalog.EvidenceStatusObserved {
		t.Fatalf("legacy true SBOM normalized to %q, want observed", got)
	}
	if got := releaseEvidence.Statuses.Vulnerabilities.Status; got != catalog.EvidenceStatusObserved {
		t.Fatalf("legacy true vulnerabilities normalized to %q, want observed", got)
	}
	if got := releaseEvidence.Statuses.Provenance.Status; got != catalog.EvidenceStatusMissing {
		t.Fatalf("legacy false provenance normalized to %q, want missing", got)
	}
}

func TestEvidenceStatusesAreCanonicalOverLegacyBooleans(t *testing.T) {
	catalogDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(catalogDir, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	indexJSON := []byte(`{
  "images": [{
    "id": "imported-java",
    "signed": false,
    "provenance": true,
    "passed": true,
    "evidence": {
      "signature": false,
      "provenance": true,
      "sbom": false,
      "tests": true,
      "vulnerabilities": false,
      "statuses": {
        "signature": { "status": "verified", "source": "test" },
        "provenance": { "status": "missing", "source": "test" },
        "sbom": { "status": "observed", "source": "test" },
        "tests": { "status": "missing", "source": "test" },
        "vulnerabilities": { "status": "stale", "source": "test" }
      }
    }
  }]
}`)
	recordJSON := []byte(`{
  "id": "imported-java",
  "releases": [{
    "tag": "latest",
    "evidence": {
      "signature": false,
      "provenance": true,
      "sbom": false,
      "tests": true,
      "vulnerabilities": false,
      "statuses": {
        "signature": { "status": "verified", "source": "test" },
        "provenance": { "status": "missing", "source": "test" },
        "sbom": { "status": "observed", "source": "test" },
        "tests": { "status": "missing", "source": "test" },
        "vulnerabilities": { "status": "stale", "source": "test" }
      }
    }
  }]
}`)
	if err := os.WriteFile(filepath.Join(catalogDir, "index.json"), indexJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(catalogDir, "images", "imported-java.json"), recordJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := catalog.LoadCatalogIndex(catalogDir)
	if err != nil {
		t.Fatalf("LoadCatalogIndex failed: %v", err)
	}
	summary := index.Images[0]
	if !summary.Signed || summary.Provenance || summary.Passed {
		t.Fatalf("summary booleans should be derived from canonical statuses: signed=%t provenance=%t passed=%t", summary.Signed, summary.Provenance, summary.Passed)
	}
	if evidence := summary.Evidence; evidence == nil || !evidence.Signature || evidence.Provenance || !evidence.SBOM || evidence.Tests || evidence.Vulnerabilities {
		t.Fatalf("evidence booleans should be derived from canonical statuses: %#v", evidence)
	}

	record, err := catalog.LoadImageRecord(catalogDir, "imported-java")
	if err != nil {
		t.Fatalf("LoadImageRecord failed: %v", err)
	}
	evidence := record.Releases[0].Evidence
	if evidence == nil || !evidence.Signature || evidence.Provenance || !evidence.SBOM || evidence.Tests || evidence.Vulnerabilities {
		t.Fatalf("release evidence booleans should be derived from canonical statuses: %#v", evidence)
	}
}

func TestStaleAndObservedTrustChannelsDoNotSatisfyLegacyGates(t *testing.T) {
	evidence := catalog.EvidenceSummary{
		Signature:       true,
		Provenance:      true,
		SBOM:            true,
		Tests:           true,
		Vulnerabilities: true,
		Statuses: &catalog.EvidenceStatuses{
			Signature:       catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusObserved},
			Provenance:      catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusAttested},
			SBOM:            catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusStale},
			Tests:           catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusStale},
			Vulnerabilities: catalog.EvidenceChannelStatus{Status: catalog.EvidenceStatusObserved},
		},
	}
	catalog.NormalizeEvidenceSummary(&evidence)
	if evidence.Signature || evidence.Provenance || evidence.SBOM || evidence.Tests {
		t.Fatalf("non-verified or stale trust channels must not satisfy legacy gates: %#v", evidence)
	}
	if !evidence.Vulnerabilities {
		t.Fatalf("current observed vulnerability coverage should satisfy the coverage gate: %#v", evidence)
	}
	if !catalog.EvidenceChannelPresent(evidence.Statuses.SBOM) || catalog.EvidenceChannelCurrent(evidence.Statuses.SBOM) {
		t.Fatalf("stale evidence should remain visible but not current: %#v", evidence.Statuses.SBOM)
	}
}
