package estateverify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

func factoryVEXPredicate(t *testing.T) (map[string]any, []map[string]any) {
	t.Helper()
	r := recordedGrype(t)
	var rows []map[string]any
	for _, m := range r.IgnoredMatches {
		rows = append(rows, map[string]any{"vulnerability": m.Vulnerability.ID, "package": m.Artifact.Name, "version": m.Artifact.Version, "purl": m.Artifact.PURL,
			"document": "https://example.test/triage/1", "product": "pkg:apk/wolfi/openssl", "status": "not_affected", "justification": "vulnerable_code_not_present"})
	}
	return map[string]any{"scanner": map[string]any{"uri": "pkg:github/anchore/grype@0.120.1", "result": r},
		"metadata": map[string]any{"vex": map[string]any{"suppressed": rows}}}, rows
}

func TestAttestedFactoryVEXAttribution(t *testing.T) {
	pred, _ := factoryVEXPredicate(t)
	raw, _ := json.Marshal(pred)
	scan, err := readVulnPredicate(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := mergeVulnerabilities(map[string]vulnScan{"linux/amd64": scan, "linux/arm64": scan})
	suppressed := 0
	for _, f := range got.Findings {
		if !f.Suppressed {
			if f.SuppressedBy != nil {
				t.Fatal("metadata suppressed a counted finding")
			}
			continue
		}
		suppressed++
		by := f.SuppressedBy
		if by == nil || by.Source != "vex" || by.Document != "https://example.test/triage/1" || by.Product != "pkg:apk/wolfi/openssl" || by.Status != "not_affected" || by.Justification != "vulnerable_code_not_present" || by.File != "" {
			t.Fatalf("publisher's signed attribution was lost or invented a local file: %+v", by)
		}
	}
	if suppressed != 2 || len(got.Findings) != 4 || got.Counts.High != 1 || got.Counts.Medium != 1 {
		t.Fatalf("attribution changed findings/counts: %+v", got)
	}
}

func TestAttestedVEXRequiresExactUnambiguousIgnoredMatch(t *testing.T) {
	for _, change := range []string{"id", "package", "version", "purl", "missing-document", "missing-product", "bad-status", "conflict", "scanner-rule", "malformed"} {
		t.Run(change, func(t *testing.T) {
			pred, rows := factoryVEXPredicate(t)
			switch change {
			case "id":
				rows[0]["vulnerability"] = "CVE-OTHER"
			case "package":
				rows[0]["package"] = "other"
			case "version":
				rows[0]["version"] = "other"
			case "purl":
				rows[0]["purl"] = rows[0]["purl"].(string) + "&arch=other"
			case "missing-document":
				delete(rows[0], "document")
			case "missing-product":
				delete(rows[0], "product")
			case "bad-status":
				rows[0]["status"] = "under_investigation"
			case "conflict":
				copy := map[string]any{}
				for k, v := range rows[0] {
					copy[k] = v
				}
				copy["document"] = "another"
				pred["metadata"].(map[string]any)["vex"].(map[string]any)["suppressed"] = append(rows, copy)
			case "scanner-rule":
				r := pred["scanner"].(map[string]any)["result"].(grypeResult)
				r.IgnoredMatches[0].AppliedIgnoreRules = nil
				pred["scanner"].(map[string]any)["result"] = r
			case "malformed":
				pred["metadata"].(map[string]any)["vex"] = "unreadable"
			}
			raw, _ := json.Marshal(pred)
			scan, err := readVulnPredicate(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(scan.suppressedBy) > 0 && scan.suppressedBy[0] != nil {
				t.Fatalf("invalid attribution accepted: %+v", scan.suppressedBy[0])
			}
			got := mergeVulnerabilities(map[string]vulnScan{"linux/amd64": scan})
			if len(got.Findings) != 4 || got.Counts.High != 1 || got.Counts.Medium != 1 {
				t.Fatal("optional metadata changed scan coverage or findings")
			}
		})
	}
}

func TestSuppressionAttributionDoesNotExpandAcrossPlatforms(t *testing.T) {
	pred, _ := factoryVEXPredicate(t)
	raw, _ := json.Marshal(pred)
	first, err := readVulnPredicate(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []*report.Suppression{nil, {Source: "vex", Document: "different", Product: "pkg:apk/wolfi/openssl", Status: "fixed"}} {
		second := first
		second.suppressedBy = append([]*report.Suppression{}, first.suppressedBy...)
		second.suppressedBy[0] = other
		got := mergeVulnerabilities(map[string]vulnScan{"linux/amd64": first, "linux/arm64": second})
		for _, f := range got.Findings {
			if strings.EqualFold(f.ID, first.Result.IgnoredMatches[0].Vulnerability.ID) && (!f.Suppressed || f.SuppressedBy != nil) {
				t.Fatalf("one platform's attribution expanded to all: %+v", f)
			}
		}
	}
}
