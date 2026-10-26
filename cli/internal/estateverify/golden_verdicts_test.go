package estateverify

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

var updateBundles = flag.Bool("update", false, "rewrite the verdicts and summaries of the contract bundles from this code")

// TestVerdictsInContractBundlesArePinned recomputes every verdict in the
// bundles under contract/ from the recorded evidence and policy, and fails
// when one differs. What a verdict means is part of the contract
// (contract/README.md, "Verdicts"): a change that alters a recorded verdict
// is a change of meaning, and has to change the bundle in the same commit,
// with a CHANGELOG entry under Breaking, rather than slip through.
func TestVerdictsInContractBundlesArePinned(t *testing.T) {
	docs, err := filepath.Glob(filepath.Join("..", "..", "..", "contract", "*", "*", "estate-report.json"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("no contract bundles found: %v", err)
	}
	for _, path := range docs {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var r report.Report
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		now, err := time.Parse(time.RFC3339, r.Metadata.GeneratedAt)
		if err != nil {
			t.Fatalf("%s: generatedAt: %v", path, err)
		}
		for i, img := range r.Images {
			got := verdictAt(img, r.Policy, now)
			if *updateBundles {
				r.Images[i].Verdict = got
				continue
			}
			if got.Status != img.Verdict.Status || strings.Join(got.Reasons, "\n") != strings.Join(img.Verdict.Reasons, "\n") {
				t.Errorf("%s: %s: the verdict recorded is %s %q, but this code decides %s %q: a change of meaning (see contract/README.md, Verdicts)",
					filepath.Base(filepath.Dir(path)), img.ID, img.Verdict.Status, img.Verdict.Reasons, got.Status, got.Reasons)
			}
		}
		if *updateBundles {
			r.Summary = summarize(&r)
			writeBundleJSON(t, path, &r)
			// The history's entry for this run carries the same summary and
			// verdicts.
			hpath := filepath.Join(filepath.Dir(path), report.HistoryFile)
			if hraw, err := os.ReadFile(hpath); err == nil {
				var h report.History
				if err := json.Unmarshal(hraw, &h); err != nil {
					t.Fatalf("%s: %v", hpath, err)
				}
				byID := map[string]report.Image{}
				for _, img := range r.Images {
					byID[img.ID] = img
				}
				for e := range h.Entries {
					if h.Entries[e].GeneratedAt != r.Metadata.GeneratedAt {
						continue
					}
					h.Entries[e].Summary = r.Summary
					for j, row := range h.Entries[e].Images {
						img, ok := byID[row.ID]
						if !ok {
							continue
						}
						row.Verdict, row.ObserveOnly, row.RescanVulnerabilities = img.Verdict.Status, img.ObserveOnly, nil
						if rs := img.Rescan; rs != nil && rs.Status == "scanned" && rs.Vulnerabilities != nil {
							c := rs.Vulnerabilities.Counts
							row.RescanVulnerabilities = &c
						}
						h.Entries[e].Images[j] = row
					}
				}
				writeBundleJSON(t, hpath, &h)
			}
		}
	}
}

func writeBundleJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
