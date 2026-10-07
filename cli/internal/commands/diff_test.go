package commands

import (
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func contains(arr []string, val string) bool {
	for _, a := range arr {
		if a == val {
			return true
		}
	}
	return false
}

// Exercises the real diffPackages (not a copy) so regressions are caught.
func TestDiffPackages(t *testing.T) {
	fromPkgs := []catalog.PackageEntry{
		{Name: "glibc", Version: "2.35"},
		{Name: "openssl", Version: "3.0.8"},
	}
	toPkgs := []catalog.PackageEntry{
		{Name: "openssl", Version: "3.1.0"},
		{Name: "curl", Version: "8.0.1"},
	}

	added, removed, changed := diffPackages(fromPkgs, toPkgs)

	if len(added) != 1 || !contains(added, "curl (8.0.1)") {
		t.Errorf("expected added 'curl (8.0.1)', got %v", added)
	}
	if len(removed) != 1 || !contains(removed, "glibc (2.35)") {
		t.Errorf("expected removed 'glibc (2.35)', got %v", removed)
	}
	if len(changed) != 1 || !contains(changed, "openssl (3.0.8 -> 3.1.0)") {
		t.Errorf("expected changed 'openssl (3.0.8 -> 3.1.0)', got %v", changed)
	}
}

func TestDiffCVEs(t *testing.T) {
	from := []catalog.FindingInfo{
		{ID: "CVE-1", Severity: "high", PackageName: "openssl"},
		{ID: "CVE-2", Severity: "low", PackageName: "zlib"},
	}
	to := []catalog.FindingInfo{
		{ID: "CVE-2", Severity: "low", PackageName: "zlib"},
		{ID: "CVE-3", Severity: "critical", PackageName: "curl"},
	}

	added, resolved := diffCVEs(from, to)
	if len(added) != 1 || !contains(added, "CVE-3 (curl)") {
		t.Errorf("expected added 'CVE-3 (curl)', got %v", added)
	}
	if len(resolved) != 1 || !contains(resolved, "CVE-1 (openssl)") {
		t.Errorf("expected resolved 'CVE-1 (openssl)', got %v", resolved)
	}
}

func TestResolveRelease(t *testing.T) {
	releases := []catalog.ReleaseEntry{
		{Tag: "v2.0.0", IsLatest: true},
		{Tag: "v1.0.0"},
	}

	if r, err := resolveRelease(releases, "latest"); err != nil || r.Tag != "v2.0.0" {
		t.Errorf("latest => v2.0.0, got %v (err %v)", tagOf(r), err)
	}
	if r, err := resolveRelease(releases, "latest-1"); err != nil || r.Tag != "v1.0.0" {
		t.Errorf("latest-1 => v1.0.0, got %v (err %v)", tagOf(r), err)
	}
	if r, err := resolveRelease(releases, "v1.0.0"); err != nil || r.Tag != "v1.0.0" {
		t.Errorf("exact tag => v1.0.0, got %v (err %v)", tagOf(r), err)
	}
	if _, err := resolveRelease(releases, "latest-9"); err == nil {
		t.Errorf("out-of-bounds latest-N should error")
	}
	if _, err := resolveRelease(releases, "nope"); err == nil {
		t.Errorf("unknown tag should error")
	}
}

func tagOf(r *catalog.ReleaseEntry) string {
	if r == nil {
		return "<nil>"
	}
	return r.Tag
}

// latestOrTaggedRelease is the shared resolver used by verify/vex/policy/mirror.
func TestLatestOrTaggedRelease(t *testing.T) {
	releases := []catalog.ReleaseEntry{
		{Tag: "v2.0.0", IsLatest: true},
		{Tag: "v1.0.0"},
	}
	if r, err := latestOrTaggedRelease(releases, ""); err != nil || r.Tag != "v2.0.0" {
		t.Errorf("empty tag => latest v2.0.0, got %v (err %v)", tagOf(r), err)
	}
	if r, err := latestOrTaggedRelease(releases, "v1.0.0"); err != nil || r.Tag != "v1.0.0" {
		t.Errorf("exact tag => v1.0.0, got %v (err %v)", tagOf(r), err)
	}
	if _, err := latestOrTaggedRelease(nil, ""); err == nil {
		t.Errorf("no releases should error")
	}
}
