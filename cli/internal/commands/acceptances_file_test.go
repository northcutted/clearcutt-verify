package commands

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/acceptance"
)

// TestShippedAcceptancesAreLoadableAndUnexpired guards the fleet's real
// acceptance file, which no other test reads — every gate test writes its own
// fixture into a temp dir.
//
// Two failure modes it catches, both of which otherwise surface only as a red
// matrix cell after a full image build:
//
//   - The file stops parsing (a bad edit, a schema change). Every build that
//     reaches the vuln gate then fails on "loading vulnerability acceptances".
//   - An acceptance quietly expires. That is the mechanism working as designed —
//     an expired entry blocks exactly as hard as no entry — but it should be a
//     fast, obvious test failure that says "renew or drop this", not a
//     mysterious build failure weeks later.
func TestShippedAcceptancesAreLoadableAndUnexpired(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	path := filepath.Join(root, "core", "vulnerability-acceptances.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("acceptances file not present: %v", err)
	}
	doc, err := acceptance.Load(path)
	if err != nil {
		t.Fatalf("the fleet's acceptance file must parse: %v", err)
	}

	// An empty list is the expected state for a fleet whose shipped line has no
	// unfixable findings. It is not a disabled gate — the build still fails on
	// any blocking finding — so this asserts loadability, not non-emptiness.
	now := time.Now()
	for _, entry := range doc.Acceptances {
		if entry.ID == "" || entry.Reason == "" || entry.AcceptedBy == "" || entry.ExpiresAt == "" {
			t.Errorf("acceptance %q must name an id, reason, owner and expiry", entry.ID)
			continue
		}
		expiry, err := time.Parse("2006-01-02", entry.ExpiresAt)
		if err != nil {
			t.Errorf("acceptance %q has an unparseable expiry %q: %v", entry.ID, entry.ExpiresAt, err)
			continue
		}
		if expiry.Before(now) {
			t.Errorf("acceptance %q expired on %s; renew it with a fresh decision or delete it — an expired acceptance blocks the build",
				entry.ID, entry.ExpiresAt)
		}
	}
}
