package commands

import (
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/versionpolicy"
)

func TestVersionPolicyLoaded(t *testing.T) {
	policy := versionpolicy.Loaded()
	if len(policy.Languages) == 0 {
		t.Fatal("embedded version policy should classify at least one language")
	}
}
