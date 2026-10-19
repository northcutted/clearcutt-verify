package estategraph

import (
	"strings"
	"testing"
)

func TestImageID(t *testing.T) {
	for _, tc := range []struct{ ref, want string }{
		{"ghcr.io/acme/billing:1.2", "ghcr-io-acme-billing-1-2"},
		{"ghcr.io/acme/billing", "ghcr-io-acme-billing"},
		{"ghcr.io/acme/billing:latest", "ghcr-io-acme-billing"},
		{"debian:trixie-slim", "docker-io-library-debian-trixie-slim"},
		{"index.docker.io/library/debian:trixie-slim", "docker-io-library-debian-trixie-slim"},
		{"localhost:5000/e2e/app:7", "localhost-5000-e2e-app-7"},
		{"ghcr.io/acme/billing@sha256:" + strings.Repeat("0123456789abcdef", 4), "ghcr-io-acme-billing-sha256-0123456789ab"},
		// The same name in two registries or two paths is two images.
		{"cgr.dev/chainguard/static:latest", "cgr-dev-chainguard-static"},
		{"ghcr.io/acme/images/static:latest", "ghcr-io-acme-images-static"},
	} {
		if got := ImageID(tc.ref); got != tc.want {
			t.Errorf("ImageID(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

// IDs are unique, and the same whatever order the references come in, so an
// estate's images keep their IDs from run to run.
func TestAssignIDsIsUniqueAndOrderIndependent(t *testing.T) {
	refs := []string{"ghcr.io/acme/a-b:1", "ghcr.io/acme/a/b:1", "ghcr.io/acme/a-b:1.0", "ghcr.io/acme/c:1"}
	first := AssignIDs(refs)
	seen := map[string]bool{}
	for i, id := range first {
		if seen[id] {
			t.Fatalf("duplicate ID %s in %v", id, first)
		}
		seen[id] = true
		if strings.Trim(id, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			t.Errorf("%s isn't a URL path segment", id)
		}
		if i == 3 && id != "ghcr-io-acme-c-1" {
			t.Errorf("an ID nothing collides with keeps its plain form: %s", id)
		}
	}
	reversed := []string{refs[3], refs[2], refs[1], refs[0]}
	second := AssignIDs(reversed)
	for i := range refs {
		if first[i] != second[len(refs)-1-i] {
			t.Errorf("%s: %s in one order, %s in another", refs[i], first[i], second[len(refs)-1-i])
		}
	}
	// A collision suffix depends only on the reference.
	if !strings.HasPrefix(first[0], "ghcr-io-acme-a-b-1-") || first[0] == first[1] {
		t.Errorf("colliding IDs: %v", first)
	}
}

func TestImportRefListListsAnImageOnce(t *testing.T) {
	inventory, _, err := ImportRefList([]string{"ghcr.io/acme/app:1", "ghcr.io/acme/app:1", "ghcr.io/acme/app:latest", "ghcr.io/acme/app"}, ImportOptions{GeneratedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, img := range inventory.Images {
		ids = append(ids, img.ID)
	}
	if strings.Join(ids, ",") != "ghcr-io-acme-app,ghcr-io-acme-app-1" {
		t.Errorf("IDs %v", ids)
	}
}
