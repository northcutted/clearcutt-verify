package registryauth

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

func TestKeychain(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir()) // no docker login
	t.Setenv("GITHUB_TOKEN", "ghs_test")
	t.Setenv("GITHUB_ACTOR", "octocat")
	resolve := func(ref string) *authn.AuthConfig {
		t.Helper()
		r, err := name.ParseReference(ref)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Keychain.Resolve(r.Context())
		if err != nil {
			t.Fatal(err)
		}
		c, err := a.Authorization()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := resolve("ghcr.io/acme/app:1"); c.Username != "octocat" || c.Password != "ghs_test" {
		t.Errorf("ghcr.io: %+v", c)
	}
	for _, ref := range []string{"docker.io/library/debian:13", "cgr.dev/chainguard/static", "ghcr.io.evil.example/acme/x:1", "evil.example/ghcr.io/x:1"} {
		if c := resolve(ref); c.Password != "" || c.Username != "" {
			t.Errorf("%s got credentials %+v", ref, c)
		}
	}
	t.Setenv("GITHUB_TOKEN", "")
	if c := resolve("ghcr.io/acme/app:1"); c.Password != "" {
		t.Errorf("no token: %+v", c)
	}
}
