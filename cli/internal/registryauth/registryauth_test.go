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

// TestForRefs: each credential reaches only its registry. The explicit pair
// goes to the registries the command names, GITHUB_TOKEN to ghcr.io, and
// nothing to anything else, however its name is spelled.
func TestForRefs(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir()) // no docker login
	t.Setenv("GITHUB_TOKEN", "ghs_test")
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("REGISTRY_USER", "ci-bot")
	t.Setenv("REGISTRY_TOKEN", "s3cret")
	t.Setenv("CLEARCUTT_REGISTRY_USER", "")
	t.Setenv("CLEARCUTT_REGISTRY_TOKEN", "")
	kc := ForRefs("registry.acme.example/estate:latest", "", "not a reference!")
	resolve := func(ref string) authn.AuthConfig {
		t.Helper()
		r, err := name.ParseReference(ref)
		if err != nil {
			t.Fatal(err)
		}
		a, err := kc.Resolve(r.Context())
		if err != nil {
			t.Fatal(err)
		}
		c, err := a.Authorization()
		if err != nil {
			t.Fatal(err)
		}
		return *c
	}
	for ref, want := range map[string]string{
		"registry.acme.example/estate:history":      "ci-bot:s3cret",
		"ghcr.io/acme/app:1":                        "octocat:ghs_test",
		"docker.io/library/debian:13":               ":",
		"registry.acme.example.evil.example/x:1":    ":",
		"evil.example/registry.acme.example/x:1":    ":",
		"ghcr.io.evil.example/acme/x:1":             ":",
		"registry.acme.example:5000/estate:history": ":",
	} {
		if c := resolve(ref); c.Username+":"+c.Password != want {
			t.Errorf("%s got %s:%s, want %s", ref, c.Username, c.Password, want)
		}
	}
	// The ClearCutt-prefixed pair stands in for the plain one.
	t.Setenv("REGISTRY_USER", "")
	t.Setenv("REGISTRY_TOKEN", "")
	t.Setenv("CLEARCUTT_REGISTRY_USER", "cc-bot")
	t.Setenv("CLEARCUTT_REGISTRY_TOKEN", "cc-token")
	if c := resolve("registry.acme.example/estate:latest"); c.Username != "cc-bot" || c.Password != "cc-token" {
		t.Errorf("CLEARCUTT_REGISTRY_*: %+v", c)
	}
	// Half a pair is no credential.
	t.Setenv("CLEARCUTT_REGISTRY_TOKEN", "")
	if c := resolve("registry.acme.example/estate:latest"); c.Password != "" {
		t.Errorf("user without token: %+v", c)
	}
}
