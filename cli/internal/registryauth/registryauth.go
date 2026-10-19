// Package registryauth finds registry credentials: the Docker keychain
// (docker login, credential helpers), then, for ghcr.io only, the
// GITHUB_TOKEN a GitHub Actions job already has. Commands that name the
// registry they write to (estate push, pull, and history; evidence) also
// offer the explicit credentials in the environment, to that registry only.
package registryauth

import (
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// Keychain is the Docker keychain, falling back to GITHUB_TOKEN for ghcr.io.
// The token is never offered to any other registry.
var Keychain authn.Keychain = authn.NewMultiKeychain(authn.DefaultKeychain, githubToken{})

type githubToken struct{}

func (githubToken) Resolve(r authn.Resource) (authn.Authenticator, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if r.RegistryStr() != "ghcr.io" || token == "" {
		return authn.Anonymous, nil
	}
	user := os.Getenv("GITHUB_ACTOR")
	if user == "" {
		user = "x-access-token"
	}
	return authn.FromConfig(authn.AuthConfig{Username: user, Password: token}), nil
}

// EnvCredentials are the explicit registry credentials in the environment:
// REGISTRY_USER and REGISTRY_TOKEN, else CLEARCUTT_REGISTRY_USER and
// CLEARCUTT_REGISTRY_TOKEN. GITHUB_TOKEN is not one of them: it is ghcr.io's.
func EnvCredentials() (user, token string) {
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := os.Getenv(k); strings.TrimSpace(v) != "" {
				return v
			}
		}
		return ""
	}
	return first("REGISTRY_USER", "CLEARCUTT_REGISTRY_USER"), first("REGISTRY_TOKEN", "CLEARCUTT_REGISTRY_TOKEN")
}

// ForRefs is Keychain with the explicit credentials in the environment
// (EnvCredentials) offered first, and only, to the registries refs name: the
// ones a command was told to read or write. Each credential reaches only its
// registry: the explicit ones the named registries, GITHUB_TOKEN ghcr.io,
// and the Docker keychain's each its own.
func ForRefs(refs ...string) authn.Keychain {
	named := map[string]bool{}
	for _, ref := range refs {
		if r, err := name.ParseReference(strings.TrimSpace(ref), name.WeakValidation); err == nil {
			named[r.Context().RegistryStr()] = true
		} else if repo, err := name.NewRepository(strings.TrimSpace(ref), name.WeakValidation); err == nil {
			named[repo.RegistryStr()] = true
		}
	}
	return authn.NewMultiKeychain(explicit(named), Keychain)
}

// explicit offers EnvCredentials to the registries it holds.
type explicit map[string]bool

func (e explicit) Resolve(r authn.Resource) (authn.Authenticator, error) {
	user, token := EnvCredentials()
	if user == "" || token == "" || !e[r.RegistryStr()] {
		return authn.Anonymous, nil
	}
	return authn.FromConfig(authn.AuthConfig{Username: user, Password: token}), nil
}
