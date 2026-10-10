// Package registryauth finds registry credentials: the Docker keychain
// (docker login, credential helpers), then, for ghcr.io only, the
// GITHUB_TOKEN a GitHub Actions job already has.
package registryauth

import (
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
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
