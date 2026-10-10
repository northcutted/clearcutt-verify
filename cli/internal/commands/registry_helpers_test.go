package commands

import (
	"io"
	"log"
	"math/rand"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// testRegistryClient pushes images to an in-process registry.
type testRegistryClient struct{}

func (testRegistryClient) PushImage(ref string, img v1.Image) (string, error) {
	r, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		return "", err
	}
	if err := remote.Write(r, img); err != nil {
		return "", err
	}
	d, err := img.Digest()
	return d.String(), err
}

// commandTestRegistry starts an in-process registry for a test.
func commandTestRegistry(t *testing.T) (testRegistryClient, string) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return testRegistryClient{}, strings.TrimPrefix(srv.URL, "http://")
}

// commandTestImage is a reproducible two-layer linux/amd64 image.
func commandTestImage(t *testing.T, seed int64) v1.Image {
	t.Helper()
	img, err := random.Image(256, 2, random.WithSource(rand.NewSource(seed)))
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture = "linux", "amd64"
	cfg.Config.User = "10001:10001"
	cfg.Config.Entrypoint = []string{"/base"}
	cfg.Config.Labels = map[string]string{"org.opencontainers.image.source": "https://github.com/acme/images"}
	if img, err = mutate.ConfigFile(img, cfg); err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	return img
}
