package estateverify

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestManifestCache(t *testing.T) {
	reg := ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)))
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/") {
			gets.Add(1)
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	idx, err := random.Index(64, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := name.ParseReference(u.Host + "/acme/base:latest")
	if err := remote.WriteIndex(tag, idx); err != nil {
		t.Fatal(err)
	}
	digest, _ := idx.Digest()
	im, _ := idx.IndexManifest()
	child := im.Manifests[0].Digest

	o := []remote.Option{remote.WithTransport(NewManifestCache(http.DefaultTransport))}
	gets.Store(0)
	read := func() {
		t.Helper()
		if _, err := remote.Get(tag, o...); err != nil { // the observer
			t.Fatal(err)
		}
		byDigest, _ := name.NewDigest(u.Host + "/acme/base@" + digest.String())
		got, err := remote.Index(byDigest, o...) // platform listing
		if err != nil {
			t.Fatal(err)
		}
		img, err := got.Image(child)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := img.Manifest(); err != nil {
			t.Fatal(err)
		}
	}
	read()
	read()
	// The tag once (also remembered under its digest), the platform image once.
	if n := gets.Load(); n != 2 {
		t.Fatalf("registry served %d manifest GETs, want 2", n)
	}

	// Failures aren't remembered.
	missing, _ := name.ParseReference(u.Host + "/acme/base:nope")
	for range 2 {
		if _, err := remote.Get(missing, o...); err == nil {
			t.Fatal("want an error for a missing tag")
		}
	}
	if n := gets.Load(); n != 4 {
		t.Fatalf("registry served %d manifest GETs, want 4", n)
	}
}
