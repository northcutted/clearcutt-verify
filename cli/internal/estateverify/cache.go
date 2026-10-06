package estateverify

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
)

// ManifestCache is an http.RoundTripper that remembers the manifests it
// fetches for the length of one run. Registries count manifest reads against
// their rate limits (Docker Hub allows 100 anonymous ones an hour), and one
// run reads the same manifest several times: to observe the image, to list
// its platforms, and again to check the images built on it. A manifest
// fetched by tag is also remembered under its digest. Only successful GETs
// are kept, and nothing outlives the process.
type ManifestCache struct {
	next    http.RoundTripper
	mu      sync.Mutex
	entries map[string]cachedResponse
}

type cachedResponse struct {
	header http.Header
	body   []byte
}

// NewManifestCache wraps next, typically remote.DefaultTransport.
func NewManifestCache(next http.RoundTripper) *ManifestCache {
	return &ManifestCache{next: next, entries: map[string]cachedResponse{}}
}

func (c *ManifestCache) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || !strings.Contains(req.URL.Path, "/manifests/") {
		return c.next.RoundTrip(req)
	}
	key := cacheKey(req.URL.Host, req.URL.Path, req.Header.Get("Accept"))
	c.mu.Lock()
	hit, ok := c.entries[key]
	c.mu.Unlock()
	if ok {
		return hit.response(req), nil
	}

	resp, err := c.next.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	entry := cachedResponse{header: resp.Header.Clone(), body: body}
	c.mu.Lock()
	c.entries[key] = entry
	if d := resp.Header.Get("Docker-Content-Digest"); strings.HasPrefix(d, "sha256:") {
		path := req.URL.Path[:strings.LastIndex(req.URL.Path, "/manifests/")] + "/manifests/" + d
		c.entries[cacheKey(req.URL.Host, path, "")] = entry
	}
	c.mu.Unlock()
	return entry.response(req), nil
}

// cacheKey keys a manifest by URL. What a digest names never changes, so a
// digest's key ignores the Accept header (ggcr asks for images, indexes, or
// either); what a tag names depends on what was asked for.
func cacheKey(host, path, accept string) string {
	if strings.Contains(path, "/manifests/sha256:") {
		return host + path
	}
	return host + path + "\x00" + accept
}

func (e cachedResponse) response(req *http.Request) *http.Response {
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: e.header.Clone(), Body: io.NopCloser(bytes.NewReader(e.body)),
		ContentLength: int64(len(e.body)), Request: req,
	}
}
