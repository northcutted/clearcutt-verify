package estate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// TestHistoryStartsOverOnlyWhenNothingIsThere: estate push starts a new
// history index only when the registry says there is none. A registry that
// refuses or fails the read (401, 403, 429, 500) stops the push before it
// writes, so a blip can't erase the series by writing a one-entry index over
// it, and a tag holding something other than a history is never overwritten.
func TestHistoryStartsOverOnlyWhenNothingIsThere(t *testing.T) {
	reg := registry.New()
	var fail atomic.Int32 // status the history manifest is served with; 0 serves it
	var historyWrites atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/manifests/history") {
			if r.Method == http.MethodPut {
				historyWrites.Add(1)
			} else if code := int(fail.Load()); code != 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_, _ = fmt.Fprintf(w, `{"errors":[{"code":"%s","message":"no"}]}`, map[int]string{401: "UNAUTHORIZED", 403: "DENIED", 429: "TOOMANYREQUESTS", 500: "UNKNOWN"}[code])
				return
			}
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := &Client{nameOpts: []name.Option{name.Insecure}, remoteOpts: []remote.Option{remote.WithRetryBackoff(remote.Backoff{Duration: time.Millisecond, Steps: 1})}}
	historyRef := host + "/acme/estate:history"

	// A first run: nothing there, so a series starts.
	if _, _, err := c.PushSnapshot(host+"/acme/estate:day-1", historyRef, snapshotWith("2026-09-01T00:00:00Z", 19, 3, 2, 6)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if historyWrites.Load() != 1 {
		t.Fatalf("first run wrote the history %d times", historyWrites.Load())
	}

	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		fail.Store(int32(code))
		before := historyWrites.Load()
		digest, _, err := c.PushSnapshot(host+"/acme/estate:day-2", historyRef, snapshotWith("2026-09-02T00:00:00Z", 19, 9, 7, 1))
		if err == nil || !strings.Contains(err.Error(), "not starting a new history") {
			t.Errorf("%d: got %v, want the push to stop", code, err)
		}
		if digest == "" {
			t.Errorf("%d: the stored snapshot's digest was lost", code)
		}
		if historyWrites.Load() != before {
			t.Errorf("%d: the history index was overwritten", code)
		}
	}
	fail.Store(0)
	h, err := c.ReadHistory(historyRef)
	if err != nil || len(h.Entries) != 1 {
		t.Fatalf("the series after refused reads: %+v, %v", h, err)
	}

	// Something that isn't a history is never overwritten.
	img, _ := random.Image(64, 1)
	idx, _ := random.Index(64, 1, 2)
	for what, write := range map[string]func(name.Reference) error{
		"an image": func(r name.Reference) error { return remote.Write(r, img) },
		"an index": func(r name.Reference) error { return remote.WriteIndex(r, idx) },
	} {
		ref := host + "/acme/" + strings.ReplaceAll(what, " ", "-") + ":history"
		r, _ := name.ParseReference(ref, name.Insecure)
		if err := write(r); err != nil {
			t.Fatal(err)
		}
		before := historyWrites.Load()
		if _, _, err := c.PushSnapshot(host+"/acme/estate:day-3", ref, snapshotWith("2026-09-03T00:00:00Z", 19, 9, 7, 1)); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
			t.Errorf("%s at the history tag: %v", what, err)
		}
		if historyWrites.Load() != before {
			t.Errorf("%s at the history tag was overwritten", what)
		}
	}
}
