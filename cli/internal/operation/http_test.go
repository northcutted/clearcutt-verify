package operation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPTimeoutIncludesHeadersAndBody(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "body"}[body], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if body {
					_, _ = io.WriteString(w, "partial")
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer srv.Close()
			client := &http.Client{Transport: HTTPTimeout(nil, 50*time.Millisecond, "registry request")}
			resp, err := client.Get(srv.URL)
			if err == nil {
				defer resp.Body.Close()
				_, err = io.ReadAll(resp.Body)
			}
			if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "registry request (limit 50ms)") {
				t.Fatalf("expected a bounded request, got %v", err)
			}
		})
	}
}

func TestHTTPBodyRemainsUsableUntilReadOrClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "manifest")
	}))
	defer srv.Close()
	transport := HTTPTimeout(nil, time.Second, "registry request")
	for _, read := range []bool{true, false} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Request.Context().Err(); err != nil {
			t.Fatalf("cancelled at headers: %v", err)
		}
		if read {
			raw, err := io.ReadAll(resp.Body)
			if err != nil || string(raw) != "manifest" {
				t.Fatalf("lazy body read: %s, %v", raw, err)
			}
		}
		_ = resp.Body.Close()
		if resp.Request.Context().Err() == nil || req.Context().Err() != nil {
			t.Fatal("body did not release its own timer or cancelled the parent")
		}
	}
}

func TestHTTPTimeoutRespectsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:1", nil)
	_, err := HTTPTimeout(nil, time.Hour, "registry request").RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if Limit(0, time.Minute) != time.Minute || Limit(time.Second, time.Minute) != time.Second {
		t.Fatal("invalid internal default")
	}
}
