package registryscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubTimeoutAppliesToEveryPageAndBody(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprint("body=", body), func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Query().Get("page") == "1" {
					page := make([]map[string]string, 100)
					for i := range page {
						page[i] = map[string]string{"name": "app"}
					}
					_ = json.NewEncoder(w).Encode(page)
					return
				}
				if body {
					_, _ = io.WriteString(w, "[")
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer srv.Close()
			client := &http.Client{}
			g := &GitHubPackages{Owner: "acme", API: srv.URL, Client: client, Timeout: 100 * time.Millisecond}
			repos, err := g.Repositories(context.Background(), "ghcr.io")
			if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "limit 100ms") || len(repos) != 0 || requests.Load() != 2 {
				t.Fatalf("pagination timeout lost or partial inventory accepted: %v, %v, requests=%d", repos, err, requests.Load())
			}
			if client.Timeout != 0 {
				t.Fatal("changed shared HTTP client")
			}
		})
	}
}
