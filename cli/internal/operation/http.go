package operation

import (
	"context"
	"io"
	"net/http"
	"time"
)

type timeoutTransport struct {
	next  http.RoundTripper
	limit time.Duration
	label string
}

// HTTPTimeout limits each RoundTrip including its response body. When wrapped
// by a retry transport, each attempt gets a new budget. It does not change
// the caller's transport, credentials, retry policy or parent cancellation.
func HTTPTimeout(next http.RoundTripper, limit time.Duration, label string) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &timeoutTransport{next: next, limit: limit, label: label}
}

func (t *timeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), t.limit)
	resp, err := t.next.RoundTrip(req.Clone(ctx))
	err = Result(ctx, t.label, t.limit, err)
	if err != nil {
		cancel()
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, err
	}
	if resp.Body == nil {
		cancel()
		return resp, nil
	}
	// Registry images read configs/blobs lazily, after headers have returned.
	resp.Body = &timeoutBody{ReadCloser: resp.Body, ctx: ctx, cancel: cancel, limit: t.limit, label: t.label}
	return resp, nil
}

type timeoutBody struct {
	io.ReadCloser
	ctx    context.Context
	cancel context.CancelFunc
	limit  time.Duration
	label  string
}

func (b *timeoutBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	err = Result(b.ctx, b.label, b.limit, err)
	if err != nil {
		b.cancel()
	}
	return n, err
}

func (b *timeoutBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}
