package estateverify

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

func TestCosignTimeoutIsUnknownEvenWhenRunnerSaysSuccess(t *testing.T) {
	for _, runErr := range []error{nil, errors.New("signal: killed")} {
		v := &Verifier{Timeout: time.Millisecond,
			Run: func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
				<-ctx.Done()
				return []byte("untrusted output"), runErr
			}}
		_, err := v.run(context.Background(), "verify")
		status, detail := failure(err, "invalid signature")
		if !errors.Is(err, context.DeadlineExceeded) || status != "unknown" || !strings.Contains(detail, "limit 1ms") {
			t.Fatalf("timeout counted as an evidence decision: %s, %s", status, detail)
		}
	}
}

func TestFactoryTimeoutCannotCountAMismatch(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	signer := report.Signer{Key: "acme.pub"}
	f := FactoryReproducer{Dir: t.TempDir(), Timeout: time.Millisecond,
		Run: func(ctx context.Context, _, _ string, _ ...string) ([]byte, []byte, error) {
			<-ctx.Done()
			return nil, []byte("error: NOT reproducible: expected " + digest + ", rebuilt " + other), errors.New("signal: killed")
		}}
	got, err := f.Reproduce(context.Background(), "example.test/app@"+digest, signer)
	if got != "" || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), f.Dir) {
		t.Fatalf("timeout accepted mismatch or lost logs: %s, %v", got, err)
	}
	img := &report.Image{Repository: "example.test/app", Digest: digest}
	r := reproduceLocally(context.Background(), img, imageData{recipeVerified: true, recipeSigner: &signer},
		Options{Policy: report.Policy{Reproduce: true}, Reproducer: f}, false)
	if r.Status != "not-checked" || !strings.Contains(r.Detail, "context deadline exceeded") {
		t.Fatalf("timeout counted as non-reproducibility: %+v", r)
	}
}

func TestGrypeTimeoutLeavesRescanUnknown(t *testing.T) {
	g := &GrypeScanner{Timeout: time.Millisecond,
		Run: func(ctx context.Context, _, _ string, _ ...string) ([]byte, []byte, error) {
			<-ctx.Done()
			return []byte(`{"matches":[]}`), nil, nil
		}}
	img := &report.Image{Repository: "example.test/app", Digest: "sha256:" + strings.Repeat("a", 64)}
	r := rescanImage(context.Background(), img, []report.Platform{{Platform: "linux/amd64"}}, nil,
		imageData{sboms: map[string]sbomDoc{"linux/amd64": {raw: []byte(`{"bomFormat":"CycloneDX"}`)}}}, Options{Scanner: g})
	if r.Status != "unknown" || r.Vulnerabilities != nil || !strings.Contains(r.Detail, "context deadline exceeded") || g.Scanned() != 0 || g.Failed() != 1 {
		t.Fatalf("expired scan became clean: %+v", r)
	}
}

func TestStackSignatureUsesConfiguredCosignTimeout(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	idx := pushIndex(t, host+"/stacks/go:1", nil, built, nil)
	desc := descriptorOf(t, idx)
	attach(t, host+"/stacks/go", desc, bundleJSON(t, PredicateCosignSign, desc.Digest.String(), map[string]any{}, fulcioCert(t, ourSigner, ghIssuer)))
	signers := []report.Signer{{Identity: ourSigner, Issuer: ghIssuer}}
	verifier := &Verifier{Timeout: time.Millisecond, Run: func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second {
			return nil, errors.New("configured timeout was not forwarded")
		}
		<-ctx.Done()
		return nil, nil
	}}
	images := []report.Image{{ID: "app", Factory: &report.Factory{StackRef: host + "/stacks/go:1", StackDigest: desc.Digest.String()},
		Evidence: report.Evidence{Recipe: report.EvidenceItem{Status: "verified"}}}}
	stacks := stacksOf(context.Background(), images, Options{Verifier: verifier, Discoverer: &Discoverer{}, Policy: report.Policy{StackSigners: signers}})
	if len(stacks) != 1 || len(stacks[0].Versions) != 1 {
		t.Fatalf("stacks: %+v", stacks)
	}
	sig := stacks[0].Versions[0].Signature
	if sig.Status != "unknown" || !strings.Contains(sig.Detail, "limit 1ms") {
		t.Fatalf("stack ignored timeout or failed evidence: %+v", sig)
	}
}

func TestNativeSubprocessesRespectTimeout(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "blocking-tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Cosign: bin, Timeout: 50 * time.Millisecond}
	if _, err := v.run(context.Background(), "verify"); !errors.Is(err, context.DeadlineExceeded) || !couldntCheck(err) {
		t.Fatalf("native cosign: %v", err)
	}
	g := &GrypeScanner{Binary: bin, Timeout: 50 * time.Millisecond}
	if _, _, err := g.run(context.Background(), "", "version"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("native grype: %v", err)
	}
	f := FactoryReproducer{Binary: bin, Dir: t.TempDir(), Timeout: 50 * time.Millisecond}
	if got, err := f.Reproduce(context.Background(), "r@sha256:x", report.Signer{Key: "acme.pub"}); got != "" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("native factory: %s, %v", got, err)
	}
}
