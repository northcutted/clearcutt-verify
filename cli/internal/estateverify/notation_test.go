package estateverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

func notationFixture(t *testing.T) (string, string, Found, *report.NotationTrust) {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	repo := host + "/notated"
	idx := pushIndex(t, repo+":1", nil, built, nil)
	desc := descriptorOf(t, idx)
	attachNotation(t, repo, desc, false)
	found, err := (&Discoverer{}).Discover(context.Background(), repo, desc.Digest.String())
	if err != nil || len(found) != 1 {
		t.Fatalf("notation discovery: %+v, %v", found, err)
	}
	der, _ := base64.StdEncoding.DecodeString(fulcioCert(t, ourSigner, ghIssuer))
	root := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return host, repo + "@" + desc.Digest.String(), found[0], &report.NotationTrust{TrustedIdentities: []string{"x509.subject: " + notarySubject}, TrustRoots: []string{root}}
}

func TestNotationPinnedStrictVerificationAndIsolation(t *testing.T) {
	host, ref, found, trust := notationFixture(t)
	t.Setenv("NOTATION_CONFIG", "/foreign/audit-policy")
	t.Setenv("NOTATION_PASSWORD", "test-credential-must-not-be-forwarded")
	var invocations int
	run := func(_ context.Context, _ string, env []string, args ...string) ([]byte, []byte, error) {
		if args[0] == "version" {
			return []byte("Version: 1.3.2\n"), nil, nil
		}
		invocations++
		settings := map[string]string{}
		for _, entry := range env {
			k, v, _ := strings.Cut(entry, "=")
			settings[k] = v
		}
		if settings["NOTATION_CONFIG"] == "/foreign/audit-policy" || settings["NOTATION_PASSWORD"] != "" || settings["NOTATION_EXPERIMENTAL"] != "1" {
			t.Fatal("user configuration or credentials reached isolated checker")
		}
		raw, err := os.ReadFile(filepath.Join(settings["NOTATION_CONFIG"], "trustpolicy.json"))
		if err != nil {
			t.Fatal(err)
		}
		var policy struct {
			Policies []struct {
				Scopes       []string `json:"registryScopes"`
				Verification struct {
					Level    string `json:"level"`
					Override any    `json:"override"`
				} `json:"signatureVerification"`
			} `json:"trustPolicies"`
		}
		if json.Unmarshal(raw, &policy) != nil || len(policy.Policies) != 1 || policy.Policies[0].Verification.Level != "strict" || policy.Policies[0].Verification.Override != nil || strings.Join(policy.Policies[0].Scopes, ",") != host+"/notated" {
			t.Fatalf("not a strict per-repository policy: %s", raw)
		}
		index, _ := os.ReadFile(filepath.Join(strings.Split(args[2], "@")[0], "index.json"))
		var idx struct {
			Manifests []any `json:"manifests"`
		}
		_ = json.Unmarshal(index, &idx)
		if len(idx.Manifests) != 2 || !strings.Contains(strings.Join(args, " "), "--max-signatures 1") {
			t.Fatal("verification was not restricted to the captured signature")
		}
		return []byte("Successfully verified signature for " + args[2] + "\n"), nil, nil
	}
	v, err := NewNotationVerifier(context.Background(), trust, "notation", time.Second, nil, run)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		status, detail := v.Verify(context.Background(), ref, found)
		if status != "verified" {
			t.Fatalf("pinned signature: %s %s", status, detail)
		}
	}
	if invocations != 2 {
		t.Fatal("Notation expiry/revocation check was cached")
	}
	verifier := &Verifier{Notation: v}
	observations := observe(t, host, "notated:1")
	r, err := Build(context.Background(), observations, Options{Verifier: verifier, Policy: report.Policy{Required: []string{KindSignature}, Notation: trust}})
	if err != nil {
		t.Fatal(err)
	}
	sig := r.Images[0].Evidence.Signature
	if sig.Status != "verified" || sig.Source != FormatNotation || sig.Signer == nil || sig.Signer.Identity != "x509.subject: "+notarySubject || sig.Signer.Issuer != "" || r.Images[0].Verdict.Status != "verified" {
		t.Fatalf("Notation-only image: %+v %+v", sig, r.Images[0].Verdict)
	}
	validateReport(t, r)
	// COSE can establish a trusted signature without exposing a parsed DN.
	found.Signer = nil
	item, _ := verifyEvidence(context.Background(), verifier, strings.Split(ref, "@")[0], strings.Split(ref, "@")[1], KindSignature, "", []Found{found})
	if item.Status != "verified" || item.Signer != nil || !strings.Contains(item.Detail, "not read") {
		t.Fatalf("invented a COSE identity: %+v", item)
	}
}

func TestNotationAmbiguousFailuresAndSkipAreUnknown(t *testing.T) {
	_, ref, found, trust := notationFixture(t)
	for _, behavior := range []string{"failure", "timeout", "skip", "wrong-subject"} {
		t.Run(behavior, func(t *testing.T) {
			run := func(ctx context.Context, _ string, _ []string, args ...string) ([]byte, []byte, error) {
				if args[0] == "version" {
					return []byte("Version: 1.3.2\n"), nil, nil
				}
				switch behavior {
				case "failure":
					return nil, []byte("signature verification failed for all signatures"), errors.New("exit status 1")
				case "timeout":
					<-ctx.Done()
					return []byte("Successfully verified signature for " + args[2]), nil, nil
				case "skip":
					return []byte("Trust policy is configured to skip signature verification for " + args[2]), nil, nil
				default:
					return []byte("Successfully verified signature for unrelated@sha256:wrong"), nil, nil
				}
			}
			v, err := NewNotationVerifier(context.Background(), trust, "notation", time.Millisecond, nil, run)
			if err != nil {
				t.Fatal(err)
			}
			status, detail := v.Verify(context.Background(), ref, found)
			if status != "unknown" {
				t.Fatalf("ambiguous result became %s: %s", status, detail)
			}
		})
	}
}

func TestNotationTrustValidationAndMissingCLI(t *testing.T) {
	_, ref, found, trust := notationFixture(t)
	v, err := NewNotationVerifier(context.Background(), trust, "/nonexistent/notation", 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := v.Verify(context.Background(), ref, found); status != "present" {
		t.Fatal("missing optional CLI did not stay present")
	}
	for _, bad := range []*report.NotationTrust{
		{}, {TrustedIdentities: []string{"*"}, TrustRoots: trust.TrustRoots},
		{TrustedIdentities: []string{"x509.subject:"}, TrustRoots: trust.TrustRoots},
		{TrustedIdentities: trust.TrustedIdentities, TrustRoots: []string{"https://roots.example.test/ca.pem"}},
	} {
		if err := ValidatePolicy(report.Policy{Notation: bad}); err == nil {
			t.Fatalf("invalid Notation trust accepted: %+v", bad)
		}
	}
	runner := func(context.Context, string, []string, ...string) ([]byte, []byte, error) {
		return []byte("Version: 1.4.0\n"), nil, nil
	}
	v, err = NewNotationVerifier(context.Background(), trust, "notation", 0, nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := v.Verify(context.Background(), ref, found); status != "present" {
		t.Fatal("unsupported CLI did not stay present")
	}
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	text := "apiVersion: clearcutt.dev/v1\nkind: VerificationPolicy\nrequired: [signature]\nnotation:\n  trustedIdentities: ['x509.subject: CN=Acme']\n  trustRoots: [ca.pem]\n"
	if err := os.WriteFile(policy, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := ReadPolicy(policy)
	if err != nil || p.Notation.TrustRoots[0] != filepath.Join(dir, "ca.pem") {
		t.Fatalf("relative Notation root: %+v %v", p, err)
	}
	if err := os.WriteFile(policy, []byte(strings.Replace(text, "[ca.pem]", "['https://roots.example.test/ca.pem']", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicy(policy); err == nil || !strings.Contains(err.Error(), "local certificate") {
		t.Fatalf("remote root became a local path: %v", err)
	}
}

func TestNotationVersionTimeoutIsUnknown(t *testing.T) {
	_, ref, found, trust := notationFixture(t)
	runner := func(ctx context.Context, _ string, _ []string, _ ...string) ([]byte, []byte, error) {
		<-ctx.Done()
		return nil, nil, nil
	}
	v, err := NewNotationVerifier(context.Background(), trust, "notation", time.Millisecond, nil, runner)
	if err != nil {
		t.Fatal(err)
	}
	if status, detail := v.Verify(context.Background(), ref, found); status != "unknown" || !strings.Contains(detail, "deadline exceeded") {
		t.Fatalf("probe timeout: %s %s", status, detail)
	}
}
