package estateverify

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// TestRebaseRecordCarriesTheSmokeTest: clearcutt-factory (v0.2.0 and later)
// records in the signed rebase record the smoke test it ran on the rebased
// image and each platform's result. A verified record that says it passed on
// every platform is verified test evidence; rebased images no longer show
// tests: missing when their record says the test passed.
func TestRebaseRecordCarriesTheSmokeTest(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)), ggcrregistry.WithReferrersSupport(true)))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ours, evil := fulcioCert(t, ourSigner, ghIssuer), fulcioCert(t, evilSigner, ghIssuer)
	original := pushIndex(t, host+"/original:1", nil, built, nil)
	originalRef := host + "/original@" + descriptorOf(t, original).Digest.String()
	test := func(results map[string]string) map[string]any {
		return map[string]any{"http": map[string]any{"port": 8080, "path": "/healthz"}, "timeout": "30s", "platforms": results}
	}
	both := map[string]string{"linux/amd64": "sha256:" + strings.Repeat("1", 64), "linux/arm64": "sha256:" + strings.Repeat("2", 64)}

	for _, tc := range []struct {
		name, cert     string
		test           map[string]any
		status         string
		verdict        string
		detailIncludes string
	}{
		{"passed", ours, test(map[string]string{"linux/amd64": "passed", "linux/arm64": "passed"}), "verified", "verified", "passed on linux/amd64, linux/arm64"},
		{"failed", ours, test(map[string]string{"linux/amd64": "passed", "linux/arm64": "failed"}), "failed", "failed", "didn't pass on linux/arm64 (failed)"},
		{"one platform", ours, test(map[string]string{"linux/amd64": "passed"}), "present", "unverified", "says nothing about linux/arm64"},
		{"no results", ours, test(map[string]string{}), "present", "unverified", "no result"},
		{"no test", ours, nil, "missing", "failed", "No test attestation."},
		// A record nobody trusted says nothing, whatever it claims.
		{"untrusted", evil, test(map[string]string{"linux/amd64": "passed", "linux/arm64": "passed"}), "missing", "failed", "No test attestation."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := strings.ReplaceAll(tc.name, " ", "-")
			img := pushIndex(t, host+"/"+repo+":1", nil, built, nil)
			desc := descriptorOf(t, img)
			d := desc.Digest.String()
			record := map[string]any{"factory": map[string]string{"version": "v0.3.0"}, "image": originalRef,
				"result": map[string]any{"ref": host + "/" + repo + ":1", "digest": d, "platforms": both}}
			if tc.test != nil {
				record["test"] = tc.test
			}
			attach(t, host+"/"+repo, desc, bundleJSON(t, PredicateCosignSign, d, map[string]any{}, ours))
			attach(t, host+"/"+repo, desc, bundleJSON(t, PredicateRebase, d, record, tc.cert))
			verifier := acmeVerifier()
			r, err := Build(context.Background(), observe(t, host, repo+":1"), Options{
				Name: "tests", Version: "test", GeneratedAt: "2026-10-18T00:00:00Z", Verifier: verifier,
				Policy: report.Policy{Required: []string{KindSignature, KindRecipe, KindTests}, TrustedSigners: verifier.Signers},
			})
			if err != nil {
				t.Fatal(err)
			}
			validateReport(t, r)
			e := r.Images[0].Evidence.Tests
			if e.Status != tc.status || !strings.Contains(e.Detail, tc.detailIncludes) {
				t.Errorf("tests %+v, want %s saying %q", e, tc.status, tc.detailIncludes)
			}
			if tc.status != "missing" && (e.PredicateType != PredicateRebase || e.Signer == nil || e.Signer.Identity != ourSigner || e.Ref == "") {
				t.Errorf("tests don't point at the rebase record that says so: %+v", e)
			}
			if v := r.Images[0].Verdict; v.Status != tc.verdict {
				t.Errorf("verdict %+v, want %s", v, tc.verdict)
			}
		})
	}
}
