package commands

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

// TestRealNotation needs CLEARCUTT_E2E_REGISTRY and CLEARCUTT_E2E_NOTATION
// (a Notation 1.3.2 binary). All signing keys/configuration are temporary.
func TestRealNotation(t *testing.T) {
	registry, binary := os.Getenv("CLEARCUTT_E2E_REGISTRY"), os.Getenv("CLEARCUTT_E2E_NOTATION")
	if registry == "" || binary == "" {
		t.Skip("set CLEARCUTT_E2E_REGISTRY and CLEARCUTT_E2E_NOTATION for real Notation")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "producer-config")
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NOTATION_") {
			env = append(env, entry)
		}
	}
	env = append(env, "NOTATION_CONFIG="+config, "NOTATION_CACHE="+filepath.Join(dir, "producer-cache"), "NOTATION_LIBEXEC="+filepath.Join(dir, "producer-plugins"), "NOTATION_EXPERIMENTAL=1")
	run := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env, cmd.Dir, cmd.WaitDelay = env, dir, 2*time.Second
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("notation %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	t.Log(run("version"))
	run("cert", "generate-test", "--default", "clearcutt-e2e")
	var root []byte
	_ = filepath.WalkDir(config, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && entry.Name() == "clearcutt-e2e.crt" && root == nil {
			root, _ = os.ReadFile(path)
		}
		return nil
	})
	block, _ := pem.Decode(root)
	if block == nil {
		t.Fatal("generated certificate was not found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	identity := "x509.subject: " + cert.Subject.String()
	rootFile := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(rootFile, root, 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Format("150405.000000000")
	push := func(repo string, seed int64) (name.Reference, v1.ImageIndex) {
		t.Helper()
		idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: commandTestImage(t, seed), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}})
		tag, _ := name.NewTag(registry + "/clearcutt-notation-e2e/" + repo + ":" + stamp)
		if err := remote.WriteIndex(tag, idx); err != nil {
			t.Fatal(err)
		}
		digest, _ := idx.Digest()
		return tag.Context().Digest(digest.String()), idx
	}
	jws, _ := push("jws", 1001)
	cose, _ := push("cose", 1002)
	run("sign", "--signature-format", "jws", "--insecure-registry", jws.Name())
	run("sign", "--signature-format", "cose", "--force-referrers-tag=false", "--insecure-registry", cose.Name())
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(jws.Name()+"\n"+cose.Name()), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.json")
	writePolicy := func(id string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"apiVersion": report.APIVersion, "kind": "VerificationPolicy", "required": []string{"signature"}, "notation": map[string]any{"trustedIdentities": []string{id}, "trustRoots": []string{"root.pem"}}})
		if err := os.WriteFile(policy, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy(identity)
	verify := func(extra ...string) (report.Report, error) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "estate")
		args := []string{"estate", "verify", "--refs", refs, "--policy", policy, "--out", out, "--notation-path", binary, "--cosign-path", "/nonexistent/cosign", "--fail-on", "unverified", "--quiet"}
		console, err := runCLI(t, append(args, extra...)...)
		var r report.Report
		raw, readErr := os.ReadFile(filepath.Join(out, report.ReportFile))
		if readErr != nil {
			t.Fatalf("report missing: %v (%v)\n%s", readErr, err, console)
		}
		if json.Unmarshal(raw, &r) != nil {
			t.Fatal("invalid report")
		}
		validateAgainstContract(t, raw)
		return r, err
	}
	r, err := verify()
	if err != nil {
		t.Fatal(err)
	}
	var jwsSignature string
	for _, img := range r.Images {
		sig := img.Evidence.Signature
		if sig.Status != "verified" || sig.Source != "notation-signature" || img.Verdict.Status != "verified" {
			t.Fatalf("Notation signature did not verify: %+v %+v", sig, img.Verdict)
		}
		if strings.HasSuffix(img.Repository, "/jws") {
			jwsSignature = sig.Ref
			if sig.Signer == nil || sig.Signer.Identity != identity || sig.Signer.Issuer != "" {
				t.Fatalf("JWS signer: %+v", sig.Signer)
			}
		} else if sig.Signer != nil {
			t.Fatalf("invented a COSE signer: %+v", sig.Signer)
		}
	}
	// A forged, newer copy carrying the same certificate must not borrow a
	// valid sibling's success. Add it to the same fallback index explicitly.
	original, err := remote.Image(mustReference(t, jwsSignature))
	if err != nil {
		t.Fatal(err)
	}
	mf, _ := original.Manifest()
	layer, _ := original.LayerByDigest(mf.Layers[0].Digest)
	body, _ := layer.Compressed()
	raw, _ := io.ReadAll(body)
	_ = body.Close()
	var envelope map[string]any
	_ = json.Unmarshal(raw, &envelope)
	envelope["signature"] = "AAAA"
	raw, _ = json.Marshal(envelope)
	forged, err := mutate.Append(mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), mf.Config.MediaType), mutate.Addendum{Layer: static.NewLayer(raw, mf.Layers[0].MediaType)})
	if err != nil {
		t.Fatal(err)
	}
	forged = mutate.Subject(forged, *mf.Subject).(v1.Image)
	forged = mutate.Annotations(forged, map[string]string{"org.opencontainers.image.created": "2099-01-01T00:00:00Z"}).(v1.Image)
	digest, _ := forged.Digest()
	if err := remote.Write(jws.Context().Digest(digest.String()), forged); err != nil {
		t.Fatal(err)
	}
	fallback := jws.Context().Tag(strings.Replace(jws.Identifier(), ":", "-", 1))
	idx, err := remote.Index(fallback)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(fallback, mutate.AppendManifests(idx, mutate.IndexAddendum{Add: forged})); err != nil {
		t.Fatal(err)
	}
	r, err = verify()
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range r.Images {
		if strings.HasSuffix(img.Repository, "/jws") && (img.Evidence.Signature.Ref != jwsSignature || img.Evidence.Signature.Status != "verified") {
			t.Fatalf("forged copy borrowed valid identity: %+v", img.Evidence.Signature)
		}
	}
	// The certificate is trusted, but a signature over another artifact must
	// not pass merely because its unsigned manifest subject was retargeted.
	borrowed, _ := push("borrowed", 1003)
	borrowedDesc, err := remote.Get(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	foreign := mutate.Subject(original, borrowedDesc.Descriptor).(v1.Image)
	foreignDigest, _ := foreign.Digest()
	if err := remote.Write(borrowed.Context().Digest(foreignDigest.String()), foreign); err != nil {
		t.Fatal(err)
	}
	foreignIndex := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: foreign})
	if err := remote.WriteIndex(borrowed.Context().Tag(strings.Replace(borrowed.Identifier(), ":", "-", 1)), foreignIndex); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refs, []byte(borrowed.Name()), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err = verify()
	if !errors.Is(err, ErrCheckFailed) || len(r.Images) != 1 || r.Images[0].Evidence.Signature.Status != "unknown" {
		t.Fatalf("foreign subject was accepted: %v %+v", err, r.Images)
	}
	if err := os.WriteFile(refs, []byte(jws.Name()+"\n"+cose.Name()), 0o600); err != nil {
		t.Fatal(err)
	}
	writePolicy("x509.subject: CN=Somebody Else")
	r, err = verify()
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("wrong identity did not leave gate unverified: %v", err)
	}
	for _, img := range r.Images {
		if img.Evidence.Signature.Status != "unknown" || img.Verdict.Status != "unverified" {
			t.Fatalf("ambiguous wrong-identity outcome: %+v", img.Evidence.Signature)
		}
	}
	writePolicy(identity)
	run("cert", "generate-test", "other-root")
	var wrongRoot []byte
	_ = filepath.WalkDir(config, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && entry.Name() == "other-root.crt" && wrongRoot == nil {
			wrongRoot, _ = os.ReadFile(path)
		}
		return nil
	})
	if len(wrongRoot) == 0 {
		t.Fatal("wrong-root fixture was not generated")
	}
	if err := os.WriteFile(rootFile, wrongRoot, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err = verify()
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("wrong root did not leave gate unverified: %v", err)
	}
	for _, img := range r.Images {
		if img.Evidence.Signature.Status != "unknown" {
			t.Fatalf("wrong root was accepted: %+v", img.Evidence.Signature)
		}
	}
	if err := os.WriteFile(rootFile, root, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err = verify("--notation-path", "/nonexistent/notation")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("missing CLI gate: %v", err)
	}
	for _, img := range r.Images {
		if img.Evidence.Signature.Status != "present" {
			t.Fatal("missing optional CLI did not stay present")
		}
	}
}

func mustReference(t *testing.T, ref string) name.Reference {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
