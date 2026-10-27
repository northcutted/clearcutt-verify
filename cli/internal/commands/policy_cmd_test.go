package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/northcutted/clearcutt-verify/internal/estateverify"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

func TestPolicyInitStarterDoesNotEstablishTrust(t *testing.T) {
	reg, host := commandTestRegistry(t)
	ref := host + "/acme/app:1"
	if _, err := reg.PushImage(ref, commandTestImage(t, 71)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(ref+"\n"+ref+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "starter")
	stdout, err := runCLI(t, "policy", "init", "--refs", refs, "--out", dest, "--format", "json")
	if err != nil {
		t.Fatalf("initialize policy: %v\n%s", err, stdout)
	}
	var summary struct {
		Images   int      `json:"images"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil || summary.Images != 1 || len(summary.Required) != 0 {
		t.Fatalf("summary: %s (%v)", stdout, err)
	}
	policyPath := filepath.Join(dest, "policy.yaml")
	policy, err := estateverify.ReadPolicy(policyPath)
	if err != nil || len(policy.TrustedSigners) != 0 {
		t.Fatalf("starter inferred trust: %+v (%v)", policy, err)
	}
	trust, err := estateverify.ReadTrustPolicy(filepath.Join(dest, "trust-policy.yaml"))
	if err != nil || len(trust.Signers) != 0 {
		t.Fatalf("active trust: %+v (%v)", trust, err)
	}
	if err := report.Validate(trust); err != nil {
		t.Fatal(err)
	}
	// An untouched starter cannot turn discovered metadata into a verified image.
	_, err = runCLI(t, "estate", "verify", "--refs", refs, "--policy", policyPath,
		"--out", filepath.Join(dir, "estate"), "--fail-on", "unverified", "--quiet")
	if !errors.Is(err, ErrCheckFailed) {
		t.Fatalf("untouched starter passed verification: %v", err)
	}
}

func TestPolicyInitInventoryAndRefOrder(t *testing.T) {
	reg, host := commandTestRegistry(t)
	refs := []string{host + "/acme/one:1", host + "/acme/two:1"}
	for i, ref := range refs {
		if _, err := reg.PushImage(ref, commandTestImage(t, int64(81+i))); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	list := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(list, []byte(strings.Join(refs, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(dir, "images.yaml")
	if err := os.WriteFile(inventory, []byte("images:\n  - image: "+refs[1]+"\n    evidencePolicy: {required: [signature]}\n  - image: "+refs[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ flag, input, out string }{
		{"--refs", list, "from-refs"}, {"--images", inventory, "from-inventory"},
	} {
		if stdout, err := runCLI(t, "policy", "init", tc.flag, tc.input, "--out", filepath.Join(dir, tc.out), "--quiet"); err != nil || stdout != "" {
			t.Fatalf("%s: %v %q", tc.flag, err, stdout)
		}
	}
	for _, file := range []string{"policy.yaml", "trust-policy.yaml"} {
		a, _ := os.ReadFile(filepath.Join(dir, "from-refs", file))
		b, _ := os.ReadFile(filepath.Join(dir, "from-inventory", file))
		if string(a) != string(b) || len(a) == 0 {
			t.Errorf("%s depends on input order or declared evidence", file)
		}
	}
}

func TestPolicyInitRefusesInvalidInputAndExistingOutput(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.txt")
	malformed := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(empty, []byte("# no references\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformed, []byte("images: broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{}, {"--refs", empty, "--images", malformed}, {"--refs", empty},
		{"--refs", empty, "--concurrency", "0"}, {"--refs", empty, "extra"},
		{"--images", malformed}, {"--refs", filepath.Join(dir, "missing")},
	} {
		dest := filepath.Join(t.TempDir(), "policy")
		argv := append([]string{"policy", "init", "--out", dest}, args...)
		if _, err := runCLI(t, argv...); err == nil {
			t.Errorf("accepted %v", argv)
		}
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			t.Errorf("failed input published output %s: %v", dest, err)
		}
	}
	// Existing directories and dangling symlinks are both outputs to preserve.
	existing := filepath.Join(dir, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(existing, "policy.yaml")
	if err := os.WriteFile(keep, []byte("keep this"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "absent"), link); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{existing, link} {
		if _, err := runCLI(t, "policy", "init", "--refs", empty, "--out", dest); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("existing output %s: %v", dest, err)
		}
	}
	if raw, _ := os.ReadFile(keep); string(raw) != "keep this" {
		t.Fatal("existing policy was overwritten")
	}
}

func TestPolicyInitVerboseKeepsJSONOnStdout(t *testing.T) {
	reg, host := commandTestRegistry(t)
	ref := host + "/acme/app:1"
	if _, err := reg.PushImage(ref, commandTestImage(t, 91)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	refs := filepath.Join(dir, "refs.txt")
	if err := os.WriteFile(refs, []byte(ref), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"policy", "init", "--refs", refs, "--out", filepath.Join(dir, "starter"), "--verbose", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(stdout.Bytes()) || !strings.Contains(stderr.String(), "inspected 1/1") || strings.Contains(stdout.String(), "[policy-init]") {
		t.Fatalf("machine output/progress mixed: stdout=%s stderr=%s", &stdout, &stderr)
	}
}

func TestPolicyInitPublishesOneCompletePair(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "policy")
	const writers = 8
	done := make(chan error, writers)
	type pair struct{ policy, trust []byte }
	var expected []pair
	for i := range writers {
		s := estateverify.PolicySuggestion{Images: i + 1, Required: []string{},
			UnverifiedSigners: []estateverify.UnverifiedSigner{{Format: estateverify.FormatBundle,
				Signer: report.Signer{Identity: fmt.Sprintf("https://example.test/workflow-%d", i), Issuer: "https://issuer.test"}}}}
		p, tr, err := estateverify.RenderPolicySuggestion(s)
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, pair{p, tr})
		go func() { done <- publishPolicyStarter(context.Background(), dest, s) }()
	}
	succeeded := 0
	for range writers {
		if err := <-done; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d concurrent initializers published", succeeded)
	}
	p, _ := os.ReadFile(filepath.Join(dest, "policy.yaml"))
	tr, _ := os.ReadFile(filepath.Join(dest, "trust-policy.yaml"))
	matched := false
	for _, want := range expected {
		matched = matched || bytes.Equal(p, want.policy) && bytes.Equal(tr, want.trust)
	}
	if !matched {
		t.Fatal("published files came from different initializers")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != "policy" {
		t.Fatalf("staging files left behind: %v (%v)", entries, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := filepath.Join(parent, "cancelled", "policy")
	if err := publishPolicyStarter(ctx, cancelled, estateverify.PolicySuggestion{Images: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled initializer: %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(cancelled)); !os.IsNotExist(err) {
		t.Fatalf("cancelled initializer published files: %v", err)
	}
}
