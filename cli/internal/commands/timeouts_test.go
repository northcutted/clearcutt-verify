package commands

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTimeoutFlagsRejectZeroAndNegative(t *testing.T) {
	for _, tc := range []struct {
		args []string
		flag string
	}{
		{[]string{"estate", "verify"}, "registry-timeout"},
		{[]string{"estate", "verify"}, "cosign-timeout"},
		{[]string{"estate", "verify"}, "reproduce-timeout"},
		{[]string{"estate", "verify"}, "grype-timeout"},
		{[]string{"estate", "verify"}, "notation-timeout"},
		{[]string{"registry", "scan", "--output", "unused"}, "github-timeout"},
	} {
		for _, limit := range []string{"0", "-1s"} {
			_, err := runCLI(t, append(tc.args, "--"+tc.flag+"="+limit)...)
			if err == nil || !strings.Contains(err.Error(), "--"+tc.flag+" must be greater than zero") {
				t.Errorf("%s=%s accepted: %v", tc.flag, limit, err)
			}
		}
	}
}

func TestInitializationTimeoutPublishesNoReport(t *testing.T) {
	for _, env := range []string{"SIGSTORE_ROOT_FILE", "SIGSTORE_REKOR_PUBLIC_KEY", "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", "SIGSTORE_TSA_CERTIFICATE_FILE", "GRYPE_DB_AUTO_UPDATE"} {
		t.Setenv(env, "")
	}
	for _, stage := range []string{"cosign version", "cosign initialize", "grype version", "grype db"} {
		t.Run(stage, func(t *testing.T) {
			oldCosign, oldGrype := cosignRunner, grypeRunner
			t.Cleanup(func() { cosignRunner, grypeRunner = oldCosign, oldGrype })
			cosignRunner = func(ctx context.Context, _ string, args ...string) ([]byte, error) {
				if stage == "cosign "+args[0] {
					<-ctx.Done()
					return nil, errors.New("signal: killed")
				}
				if args[0] == "version" {
					return []byte(`{"gitVersion":"v3.1.4"}`), nil
				}
				return nil, nil
			}
			grypeRunner = func(ctx context.Context, _, _ string, args ...string) ([]byte, []byte, error) {
				if stage == "grype "+args[0] {
					<-ctx.Done()
					return nil, nil, nil
				}
				return []byte(`{"version":"0.120.1"}`), nil, nil
			}
			out := filepath.Join(t.TempDir(), "estate")
			args := []string{"estate", "verify", "--refs", "not-read-before-preflight", "--out", out,
				"--cosign-timeout", "1ms", "--grype-timeout", "1ms"}
			if strings.HasPrefix(stage, "cosign") {
				args = append(args, "--trusted-identity-regexp", `^https://github\.com/acme/`, "--trusted-issuer", "https://token.actions.githubusercontent.com")
			} else {
				args = append(args, "--rescan")
			}
			_, err := runCLI(t, args...)
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrCheckFailed) || !strings.Contains(err.Error(), stage) {
				t.Fatalf("preflight timeout not an operational error: %v", err)
			}
			if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preflight failure published output: %v", err)
			}
		})
	}
}
