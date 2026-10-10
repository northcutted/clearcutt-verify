package estateverify

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// FactoryReproducer reproduces clearcutt-factory images with
// `clearcutt-factory verify --image`, which rebuilds an image from its signed
// recipe without cache (or repeats a signed rebase) and compares digests.
type FactoryReproducer struct {
	// Binary is the clearcutt-factory binary (default "clearcutt-factory").
	Binary string
	// Dir is where clearcutt-factory works; it writes build contexts and
	// logs under ./out. The default is a new directory per image under the
	// user cache directory, which container VMs on macOS share (they don't
	// share /tmp). It is removed when the image reproduces and kept, for
	// its logs, when it doesn't.
	Dir string
	// Run executes it in dir and returns its combined output; tests replace
	// it.
	Run func(ctx context.Context, dir, bin string, args ...string) ([]byte, error)
}

var reproducedRE = regexp.MustCompile(`(?:rebuilt|rebase gives) (sha256:[0-9a-f]{64})`)

// Reproduce returns the digest the rebuild produced.
func (f FactoryReproducer) Reproduce(ctx context.Context, ref string, signer report.Signer) (string, error) {
	bin := f.Binary
	if bin == "" {
		bin = "clearcutt-factory"
	}
	flags, err := signerFlags(signer)
	if err != nil {
		return "", err
	}
	args := append([]string{"verify", "--image", ref}, flags...)
	if repo := signer.SourceRepository; repo != "" {
		args = append(args, "--certificate-github-workflow-repository", strings.TrimPrefix(repo, "https://github.com/"))
	}
	dir := f.Dir
	if dir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base := filepath.Join(cache, "clearcutt-verify", "reproduce")
		if err := os.MkdirAll(base, 0o755); err != nil {
			return "", err
		}
		if dir, err = os.MkdirTemp(base, "image-"); err != nil {
			return "", err
		}
	}
	run := f.Run
	if run == nil {
		run = func(ctx context.Context, dir, bin string, args ...string) ([]byte, error) {
			var out bytes.Buffer
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &out, &out
			err := cmd.Run()
			return out.Bytes(), err
		}
	}
	out, err := run(ctx, dir, bin, args...)
	m := reproducedRE.FindSubmatch(out)
	switch {
	case m == nil && err != nil:
		return "", fmt.Errorf("clearcutt-factory verify: %v: %s (in %s)", err, lastLine(string(out)), dir)
	case m == nil:
		return "", fmt.Errorf("clearcutt-factory verify gave no digest: %s (in %s)", lastLine(string(out)), dir)
	case err == nil && f.Dir == "":
		_ = os.RemoveAll(dir)
	}
	return string(m[1]), nil
}
