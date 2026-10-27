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
	"time"

	"github.com/northcutted/clearcutt-verify/internal/operation"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

// FactoryReproducer reproduces clearcutt-factory images with
// `clearcutt-factory verify --image`, which rebuilds an image from its signed
// recipe without cache (or repeats a signed rebase) and compares digests.
type FactoryReproducer struct {
	// Binary is the clearcutt-factory binary (default "clearcutt-factory").
	Binary string
	// Timeout bounds one Factory invocation (default 30m).
	Timeout time.Duration
	// Dir is where clearcutt-factory works; it writes build contexts and
	// logs under ./out. The default is a new directory per image under the
	// user cache directory, which container VMs on macOS share (they don't
	// share /tmp). It is removed when the image reproduces and kept, for
	// its logs, when it doesn't.
	Dir string
	// Run executes it in dir and returns its standard output and error;
	// tests replace it.
	Run func(ctx context.Context, dir, bin string, args ...string) (stdout, stderr []byte, err error)
}

// What clearcutt-factory verify says last: on success, the digest it
// rebuilt (or rebased to), on its standard output; on a mismatch, the
// expected digest and the one it got, as its error. Build logs go to a log
// file, not to either stream, and only these whole lines count.
var (
	reproducedRE    = regexp.MustCompile(`^reproducible: (?:rebuilt (sha256:[0-9a-f]{64}) matches|rebase gives (sha256:[0-9a-f]{64}) again)$`)
	notReproducedRE = regexp.MustCompile(`^error: NOT reproducible: expected (sha256:[0-9a-f]{64}), (?:rebuilt|the rebase gives) (sha256:[0-9a-f]{64})$`)
)

// Reproduce returns the digest the rebuild produced. A rebuild that exits
// non-zero gives a digest only when it says it rebuilt a different one;
// anything else is an error, so a failed rebuild never passes for a
// reproduced one.
func (f FactoryReproducer) Reproduce(ctx context.Context, ref string, signer report.Signer) (string, error) {
	bin := f.Binary
	if bin == "" {
		bin = "clearcutt-factory"
	}
	_, want, _ := strings.Cut(ref, "@")
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
		run = func(ctx context.Context, dir, bin string, args ...string) ([]byte, []byte, error) {
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.WaitDelay = operation.PipeWait
			cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &stdout, &stderr
			err := cmd.Run()
			return stdout.Bytes(), stderr.Bytes(), err
		}
	}
	limit := operation.Limit(f.Timeout, operation.ReproduceTimeout)
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	stdout, stderr, err := run(ctx, dir, bin, args...)
	if ctx.Err() != nil {
		return "", fmt.Errorf("%w (logs in %s)", operation.Result(ctx, "clearcutt-factory verify", limit, err), dir)
	}
	if err == nil {
		m := reproducedRE.FindStringSubmatch(lastLine(string(stdout)))
		if m == nil {
			return "", fmt.Errorf("clearcutt-factory verify gave no digest: %s (in %s)", lastLine(string(stdout)), dir)
		}
		if f.Dir == "" {
			_ = os.RemoveAll(dir)
		}
		return firstNonEmpty(m[1], m[2]), nil
	}
	for _, line := range strings.Split(string(stderr), "\n") {
		if m := notReproducedRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil && m[1] == want && m[2] != want {
			return m[2], nil
		}
	}
	return "", fmt.Errorf("clearcutt-factory verify: %v: %s (in %s)", err, firstLine(firstNonEmpty(errorLine(stderr), lastLine(string(stderr)), lastLine(string(stdout)))), dir)
}

// errorLine is the error clearcutt-factory exited with.
func errorLine(stderr []byte) string {
	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.HasPrefix(line, "error: ") {
			return line
		}
	}
	return ""
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
