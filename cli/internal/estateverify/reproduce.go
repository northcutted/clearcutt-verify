package estateverify

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"

	"github.com/northcutted/clearcutt/internal/report"
)

// FactoryReproducer reproduces clearcutt-factory images with
// `clearcutt-factory verify --image`, which rebuilds an image from its signed
// recipe without cache (or repeats a signed rebase) and compares digests.
type FactoryReproducer struct {
	// Binary is the clearcutt-factory binary (default "clearcutt-factory").
	Binary string
	// Run executes it and returns its combined output; tests replace it.
	Run func(ctx context.Context, bin string, args ...string) ([]byte, error)
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
	run := f.Run
	if run == nil {
		run = func(ctx context.Context, bin string, args ...string) ([]byte, error) {
			var out bytes.Buffer
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			return out.Bytes(), err
		}
	}
	out, err := run(ctx, bin, args...)
	m := reproducedRE.FindSubmatch(out)
	if m == nil {
		if err != nil {
			return "", fmt.Errorf("clearcutt-factory verify: %v: %s", err, lastLine(string(out)))
		}
		return "", fmt.Errorf("clearcutt-factory verify gave no digest: %s", lastLine(string(out)))
	}
	return string(m[1]), nil
}
