// Package operation bounds external work without changing evidence verdicts.
package operation

import (
	"context"
	"fmt"
	"time"
)

const (
	CosignTimeout    = 2 * time.Minute
	RegistryTimeout  = time.Minute
	GitHubTimeout    = 30 * time.Second
	ReproduceTimeout = 30 * time.Minute
	GrypeTimeout     = 10 * time.Minute
	// PipeWait bounds cleanup when a subprocess's descendants retain its pipes.
	PipeWait = 2 * time.Second
)

// Limit uses the default for zero-valued internal options. CLI durations must
// be positive; a timeout cannot be disabled accidentally with a zero flag.
func Limit(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

// Result preserves cancellation even if a runner returned success or only
// "signal: killed". Call it before interpreting any subprocess output.
func Result(ctx context.Context, label string, limit time.Duration, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s (limit %s): %w", label, limit, ctx.Err())
	}
	return err
}
