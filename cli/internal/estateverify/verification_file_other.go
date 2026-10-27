//go:build !darwin && !linux

package estateverify

import "os"

func openVerificationPath(path string) (*os.File, error) { return os.Open(path) }
