//go:build darwin || linux

package estateverify

import (
	"os"

	"golang.org/x/sys/unix"
)

func openVerificationPath(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
}
