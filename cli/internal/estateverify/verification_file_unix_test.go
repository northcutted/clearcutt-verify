//go:build darwin || linux

package estateverify

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestVerificationCacheRefusesFIFOWithoutBlocking(t *testing.T) {
	for _, read := range []struct {
		name string
		run  func(string) error
	}{
		{"trust", func(path string) error { _, err := localTrustFile(path); return err }},
		{"executable", func(path string) error { _, err := executableHash(path); return err }},
	} {
		t.Run(read.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fifo")
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- read.run(path) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("accepted a FIFO as a trust/executable file")
				}
			case <-time.After(time.Second):
				// Release an old blocking implementation before failing.
				if fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
					_ = unix.Close(fd)
				}
				t.Fatal("cache input escaped the timeout by blocking in open")
			}
		})
	}
}
