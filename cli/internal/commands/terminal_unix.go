//go:build darwin || linux

package commands

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	return err == nil
}
