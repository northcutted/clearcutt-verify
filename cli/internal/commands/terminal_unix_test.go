//go:build darwin || linux

package commands

import (
	"os"
	"testing"
)

func TestProgressOnTerminal(t *testing.T) {
	pty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("no controlling terminal: %v", err)
	}
	defer pty.Close()
	old := GlobalOpts
	t.Cleanup(func() { GlobalOpts = old })
	GlobalOpts = GlobalOptions{}
	if !progressOutput(pty) {
		t.Fatal("terminal progress is not enabled by default")
	}
	GlobalOpts.Quiet = true
	if progressOutput(pty) {
		t.Fatal("quiet did not suppress terminal progress")
	}
}
