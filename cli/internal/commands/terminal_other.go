//go:build !darwin && !linux

package commands

import "io"

func isTerminal(io.Writer) bool { return false }
