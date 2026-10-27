package commands

import "io"

// progressOutput leaves redirected stderr quiet unless verbose was requested.
// Quiet takes precedence, including when stderr is a terminal.
func progressOutput(stderr io.Writer) bool {
	return !GlobalOpts.Quiet && (GlobalOpts.Verbose || isTerminal(stderr))
}

func imageProgress(stderr io.Writer, prefix string) func(int, int, string) {
	if !progressOutput(stderr) {
		return nil
	}
	return func(completed, total int, ref string) {
		fprintf(stderr, "[%s] inspected %d/%d %q\n", prefix, completed, total, ref)
	}
}
