package commands

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/output"
)

// ErrCheckFailed is the sentinel policy error returned by gating commands
// (verify, certify, conformance, exceptions validate, and the other check-list
// gates) when one or more policy checks fail. main maps it to process exit
// code 2 without printing a redundant "Error:" line, since the command has
// already rendered a detailed report. All other errors are operational
// (bad flags, IO, missing catalog) and exit 1.
var ErrCheckFailed = errors.New("one or more checks failed")

// out and errOut are the writers used for all command output. They default to
// the process stdio but are swapped in tests to capture output, which keeps the
// commands testable without threading a writer through every function.
var (
	out    io.Writer = os.Stdout
	errOut io.Writer = os.Stderr
)

// structuredFormat reports whether the global --format selects a structured
// machine-readable output (json or yaml/yml) instead of the default human form.
func structuredFormat() bool {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json", "yaml", "yml":
		return true
	default:
		return false
	}
}

// printStructured emits payload on stdout in the structured format selected by
// the global --format flag. It mirrors the json/yaml branches used by
// `verify image` and `platform status`: data goes to stdout, human commentary
// stays on stderr. Callers must only invoke it when structuredFormat() is true.
func printStructured(payload any) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, payload)
	case "yaml", "yml":
		return output.PrintYAML(out, payload)
	default:
		return errors.New("printStructured called without a structured --format")
	}
}
