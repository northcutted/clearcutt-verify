package commands

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestDocumentedCommandsExist guards prose that shows a command line. Docs are
// where an operator learns the surface, and a command that was renamed or never
// existed reads exactly like one that works — until they run it.
//
// The walk descends the real command tree token by token. It stops without
// complaint at the first token that cannot be a subcommand — a registry
// reference or a flag — but if the command reached so far HAS subcommands and
// the next token looks like one and is not, that is drift and it fails.
//
// An earlier version trimmed trailing tokens until something matched, which
// meant `clearcutt evidence backup` silently "resolved" to `evidence`. Falling
// back to the parent makes the test unable to fail.
func TestDocumentedCommandsExist(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	invocation := regexp.MustCompile(`clearcutt-verify ((?:[a-z][a-z-]*(?: |$)){1,4})`)
	looksLikeSubcommand := regexp.MustCompile(`^[a-z][a-z-]*$`)

	docs, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	docs = append(docs, filepath.Join(root, "README.md"), filepath.Join(root, "contract", "README.md"))
	for _, path := range docs {
		rel, _ := filepath.Rel(root, path)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, match := range invocation.FindAllStringSubmatch(codeOf(string(raw)), -1) {
			cursor := NewRootCmd()
			walked := []string{}
			for _, token := range strings.Fields(match[1]) {
				if !looksLikeSubcommand.MatchString(token) {
					break
				}
				var next *cobra.Command
				for _, candidate := range cursor.Commands() {
					if candidate.Name() == token {
						next = candidate
						break
					}
				}
				if next == nil {
					// Only a failure if we were standing on a command group.
					// Otherwise the token is an argument, not a subcommand.
					if cursor.HasSubCommands() && len(walked) > 0 {
						t.Errorf("%s documents `clearcutt-verify %s`, but %q is not a subcommand of `%s`",
							rel, strings.TrimSpace(match[1]), token, strings.Join(walked, " "))
					}
					break
				}
				cursor = next
				walked = append(walked, token)
			}
			if len(walked) == 0 {
				t.Errorf("%s documents `clearcutt-verify %s`, whose first word is not a command",
					rel, strings.TrimSpace(match[1]))
			}
		}
	}
}

// codeOf returns a Markdown document's code: fenced blocks and inline code
// spans, one per line. Prose that names the tool isn't a command line.
func codeOf(doc string) string {
	var b strings.Builder
	fenced := false
	inline := regexp.MustCompile("`([^`]+)`")
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			b.WriteString(line + "\n")
			continue
		}
		for _, m := range inline.FindAllStringSubmatch(line, -1) {
			b.WriteString(m[1] + "\n")
		}
	}
	return b.String()
}
