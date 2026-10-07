package commands

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/northcutted/clearcutt-verify/internal/config"
)

func TestCurrentDocsAndSiteAvoidStaleReleaseAndPrimaryForkTagline(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	scanRoots := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "docs"),
		filepath.Join(root, "site", "src"),
	}
	for _, scanRoot := range scanRoots {
		err := filepath.WalkDir(scanRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				rel, relErr := filepath.Rel(root, path)
				if relErr == nil && strings.HasPrefix(filepath.ToSlash(rel), "docs/analysis") {
					return filepath.SkipDir
				}
				return nil
			}
			if !isCurrentDocsOrSiteTextFile(path) {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			body := string(raw)
			if strings.Contains(body, "v0.17.0") {
				t.Fatalf("%s contains stale hardcoded release tag v0.17.0", path)
			}
			if strings.Contains(body, "The forkable platform kit and reference implementation") {
				t.Fatalf("%s reintroduces the old primary README tagline", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func isCurrentDocsOrSiteTextFile(path string) bool {
	switch filepath.Ext(path) {
	case ".md", ".mdx", ".astro", ".ts", ".tsx":
		return true
	default:
		return false
	}
}

// TestDocsDoNotClaimRuntimeLinesTheFleetDoesNotBuild guards a drift class this
// repo has now hit twice: prose that names concrete runtime lines, left behind
// when the fleet moved.
//
// Before the fleet narrowed to one line, six docs still advertised "four LTS
// runtime lines — java21, node22, python3.14 and go1.26". Three of those four
// versions had already been superseded by java25/node24/go1.27 in an earlier
// change, so the docs were describing a fleet that had not existed for some
// time. Nothing caught it, because prose compiles.
//
// The rule is narrow on purpose: a doc may name any line the RECIPE LIBRARY
// offers, since documenting what a fork can enable is the point. What it may
// not do is present a line as one this fleet publishes when the compiled matrix
// does not build it.
func TestDocsDoNotClaimRuntimeLinesTheFleetDoesNotBuild(t *testing.T) {
	root, ok := findRepoRoot()
	if !ok {
		t.Skip("repo root not found")
	}
	cfg, err := loadConfigForDrift(root)
	if err != nil {
		t.Skipf("fleet config unreadable: %v", err)
	}
	built := map[string]bool{}
	for _, line := range cfg.Matrix.Languages {
		built[line] = true
	}

	// Phrases that assert publication rather than availability. Each is checked
	// against the same line on which it appears.
	claims := []string{
		"lines the project publishes",
		"lines it publishes",
		"runtime lines the project publishes",
		"the fleet builds",
		"reference fleet builds",
	}

	for _, rel := range []string{"README.md", "docs/alternatives.md", "docs/cli-reference.md",
		"docs/app-lifecycle.md", "docs/concepts/mental-model.md"} {
		path := filepath.Join(root, rel)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			lower := strings.ToLower(line)
			var claimed bool
			for _, claim := range claims {
				if strings.Contains(lower, claim) {
					claimed = true
					break
				}
			}
			if !claimed {
				continue
			}
			for _, candidate := range knownRuntimeLineTokens {
				if !strings.Contains(line, candidate) || built[candidate] {
					continue
				}
				t.Errorf("%s:%d claims the fleet publishes %q, but the compiled matrix builds only %v:\n  %s",
					rel, i+1, candidate, cfg.Matrix.Languages, strings.TrimSpace(line))
			}
		}
	}
}

// knownRuntimeLineTokens are the line ids the registry can compile. A doc may
// mention any of them; it may not claim the fleet publishes one it does not
// build.
var knownRuntimeLineTokens = []string{
	"java21", "java25",
	"node22", "node24", "node26",
	"python3.13", "python3.14",
	"go1.25", "go1.26", "go1.27",
}

// loadConfigForDrift reads the repo's own fleet config.
func loadConfigForDrift(root string) (config.Config, error) {
	return config.Load(filepath.Join(root, config.DefaultConfigPath))
}

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
	invocation := regexp.MustCompile(`clearcutt ((?:[a-z][a-z-]*(?: |$)){1,4})`)
	looksLikeSubcommand := regexp.MustCompile(`^[a-z][a-z-]*$`)

	for _, rel := range []string{
		"docs/registry-native-evidence.md",
		"docs/registry-graph.md",
		"docs/cli-reference.md",
	} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		for _, match := range invocation.FindAllStringSubmatch(string(raw), -1) {
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
						t.Errorf("%s documents `clearcutt %s`, but %q is not a subcommand of `%s`",
							rel, strings.TrimSpace(match[1]), token, strings.Join(walked, " "))
					}
					break
				}
				cursor = next
				walked = append(walked, token)
			}
			if len(walked) == 0 {
				t.Errorf("%s documents `clearcutt %s`, whose first word is not a command",
					rel, strings.TrimSpace(match[1]))
			}
		}
	}
}
