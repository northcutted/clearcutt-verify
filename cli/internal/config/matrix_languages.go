package config

import (
	"encoding/json"
	"fmt"

	"github.com/northcutted/clearcutt-verify/internal/versionpolicy"
)

// LanguageSelector is the language-level form of a matrix.languages entry: a
// language plus a release channel (lts/current/preview/experimental), resolved
// to concrete runtime lines through the shared version policy. It lets a fleet
// declare intent ("java at LTS") instead of pinning every line id.
type LanguageSelector struct {
	Language string `json:"language"`
	Channel  string `json:"channel"`
}

// UnmarshalJSON accepts matrix.languages in either form: the legacy flat list of
// runtime line ids (["coreLTS","java21",...]) or the language-level form
// ([{language: java, channel: lts}, ...]). Field-merge semantics are preserved
// — keys absent from the document keep their existing/default values — and the
// language-level form is resolved into the concrete line list using the
// persistent preview setting. (sigs.k8s.io/yaml routes YAML through JSON, so
// this one hook covers both formats.)
func (m *Matrix) UnmarshalJSON(data []byte) error {
	var aux struct {
		Systems   *[]string       `json:"systems"`
		Tiers     *[]string       `json:"tiers"`
		Preview   *bool           `json:"preview"`
		Languages json.RawMessage `json:"languages"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Systems != nil {
		m.Systems = *aux.Systems
	}
	if aux.Tiers != nil {
		m.Tiers = *aux.Tiers
	}
	if aux.Preview != nil {
		m.Preview = *aux.Preview
	}
	if len(aux.Languages) == 0 {
		return nil
	}

	// Legacy form: a flat list of runtime line ids.
	var lines []string
	if err := json.Unmarshal(aux.Languages, &lines); err == nil {
		m.Languages = lines
		m.LanguageSelectors = nil
		return nil
	}

	// Language-level form: {language, channel} selectors.
	var selectors []LanguageSelector
	if err := json.Unmarshal(aux.Languages, &selectors); err != nil {
		return fmt.Errorf("matrix.languages must be a list of runtime line ids or {language, channel} objects: %w", err)
	}
	resolved, err := resolveSelectors(selectors, m.Preview)
	if err != nil {
		return err
	}
	m.LanguageSelectors = selectors
	m.Languages = resolved
	return nil
}

// MarshalJSON writes matrix.languages back in its original form: the selector
// objects when the language-level form is in use, else the flat line list, so
// `clearcutt-verify matrix add/remove` and other config round-trips stay lossless.
func (m Matrix) MarshalJSON() ([]byte, error) {
	type matrixOut struct {
		Systems   []string        `json:"systems"`
		Languages json.RawMessage `json:"languages"`
		Tiers     []string        `json:"tiers"`
		Preview   bool            `json:"preview,omitempty"`
	}
	var (
		langJSON []byte
		err      error
	)
	if len(m.LanguageSelectors) > 0 {
		langJSON, err = json.Marshal(m.LanguageSelectors)
	} else {
		langJSON, err = json.Marshal(m.Languages)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(matrixOut{
		Systems:   m.Systems,
		Languages: langJSON,
		Tiers:     m.Tiers,
		Preview:   m.Preview,
	})
}

// ResolveRuntimeLines returns the concrete runtime line ids for the matrix.
// For the language-level form it re-resolves when includePreview (from
// --allow-preview) overrides the persistent preview setting; the legacy explicit
// form ignores includePreview because its lines are already pinned.
func (m Matrix) ResolveRuntimeLines(includePreview bool) ([]string, error) {
	if len(m.LanguageSelectors) == 0 {
		return m.Languages, nil
	}
	return resolveSelectors(m.LanguageSelectors, m.Preview || includePreview)
}

func resolveSelectors(selectors []LanguageSelector, includePreview bool) ([]string, error) {
	lines := []string{}
	seen := map[string]bool{}
	for _, sel := range selectors {
		versions, err := versionpolicy.Resolve(sel.Language, sel.Channel, includePreview)
		if err != nil {
			return nil, err
		}
		for _, v := range versions {
			line := sel.Language + v
			if !seen[line] {
				seen[line] = true
				lines = append(lines, line)
			}
		}
	}
	return lines, nil
}
