package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// SchemaBaseURL is where the published contract schemas live.
const SchemaBaseURL = "https://raw.githubusercontent.com/northcutted/clearcutt-verify/main/contract/"

// SchemaFile is one generated schema.
type SchemaFile struct {
	Name    string
	Content []byte
}

// Schemas generates the contract's JSON Schemas from the report types, with
// their doc comments (read from the Go source in srcDir) as descriptions.
func Schemas(srcDir string) ([]SchemaFile, error) {
	docs, err := comments(srcDir)
	if err != nil {
		return nil, err
	}
	g := &schemaGen{docs: docs, defs: map[string]any{}}
	var out []SchemaFile
	for _, s := range []struct {
		file, kind, title string
		typ               reflect.Type
	}{
		{"estate-report.v1.schema.json", KindReport, "ClearCutt estate report", reflect.TypeOf(Report{})},
		{"estate-history.v1.schema.json", KindHistory, "ClearCutt estate history", reflect.TypeOf(History{})},
		{"trust-policy.v1.schema.json", KindTrustPolicy, "ClearCutt trust policy", reflect.TypeOf(TrustPolicy{})},
	} {
		g.defs = map[string]any{}
		root := g.object(s.typ)
		props := root["properties"].(map[string]any)
		props["apiVersion"] = map[string]any{"const": APIVersion, "description": "Always " + APIVersion + "."}
		props["kind"] = map[string]any{"const": s.kind, "description": "Always " + s.kind + "."}
		doc := map[string]any{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"$id":     SchemaBaseURL + s.file,
			"title":   s.title,
			"$defs":   g.defs,
		}
		for k, v := range root {
			doc[k] = v
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(doc); err != nil {
			return nil, err
		}
		out = append(out, SchemaFile{Name: s.file, Content: buf.Bytes()})
	}
	return out, nil
}

type schemaGen struct {
	docs map[string]string // "Type" or "Type.Field" → doc comment
	defs map[string]any
}

func (g *schemaGen) schema(t reflect.Type) map[string]any {
	switch t.Kind() {
	case reflect.Pointer:
		return g.schema(t.Elem())
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": g.schema(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.schema(t.Elem())}
	case reflect.Struct:
		// Named structs become shared definitions.
		if _, ok := g.defs[t.Name()]; !ok {
			g.defs[t.Name()] = nil // reserve against recursion
			g.defs[t.Name()] = g.object(t)
		}
		return map[string]any{"$ref": "#/$defs/" + t.Name()}
	}
	panic(fmt.Sprintf("schema: unsupported type %s", t))
}

func (g *schemaGen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		s := g.schema(f.Type)
		if enum := f.Tag.Get("enum"); enum != "" {
			values := strings.Split(enum, ",")
			if s["type"] == "array" {
				s["items"] = map[string]any{"enum": values}
			} else {
				s = map[string]any{"enum": values}
			}
		}
		if d := g.docs[t.Name()+"."+f.Name]; d != "" {
			if _, isRef := s["$ref"]; isRef {
				s = map[string]any{"allOf": []any{s}, "description": d}
			} else {
				s["description"] = d
			}
		}
		props[name] = s
		if !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if d := g.docs[t.Name()]; d != "" {
		o["description"] = d
	}
	sort.Strings(required)
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

// comments reads type and field doc comments from the Go files in dir.
func comments(dir string) (map[string]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	out := map[string]string{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts := spec.(*ast.TypeSpec)
				doc := ts.Doc
				if doc == nil {
					doc = gd.Doc
				}
				out[ts.Name.Name] = text(doc)
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					d := text(field.Doc)
					if d == "" {
						d = text(field.Comment)
					}
					for _, n := range field.Names {
						out[ts.Name.Name+"."+n.Name] = d
					}
				}
			}
		}
	}
	return out, nil
}

func text(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	return strings.Join(strings.Fields(g.Text()), " ")
}
