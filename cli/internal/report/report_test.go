package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var update = flag.Bool("update", false, "rewrite the contract schemas")

// contractDir is the repository's contract/ directory.
const contractDir = "../../../contract"

// TestContractSchemasCurrent fails when contract/*.schema.json is out of
// date with the types; go test ./internal/report -update regenerates it.
func TestContractSchemasCurrent(t *testing.T) {
	files, err := Schemas(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		path := filepath.Join(contractDir, f.Name)
		if *update {
			if err := os.WriteFile(path, f.Content, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		old, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(old, f.Content) {
			t.Errorf("contract/%s is out of date; run go test ./internal/report -update", f.Name)
		}
	}
}

// TestContractDocuments validates every example and fixture in contract/
// against its schema, and checks the Go types read them without loss.
func TestContractDocuments(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	schemas := map[string]*jsonschema.Schema{}
	for kind, file := range map[string]string{KindReport: "estate-report.v1.schema.json", KindHistory: "estate-history.v1.schema.json", KindTrustPolicy: "trust-policy.v1.schema.json"} {
		s, err := compiler.Compile(filepath.Join(contractDir, file))
		if err != nil {
			t.Fatal(err)
		}
		schemas[kind] = s
	}
	docs, err := filepath.Glob(filepath.Join(contractDir, "*", "*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) == 0 {
		t.Fatal("no contract documents found")
	}
	for _, path := range docs {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var head struct{ Kind string }
		if err := json.Unmarshal(raw, &head); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		schema := schemas[head.Kind]
		if schema == nil {
			t.Errorf("%s: unknown kind %q", path, head.Kind)
			continue
		}
		if err := schema.Validate(inst); err != nil {
			t.Errorf("%s does not match the schema:\n%v", path, err)
		}

		// The types must read the document without unknown fields, and
		// write it back the same (modulo formatting).
		var v any = &Report{}
		switch head.Kind {
		case KindHistory:
			v = &History{}
		case KindTrustPolicy:
			v = &TrustPolicy{}
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		back, _ := json.Marshal(v)
		if !sameJSON(t, raw, back) {
			t.Errorf("%s does not survive a round trip through the Go types", path)
		}
	}
}

func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

func TestSchemaDescribesStatuses(t *testing.T) {
	files, err := Schemas(".")
	if err != nil {
		t.Fatal(err)
	}
	s := string(files[0].Content)
	for _, want := range []string{`"not-applicable"`, `"layer-prefix"`, `"no-recipe"`, "checked against a trusted signer"} {
		if !strings.Contains(s, want) {
			t.Errorf("report schema lacks %s", want)
		}
	}
}
