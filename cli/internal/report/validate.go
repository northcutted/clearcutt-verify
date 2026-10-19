package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	compileOnce sync.Once
	compiled    map[string]*jsonschema.Schema // kind → schema
	compileErr  error
)

// schemaFiles maps each kind to its schema file in contract/.
var schemaFiles = map[string]string{
	KindReport:      "estate-report.v1.schema.json",
	KindHistory:     "estate-history.v1.schema.json",
	KindTrustPolicy: "trust-policy.v1.schema.json",
}

// Validate checks a document (a Report, History, or TrustPolicy, or its
// JSON) against the contract schema for its kind, the one published in
// contract/: it is generated from these types, so it is compiled into the
// binary. Writers check their output with it before writing, so a report
// that breaks the contract (a null where a list belongs, a value outside an
// enum) is never written.
func Validate(doc any) error {
	raw, ok := doc.([]byte)
	if !ok {
		var err error
		if raw, err = json.Marshal(doc); err != nil {
			return err
		}
	}
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return err
	}
	compileOnce.Do(compileSchemas)
	if compileErr != nil {
		return compileErr
	}
	schema := compiled[head.Kind]
	if schema == nil {
		return fmt.Errorf("no contract schema for kind %q", head.Kind)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if err := schema.Validate(inst); err != nil {
		return fmt.Errorf("it doesn't match contract/%s: %w", schemaFiles[head.Kind], err)
	}
	return nil
}

func compileSchemas() {
	files, err := schemas(nil)
	if err != nil {
		compileErr = err
		return
	}
	c := jsonschema.NewCompiler()
	for _, f := range files {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(f.Content))
		if err != nil {
			compileErr = err
			return
		}
		if err := c.AddResource(SchemaBaseURL+f.Name, doc); err != nil {
			compileErr = err
			return
		}
	}
	compiled = map[string]*jsonschema.Schema{}
	for kind, file := range schemaFiles {
		s, err := c.Compile(SchemaBaseURL + file)
		if err != nil {
			compileErr = err
			return
		}
		compiled[kind] = s
	}
}
