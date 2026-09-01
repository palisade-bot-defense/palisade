package shadowanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// Adding a field to a report is easy; noticing that its published schema is
// closed and now rejects the report is not. This test compares the emitted
// field set against the schema's own required list, so a new field fails here
// rather than in a deployment that validates against the contract.

func publishedSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return document
}

func schemaFields(t *testing.T, document map[string]any) []string {
	t.Helper()
	if closed, ok := document["additionalProperties"].(bool); !ok || closed {
		t.Fatal("the published schema is not a closed object")
	}
	properties, ok := document["properties"].(map[string]any)
	if !ok {
		t.Fatal("the published schema declares no properties")
	}
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func encodedFields(t *testing.T, value any) []string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode: %v", err)
	}
	names := make([]string, 0, len(document))
	for name := range document {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestReportFieldsMatchThePublishedSchema(t *testing.T) {
	document := publishedSchema(t, "shadow-analysis-report-v5.schema.json")
	if got, want := document["properties"].(map[string]any)["schema_version"].(map[string]any)["const"], SchemaVersion; got != want {
		t.Fatalf("schema declares version %v, Go emits %v", got, want)
	}
	if got, want := encodedFields(t, Report{}), schemaFields(t, document); !reflect.DeepEqual(got, want) {
		t.Fatalf("report fields do not match the published schema:\n go     %v\n schema %v", got, want)
	}
	// Every field is required, so a reader never has to guess whether an absent
	// field means zero or means unmeasured.
	required := document["required"].([]any)
	if len(required) != len(schemaFields(t, document)) {
		t.Fatalf("the schema has optional fields: %d required of %d", len(required), len(schemaFields(t, document)))
	}
}

func TestAssuranceSliceFieldsMatchThePublishedSchema(t *testing.T) {
	document := publishedSchema(t, "shadow-analysis-report-v5.schema.json")
	definitions, ok := document["$defs"].(map[string]any)
	if !ok {
		t.Fatal("the published schema declares no definitions")
	}
	slice, ok := definitions["assurance_slice"].(map[string]any)
	if !ok {
		t.Fatal("the published schema does not define an assurance slice")
	}
	if got, want := encodedFields(t, AssuranceSlice{}), schemaFields(t, slice); !reflect.DeepEqual(got, want) {
		t.Fatalf("assurance slice fields do not match the published schema:\n go     %v\n schema %v", got, want)
	}

	// Unknown must remain expressible: a decision that was never evaluated for
	// assurance is not the same as one measured at level 0.
	pattern, ok := slice["properties"].(map[string]any)["assurance_level"].(map[string]any)["pattern"].(string)
	if !ok || pattern != "^(unknown|[0-5])$" {
		t.Fatalf("the assurance level vocabulary changed: %v", pattern)
	}
}
