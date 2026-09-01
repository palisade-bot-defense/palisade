package palisadeassurance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The published JSON Schema is the frozen contract other implementations read.
// These tests keep it and the Go vocabulary from drifting apart, and assert the
// privacy properties that make the assertion safe to hand to a relying service.

type schemaNode struct {
	Const                string                `json:"const"`
	Type                 any                   `json:"type"`
	Enum                 []string              `json:"enum"`
	Minimum              *int                  `json:"minimum"`
	Maximum              *int                  `json:"maximum"`
	Required             []string              `json:"required"`
	AdditionalProperties *bool                 `json:"additionalProperties"`
	Properties           map[string]schemaNode `json:"properties"`
	Items                *schemaNode           `json:"items"`
}

func readSchema(t *testing.T) schemaNode {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "human-assurance-assertion-v1.schema.json"))
	if err != nil {
		t.Fatalf("read assertion schema: %v", err)
	}
	var schema schemaNode
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode assertion schema: %v", err)
	}
	return schema
}

func TestSchemaVocabularyMatchesGoContractExactly(t *testing.T) {
	payload := readSchema(t).Properties["payload"]
	if payload.Properties["schema_version"].Const != SchemaVersion {
		t.Fatal("schema and Go disagree about the contract version")
	}

	for name, want := range map[string][]string{
		"uniqueness_scope": UniquenessScopes(),
		"agent_provenance": AgentProvenances(),
	} {
		if got := payload.Properties[name].Enum; !sameSet(got, want) {
			t.Fatalf("schema %s vocabulary %v does not match Go %v", name, got, want)
		}
	}
	if got := payload.Properties["assurance_sources"].Items.Enum; !sameSet(got, AssuranceSources()) {
		t.Fatalf("schema assurance_sources vocabulary %v does not match Go %v", got, AssuranceSources())
	}

	binding := payload.Properties["binding"]
	if got := binding.Properties["request_action"].Enum; !sameSet(got, requestActions) {
		t.Fatalf("schema request actions %v do not match Go %v", got, requestActions)
	}
	if got := binding.Properties["endpoint_class"].Enum; !sameSet(got, endpointClasses) {
		t.Fatalf("schema endpoint classes %v do not match Go %v", got, endpointClasses)
	}

	level := payload.Properties["assurance_level"]
	if level.Minimum == nil || *level.Minimum != LevelUnattributed {
		t.Fatal("schema assurance floor does not match the Go contract")
	}
	if level.Maximum == nil || *level.Maximum != MaximumSpecifiedLevel {
		t.Fatal("schema assurance ceiling does not match the specified ladder")
	}
}

func TestSchemaIsClosedAndCarriesNoIdentityFields(t *testing.T) {
	schema := readSchema(t)
	payload := schema.Properties["payload"]
	binding := payload.Properties["binding"]

	for name, node := range map[string]schemaNode{"document": schema, "payload": payload, "binding": binding} {
		if node.AdditionalProperties == nil || *node.AdditionalProperties {
			t.Fatalf("%s object is not closed; unknown fields would be ignored", name)
		}
		if len(node.Required) != len(node.Properties) {
			t.Fatalf("%s has optional fields; every assertion field must be explicit", name)
		}
	}

	// An assertion states how much evidence existed, never who the subject is.
	forbidden := []string{
		"subject", "subject_id", "user", "user_id", "account", "email", "name",
		"device_id", "biometric", "template", "ip", "ip_address", "user_agent",
		"session_id", "credential", "issuer_account",
	}
	for _, node := range []schemaNode{payload, binding} {
		for field := range node.Properties {
			for _, banned := range forbidden {
				if field == banned {
					t.Fatalf("assertion schema exposes an identity field: %s", field)
				}
			}
			if strings.Contains(field, "fingerprint") || strings.Contains(field, "biometric") {
				t.Fatalf("assertion schema exposes an identifying field: %s", field)
			}
		}
	}
}

func TestPayloadStructMatchesSchemaFields(t *testing.T) {
	payload := readSchema(t).Properties["payload"]
	if got, want := jsonFieldNames(Payload{}), sortedKeys(payload.Properties); !reflect.DeepEqual(got, want) {
		t.Fatalf("Go payload fields %v do not match schema fields %v", got, want)
	}
	binding := payload.Properties["binding"]
	if got, want := jsonFieldNames(Binding{}), sortedKeys(binding.Properties); !reflect.DeepEqual(got, want) {
		t.Fatalf("Go binding fields %v do not match schema fields %v", got, want)
	}
}

func jsonFieldNames(value any) []string {
	structType := reflect.TypeOf(value)
	names := make([]string, 0, structType.NumField())
	for index := 0; index < structType.NumField(); index++ {
		tag := structType.Field(index).Tag.Get("json")
		names = append(names, strings.Split(tag, ",")[0])
	}
	sort.Strings(names)
	return names
}

func sortedKeys(values map[string]schemaNode) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	first := append([]string(nil), got...)
	second := append([]string(nil), want...)
	sort.Strings(first)
	sort.Strings(second)
	return reflect.DeepEqual(first, second)
}
