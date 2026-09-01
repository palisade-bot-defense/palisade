package palisadeassurance

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// Vocabulary agreement is not the same as schema conformance. These tests run
// documents this package actually signs through the constraints the published
// schema states, so an independent implementation reading only the schema
// accepts what PALISADE emits. The repository keeps its Python checks free of
// third-party dependencies, so the subset of JSON Schema the contract uses is
// evaluated here instead of pulling in a validator.

type constraint struct {
	Type                 any                   `json:"type"`
	Const                any                   `json:"const"`
	Enum                 []any                 `json:"enum"`
	Minimum              *float64              `json:"minimum"`
	Maximum              *float64              `json:"maximum"`
	MinLength            *int                  `json:"minLength"`
	MaxLength            *int                  `json:"maxLength"`
	Pattern              string                `json:"pattern"`
	Format               string                `json:"format"`
	Required             []string              `json:"required"`
	AdditionalProperties *bool                 `json:"additionalProperties"`
	Properties           map[string]constraint `json:"properties"`
	Items                *constraint           `json:"items"`
	MinItems             *int                  `json:"minItems"`
	MaxItems             *int                  `json:"maxItems"`
	UniqueItems          bool                  `json:"uniqueItems"`
}

func loadConstraints(t *testing.T) constraint {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "human-assurance-assertion-v1.schema.json"))
	if err != nil {
		t.Fatalf("read assertion schema: %v", err)
	}
	var schema constraint
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode assertion schema: %v", err)
	}
	return schema
}

func validate(schema constraint, value any, path string) error {
	if schema.Const != nil && !equalJSON(schema.Const, value) {
		return fmt.Errorf("%s: expected const %v, got %v", path, schema.Const, value)
	}
	if len(schema.Enum) > 0 {
		matched := false
		for _, candidate := range schema.Enum {
			if equalJSON(candidate, value) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: %v is outside the closed vocabulary", path, value)
		}
	}

	switch typed := value.(type) {
	case map[string]any:
		return validateObject(schema, typed, path)
	case []any:
		return validateArray(schema, typed, path)
	case string:
		return validateString(schema, typed, path)
	case float64:
		if schema.Type != nil && schema.Type != "integer" && schema.Type != "number" {
			return fmt.Errorf("%s: unexpected number", path)
		}
		if schema.Type == "integer" && typed != float64(int64(typed)) {
			return fmt.Errorf("%s: expected an integer", path)
		}
		if schema.Minimum != nil && typed < *schema.Minimum {
			return fmt.Errorf("%s: %v is below the minimum", path, typed)
		}
		if schema.Maximum != nil && typed > *schema.Maximum {
			return fmt.Errorf("%s: %v is above the maximum", path, typed)
		}
	default:
		return fmt.Errorf("%s: unsupported value %T", path, value)
	}
	return nil
}

func validateObject(schema constraint, value map[string]any, path string) error {
	if schema.Type != nil && schema.Type != "object" {
		return fmt.Errorf("%s: unexpected object", path)
	}
	for _, name := range schema.Required {
		if _, present := value[name]; !present {
			return fmt.Errorf("%s: missing required field %s", path, name)
		}
	}
	for name, field := range value {
		child, known := schema.Properties[name]
		if !known {
			if schema.AdditionalProperties != nil && !*schema.AdditionalProperties {
				return fmt.Errorf("%s: unknown field %s", path, name)
			}
			continue
		}
		if err := validate(child, field, path+"."+name); err != nil {
			return err
		}
	}
	return nil
}

func validateArray(schema constraint, value []any, path string) error {
	if schema.Type != nil && schema.Type != "array" {
		return fmt.Errorf("%s: unexpected array", path)
	}
	if schema.MinItems != nil && len(value) < *schema.MinItems {
		return fmt.Errorf("%s: too few items", path)
	}
	if schema.MaxItems != nil && len(value) > *schema.MaxItems {
		return fmt.Errorf("%s: too many items", path)
	}
	seen := make(map[string]struct{}, len(value))
	for index, item := range value {
		if schema.Items != nil {
			if err := validate(*schema.Items, item, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		if schema.UniqueItems {
			encoded, err := json.Marshal(item)
			if err != nil {
				return fmt.Errorf("%s: unencodable item", path)
			}
			if _, duplicate := seen[string(encoded)]; duplicate {
				return fmt.Errorf("%s: duplicate item", path)
			}
			seen[string(encoded)] = struct{}{}
		}
	}
	return nil
}

func validateString(schema constraint, value string, path string) error {
	if schema.Type != nil && schema.Type != "string" {
		return fmt.Errorf("%s: unexpected string", path)
	}
	if schema.MinLength != nil && len(value) < *schema.MinLength {
		return fmt.Errorf("%s: shorter than the minimum length", path)
	}
	if schema.MaxLength != nil && len(value) > *schema.MaxLength {
		return fmt.Errorf("%s: longer than the maximum length", path)
	}
	if schema.Pattern != "" {
		expression, err := regexp.Compile(schema.Pattern)
		if err != nil {
			return fmt.Errorf("%s: unusable pattern %q", path, schema.Pattern)
		}
		if !expression.MatchString(value) {
			return fmt.Errorf("%s: %q does not match %s", path, value, schema.Pattern)
		}
	}
	if schema.Format == "date-time" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil || parsed.Format(time.RFC3339) != value {
			return fmt.Errorf("%s: %q is not an RFC 3339 timestamp", path, value)
		}
	}
	return nil
}

func equalJSON(left, right any) bool {
	first, firstErr := json.Marshal(left)
	second, secondErr := json.Marshal(right)
	return firstErr == nil && secondErr == nil && string(first) == string(second)
}

func decodeDocument(t *testing.T, encoded []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	return document
}

func TestSignedAssertionsSatisfyThePublishedSchema(t *testing.T) {
	schema := loadConstraints(t)
	_, private := testKey(t, 9)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	cases := map[string]Payload{
		"unattributed": func() Payload {
			payload := testPayload(t, LevelUnattributed, nil)
			payload.ReasonCodes = nil
			return payload
		}(),
		"behavioral": testPayload(t, LevelBehavioral, []string{"behavioral"}),
		"declared agent": func() Payload {
			payload := testPayload(t, LevelBehavioral, []string{"behavioral"})
			payload.AgentProvenance = "declared"
			payload.ReasonCodes = []string{"verified_browser_events", "declared_agent_identity"}
			return payload
		}(),
	}
	for name, payload := range cases {
		for _, ttl := range []time.Duration{time.Second, MaximumLifetime} {
			encoded, err := Sign(payload, ttl, now, private)
			if err != nil {
				t.Fatalf("%s: sign: %v", name, err)
			}
			if err := validate(schema, decodeDocument(t, encoded), "assertion"); err != nil {
				t.Fatalf("%s: signed assertion violates the published schema: %v", name, err)
			}
		}
	}
}

func TestSchemaValidationRejectsDocumentsTheVerifierRejects(t *testing.T) {
	schema := loadConstraints(t)
	_, private := testKey(t, 10)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	encoded, err := Sign(testPayload(t, LevelBehavioral, []string{"behavioral"}), time.Minute, now, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"identity field added": func(document map[string]any) {
			document["payload"].(map[string]any)["subject_identifier"] = "person"
		},
		"level above the ladder": func(document map[string]any) {
			document["payload"].(map[string]any)["assurance_level"] = float64(9)
		},
		"free text reason code": func(document map[string]any) {
			document["payload"].(map[string]any)["reason_codes"] = []any{"Not A Reason"}
		},
		"unknown evidence class": func(document map[string]any) {
			document["payload"].(map[string]any)["assurance_sources"] = []any{"vibes"}
		},
		"global uniqueness claim": func(document map[string]any) {
			document["payload"].(map[string]any)["uniqueness_scope"] = "global"
		},
		"non-hex key id": func(document map[string]any) {
			document["key_id"] = "ZZZZZZZZZZZZZZZZ"
		},
		"unencoded timestamp": func(document map[string]any) {
			document["payload"].(map[string]any)["issued_at"] = "yesterday"
		},
		"raw endpoint path": func(document map[string]any) {
			document["payload"].(map[string]any)["binding"].(map[string]any)["endpoint_class"] = "/account/settings"
		},
	} {
		document := decodeDocument(t, encoded)
		mutate(document)
		if err := validate(schema, document, "assertion"); err == nil {
			t.Fatalf("%s: the published schema accepted an invalid document", name)
		}
		mutated, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("%s: encode mutated document: %v", name, err)
		}
		public := private.Public().(ed25519.PublicKey)
		verifier, err := NewVerifier(public, testAudience)
		if err != nil {
			t.Fatalf("new verifier: %v", err)
		}
		if _, err := verifier.Verify(mutated, now); err == nil {
			t.Fatalf("%s: the verifier accepted an invalid document", name)
		}
	}
}
