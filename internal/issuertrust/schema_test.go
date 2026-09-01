package issuertrust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// The published schema is what an independent publisher implements against.
// These tests keep it and the Go verifier from drifting apart, and run real
// signed lists through the constraints it states.

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

func schema(t *testing.T) constraint {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "issuer-trust-list-v1.schema.json"))
	if err != nil {
		t.Fatalf("read trust list schema: %v", err)
	}
	var document constraint
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode trust list schema: %v", err)
	}
	return document
}

func validate(node constraint, value any, path string) error {
	if node.Const != nil && !equalJSON(node.Const, value) {
		return fmt.Errorf("%s: expected const %v", path, node.Const)
	}
	if len(node.Enum) > 0 {
		matched := false
		for _, candidate := range node.Enum {
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
		for _, name := range node.Required {
			if _, present := typed[name]; !present {
				return fmt.Errorf("%s: missing required field %s", path, name)
			}
		}
		for name, field := range typed {
			child, known := node.Properties[name]
			if !known {
				if node.AdditionalProperties != nil && !*node.AdditionalProperties {
					return fmt.Errorf("%s: unknown field %s", path, name)
				}
				continue
			}
			if err := validate(child, field, path+"."+name); err != nil {
				return err
			}
		}
	case []any:
		if node.MinItems != nil && len(typed) < *node.MinItems {
			return fmt.Errorf("%s: too few items", path)
		}
		if node.MaxItems != nil && len(typed) > *node.MaxItems {
			return fmt.Errorf("%s: too many items", path)
		}
		seen := map[string]struct{}{}
		for index, item := range typed {
			if node.Items != nil {
				if err := validate(*node.Items, item, fmt.Sprintf("%s[%d]", path, index)); err != nil {
					return err
				}
			}
			if node.UniqueItems {
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
	case string:
		if node.MinLength != nil && len(typed) < *node.MinLength {
			return fmt.Errorf("%s: too short", path)
		}
		if node.MaxLength != nil && len(typed) > *node.MaxLength {
			return fmt.Errorf("%s: too long", path)
		}
		if node.Pattern != "" {
			expression, err := regexp.Compile(node.Pattern)
			if err != nil {
				return fmt.Errorf("%s: unusable pattern", path)
			}
			if !expression.MatchString(typed) {
				return fmt.Errorf("%s: %q does not match %s", path, typed, node.Pattern)
			}
		}
		if node.Format == "date-time" {
			parsed, err := time.Parse(time.RFC3339, typed)
			if err != nil || parsed.Format(time.RFC3339) != typed {
				return fmt.Errorf("%s: %q is not an RFC 3339 timestamp", path, typed)
			}
		}
	case float64:
		if node.Minimum != nil && typed < *node.Minimum {
			return fmt.Errorf("%s: below the minimum", path)
		}
		if node.Maximum != nil && typed > *node.Maximum {
			return fmt.Errorf("%s: above the maximum", path)
		}
	case bool, nil:
		return fmt.Errorf("%s: unexpected %v", path, value)
	}
	return nil
}

func equalJSON(left, right any) bool {
	first, firstErr := json.Marshal(left)
	second, secondErr := json.Marshal(right)
	return firstErr == nil && secondErr == nil && string(first) == string(second)
}

func TestSignedTrustListsSatisfyThePublishedSchema(t *testing.T) {
	document := schema(t)
	_, private := keyPair(t, 20)

	lists := map[string]Payload{
		"empty":            payload(1, time.Hour, nil, nil),
		"one issuer":       payload(2, time.Hour, []Issuer{presenceIssuer()}, nil),
		"with revocations": payload(3, MaximumLifetime, []Issuer{presenceIssuer()}, []string{commitment(11), commitment(12)}),
	}
	for name, list := range lists {
		encoded, err := Sign(list, private)
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if err := validate(document, decoded, "trust_list"); err != nil {
			t.Fatalf("%s: signed list violates the published schema: %v", name, err)
		}
	}
}

func TestSchemaVocabularyMatchesTheVerifier(t *testing.T) {
	payloadNode := schema(t).Properties["payload"]
	if payloadNode.Properties["schema_version"].Const != SchemaVersion {
		t.Fatal("schema and Go disagree about the contract version")
	}
	issuer := payloadNode.Properties["issuers"].Items

	gotScopes := enumStrings(t, issuer.Properties["uniqueness_scope"].Enum)
	if !reflect.DeepEqual(gotScopes, sortedKeys(uniquenessScopes)) {
		t.Fatalf("schema uniqueness scopes %v do not match the verifier %v", gotScopes, sortedKeys(uniquenessScopes))
	}
	gotPurposes := enumStrings(t, issuer.Properties["purpose"].Enum)
	if !reflect.DeepEqual(gotPurposes, sortedKeys(purposes)) {
		t.Fatalf("schema purposes %v do not match the verifier %v", gotPurposes, sortedKeys(purposes))
	}
	if got, want := *payloadNode.Properties["issuers"].MaxItems, maximumIssuers; got != want {
		t.Fatalf("schema issuer cap %d does not match the verifier %d", got, want)
	}
	if got, want := *payloadNode.Properties["revoked_credentials"].MaxItems, maximumRevoked; got != want {
		t.Fatalf("schema revocation cap %d does not match the verifier %d", got, want)
	}

	// Global personhood must stay absent from the published vocabulary.
	for _, scope := range gotScopes {
		if strings.Contains(scope, "global") || strings.Contains(scope, "world") {
			t.Fatalf("the schema offers a global uniqueness scope: %s", scope)
		}
	}
}

func TestSchemaIsClosed(t *testing.T) {
	document := schema(t)
	payloadNode := document.Properties["payload"]
	issuer := payloadNode.Properties["issuers"].Items
	for name, node := range map[string]constraint{"document": document, "payload": payloadNode, "issuer": *issuer} {
		if node.AdditionalProperties == nil || *node.AdditionalProperties {
			t.Fatalf("%s object is not closed", name)
		}
		if len(node.Required) != len(node.Properties) {
			t.Fatalf("%s has optional fields", name)
		}
	}
	if got, want := jsonFieldNames(Payload{}), sortedProperties(payloadNode); !reflect.DeepEqual(got, want) {
		t.Fatalf("Go payload fields %v do not match schema fields %v", got, want)
	}
	if got, want := jsonFieldNames(Issuer{}), sortedProperties(*issuer); !reflect.DeepEqual(got, want) {
		t.Fatalf("Go issuer fields %v do not match schema fields %v", got, want)
	}
}

func TestSchemaRejectsWhatTheVerifierRejects(t *testing.T) {
	document := schema(t)
	public, private := keyPair(t, 21)
	store := newStore(t, public)
	encoded, err := Sign(payload(1, time.Hour, []Issuer{presenceIssuer()}, nil), private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"global uniqueness scope": func(root map[string]any) {
			issuers := root["payload"].(map[string]any)["issuers"].([]any)
			issuers[0].(map[string]any)["uniqueness_scope"] = "global"
		},
		"level above the ladder": func(root map[string]any) {
			issuers := root["payload"].(map[string]any)["issuers"].([]any)
			issuers[0].(map[string]any)["maximum_assurance_level"] = float64(9)
		},
		"subject field": func(root map[string]any) {
			root["payload"].(map[string]any)["subject"] = "person"
		},
		"malformed key": func(root map[string]any) {
			issuers := root["payload"].(map[string]any)["issuers"].([]any)
			issuers[0].(map[string]any)["public_key"] = "short"
		},
	} {
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		mutate(decoded)
		if err := validate(document, decoded, "trust_list"); err == nil {
			t.Fatalf("%s: the published schema accepted an invalid list", name)
		}
		mutated, err := json.Marshal(decoded)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := store.Update(mutated, now); err == nil {
			t.Fatalf("%s: the verifier accepted an invalid list", name)
		}
	}
}

func jsonFieldNames(value any) []string {
	structType := reflect.TypeOf(value)
	names := make([]string, 0, structType.NumField())
	for index := 0; index < structType.NumField(); index++ {
		names = append(names, strings.Split(structType.Field(index).Tag.Get("json"), ",")[0])
	}
	sort.Strings(names)
	return names
}

func sortedProperties(node constraint) []string {
	names := make([]string, 0, len(node.Properties))
	for name := range node.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedKeys(values map[string]struct{}) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func enumStrings(t *testing.T, values []any) []string {
	t.Helper()
	names := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("non-string enum value %v", value)
		}
		names = append(names, text)
	}
	sort.Strings(names)
	return names
}
