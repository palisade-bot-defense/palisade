package palisadeassurance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// An empty evidence list and a missing one must never be the same document.
// Go marshals a nil slice as JSON null and decodes null, an absent field and an
// empty array all into the same zero value, so both directions are pinned here.

func TestEmptyEvidenceListsEncodeAsArraysNotNull(t *testing.T) {
	_, private := testKey(t, 11)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	payload := testPayload(t, LevelUnattributed, nil)
	payload.ReasonCodes = nil
	encoded, err := Sign(payload, time.Minute, now, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Contains(string(encoded), "null") {
		t.Fatalf("assertion encoded a null value: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"assurance_sources":[]`) ||
		!strings.Contains(string(encoded), `"reason_codes":[]`) {
		t.Fatalf("empty evidence lists were not encoded as arrays: %s", encoded)
	}
}

func TestVerifyRejectsAbsentAndNullFields(t *testing.T) {
	public, private := testKey(t, 12)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	encoded, err := Sign(testPayload(t, LevelBehavioral, []string{"behavioral"}), time.Minute, now, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := verifier.Verify(encoded, now); err != nil {
		t.Fatalf("a well formed assertion was rejected: %v", err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"null evidence list": func(document map[string]any) {
			document["payload"].(map[string]any)["assurance_sources"] = nil
		},
		"absent evidence list": func(document map[string]any) {
			delete(document["payload"].(map[string]any), "assurance_sources")
		},
		"absent binding": func(document map[string]any) {
			delete(document["payload"].(map[string]any), "binding")
		},
		"absent audience": func(document map[string]any) {
			delete(document["payload"].(map[string]any)["binding"].(map[string]any), "audience")
		},
		"null signature": func(document map[string]any) { document["signature"] = nil },
		"absent key id":  func(document map[string]any) { delete(document, "key_id") },
	} {
		if _, err := verifier.Verify(mutateDocument(t, encoded, mutate), now); err != ErrInvalid {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
}

func TestSignedDocumentCarriesOnlyContractFields(t *testing.T) {
	_, private := testKey(t, 13)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	encoded, err := Sign(testPayload(t, LevelBehavioral, []string{"behavioral"}), time.Minute, now, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	if len(document) != 3 {
		t.Fatalf("document carries unexpected top-level fields: %v", document)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(document["payload"], &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(payload) != 12 {
		t.Fatalf("payload carries unexpected fields: %v", payload)
	}
}
