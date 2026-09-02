package palisadeassurance

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Cross-implementation vectors. A second verifier breaks where the canonical
// bytes differ by one character, and no amount of shared prose catches that.
// So this file holds documents this Go implementation actually signed, with
// the public key and evaluation time, and every other implementation must
// accept exactly those and refuse exactly those.
//
// Regenerate with PALISADE_WRITE_VECTORS=1; the ordinary run only checks that
// the committed vectors still verify here, so they cannot drift from Go.

const vectorsPath = "human-assurance-assertion-v2.vectors.json"

type vector struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Audience    string `json:"audience"`
	PublicKey   string `json:"public_key_hex"`
	EvaluateAt  string `json:"evaluate_at"`
	Document    string `json:"document"`
	Expected    string `json:"expected"`
}

type vectorFile struct {
	SchemaVersion string   `json:"schema_version"`
	Contract      string   `json:"contract"`
	SyntheticOnly bool     `json:"synthetic_only"`
	Note          string   `json:"note"`
	Vectors       []vector `json:"vectors"`
}

func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	public, private := testKey(t, 7)
	_, otherPrivate := testKey(t, 8)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	publicHex := hex.EncodeToString(public)

	make := func(id, description string, level int, sources []string, encoded []byte, evaluateAt time.Time, expected string) vector {
		return vector{
			ID: id, Description: description, Audience: testAudience, PublicKey: publicHex,
			EvaluateAt: evaluateAt.Format(time.RFC3339), Document: string(encoded), Expected: expected,
		}
	}

	behavioral := testPayload(t, LevelBehavioral, []string{"behavioral"})
	// forceSign bypasses Sign's normalization, so the empty lists are set to
	// empty slices here: that is the encoding Sign emits, and a null would be
	// the very bug the encoding tests pin.
	unattributed := testPayload(t, LevelUnattributed, []string{})
	unattributed.ReasonCodes = []string{}
	interactive := testPayload(t, LevelInteractive, []string{"behavioral", "challenge"})
	foreignAudience := testPayload(t, LevelBehavioral, []string{"behavioral"})
	foreignAudience.Binding.Audience = "other.example"

	signed := forceSign(t, behavioral, time.Minute, now, private)
	vectors := []vector{
		make("go_signed_behavioral_accepted",
			"A level 1 assertion signed by the Go implementation verifies for its audience one second after issue.",
			LevelBehavioral, []string{"behavioral"}, signed, now.Add(time.Second), "accepted"),
		make("go_signed_unattributed_accepted",
			"A level 0 assertion with empty evidence lists encodes them as arrays and verifies.",
			LevelUnattributed, nil, forceSign(t, unattributed, time.Minute, now, private), now.Add(time.Second), "accepted"),
		make("go_signed_expired",
			"The same document evaluated after its expiry is refused as expired, not invalid.",
			LevelBehavioral, []string{"behavioral"}, signed, now.Add(2*MaximumLifetime), "expired"),
		make("go_signed_future_issued",
			"Evaluated an hour before issue, the document is beyond clock skew and invalid.",
			LevelBehavioral, []string{"behavioral"}, signed, now.Add(-time.Hour), "invalid"),
		make("go_signed_interactive_unsupported",
			"A level 2 document with a valid signature is refused because the level is above the supported ceiling.",
			LevelInteractive, []string{"behavioral", "challenge"}, forceSign(t, interactive, time.Minute, now, private), now.Add(time.Second), "unsupported_level"),
		make("go_signed_foreign_audience",
			"A document minted for another audience does not verify for this one.",
			LevelBehavioral, []string{"behavioral"}, forceSign(t, foreignAudience, time.Minute, now, private), now.Add(time.Second), "invalid"),
		make("go_signed_other_key",
			"A well formed document signed by another key is invalid.",
			LevelBehavioral, []string{"behavioral"}, forceSign(t, behavioral, time.Minute, now, otherPrivate), now.Add(time.Second), "invalid"),
		make("go_signed_foreign_domain",
			"A signature under the local-artifact domain separator must not verify as an assertion.",
			LevelBehavioral, []string{"behavioral"},
			signWithDomain(t, behavioral, time.Minute, now, private, "PALISADE\x00LOCAL-ARTIFACT\x00V1\x00"),
			now.Add(time.Second), "invalid"),
		make("go_signed_tampered_level",
			"Raising the level after signing breaks the signature.",
			LevelBehavioral, []string{"behavioral"},
			mutateDocument(t, signed, func(document map[string]any) {
				document["payload"].(map[string]any)["assurance_level"] = float64(LevelIssuerUnique)
			}), now.Add(time.Second), "invalid"),
		make("go_signed_unknown_field",
			"The document is closed; an added top-level field is refused.",
			LevelBehavioral, []string{"behavioral"},
			mutateDocument(t, signed, func(document map[string]any) { document["subject_identifier"] = "person" }),
			now.Add(time.Second), "invalid"),
		make("go_signed_null_sources",
			"A null evidence list is refused even though Go would decode it to an empty slice.",
			LevelBehavioral, []string{"behavioral"},
			mutateDocument(t, signed, func(document map[string]any) {
				document["payload"].(map[string]any)["assurance_sources"] = nil
			}), now.Add(time.Second), "invalid"),
	}
	return vectorFile{
		SchemaVersion: "palisade.human-assurance-assertion-vectors.v2",
		Contract:      SchemaVersion,
		SyntheticOnly: true,
		Note: "Documents signed by the Go reference implementation with a fixed test key. " +
			"Every implementation must produce the same outcome for each. Regenerate with PALISADE_WRITE_VECTORS=1 go test ./pkg/palisadeassurance.",
		Vectors: vectors,
	}
}

func vectorsFile(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "examples", "conformance", vectorsPath)
}

func TestCrossImplementationVectorsMatchGo(t *testing.T) {
	built := buildVectors(t)
	if os.Getenv("PALISADE_WRITE_VECTORS") == "1" {
		encoded, err := json.MarshalIndent(built, "", "  ")
		if err != nil {
			t.Fatalf("encode vectors: %v", err)
		}
		if err := os.WriteFile(vectorsFile(t), append(encoded, '\n'), 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
	}

	raw, err := os.ReadFile(vectorsFile(t))
	if err != nil {
		t.Fatalf("read vectors (run with PALISADE_WRITE_VECTORS=1 to create them): %v", err)
	}
	var committed vectorFile
	if err := json.Unmarshal(raw, &committed); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if committed.Contract != SchemaVersion || !committed.SyntheticOnly {
		t.Fatalf("vectors do not describe this contract: %+v", committed.Contract)
	}
	if len(committed.Vectors) != len(built.Vectors) {
		t.Fatalf("committed %d vectors, implementation builds %d; regenerate", len(committed.Vectors), len(built.Vectors))
	}

	// Every committed document must still produce its recorded outcome under
	// this implementation. That is what stops the vectors drifting from Go.
	for _, item := range committed.Vectors {
		public, err := hex.DecodeString(item.PublicKey)
		if err != nil {
			t.Fatalf("%s: decode key: %v", item.ID, err)
		}
		verifier, err := NewVerifier(public, item.Audience)
		if err != nil {
			t.Fatalf("%s: new verifier: %v", item.ID, err)
		}
		evaluateAt, err := time.Parse(time.RFC3339, item.EvaluateAt)
		if err != nil {
			t.Fatalf("%s: parse evaluation time: %v", item.ID, err)
		}
		_, err = verifier.Verify([]byte(item.Document), evaluateAt)
		got := "accepted"
		switch err {
		case nil:
		case ErrExpired:
			got = "expired"
		case ErrUnsupportedLevel:
			got = "unsupported_level"
		default:
			got = "invalid"
		}
		if got != item.Expected {
			t.Fatalf("%s: committed vector expects %s, Go now produces %s (%v)", item.ID, item.Expected, got, err)
		}
	}

	// The signed documents themselves must be byte-identical to what this
	// build signs, so a canonicalization change cannot hide behind a still
	// valid signature.
	for index, item := range committed.Vectors {
		if item.Document != built.Vectors[index].Document {
			t.Fatalf("%s: committed document differs from what this build signs; regenerate and review the canonical form", item.ID)
		}
	}
}
