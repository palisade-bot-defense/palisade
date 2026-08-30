package offlineimport

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLocalEvidenceNormalizationNeverEmitsDirectReferences(t *testing.T) {
	input := validLocalInputEvent()
	input.SubjectRef = "synthetic-client-alpha"
	input.SessionRef = "synthetic-session-alpha"
	input.Evidence = LocalEvidence{
		CollectionStatus: "partial", AutomationEvidence: "high", AbuseIntentEvidence: "medium",
		ContinuityEvidence: "low", DecoyInteraction: "touched", ChallengeLifecycle: "passed",
	}
	parsed, observedAt, err := decodeLocalInputEvent(mustJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	pseudonyms := newPseudonymizer(bytes.Repeat([]byte{0x42}, 32), "dataset", "pilot")
	defer pseudonyms.Wipe()
	event := normalizeLocalEvent(parsed, observedAt, ProvenanceOperatorExport, pseudonyms)
	if err := ValidateLocalEvent(event); err != nil {
		t.Fatal(err)
	}
	encoded := string(mustJSON(t, event))
	for _, forbidden := range []string{input.SubjectRef, input.SessionRef} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("direct reference leaked into normalized output: %q", forbidden)
		}
	}
	if event.Evidence != input.Evidence || event.Label != input.Label {
		t.Fatalf("separate evidence or label lanes changed: %+v", event)
	}
	if event.SubjectID == event.SessionID || !validPseudonym(event.SubjectID) || !validPseudonym(event.SessionID) {
		t.Fatalf("pseudonym domains are not separated: %+v", event)
	}

	nextDay := input
	nextDay.ObservedAt = "2026-08-30T12:00:00Z"
	_, nextObserved, err := decodeLocalInputEvent(mustJSON(t, nextDay))
	if err != nil {
		t.Fatal(err)
	}
	next := normalizeLocalEvent(nextDay, nextObserved, ProvenanceOperatorExport, pseudonyms)
	if next.SubjectID == event.SubjectID || next.SessionID == event.SessionID {
		t.Fatal("daily pseudonym rotation did not separate days")
	}
}

func TestLocalEvidenceInputRejectsAmbiguityAndInvalidTrust(t *testing.T) {
	valid := validLocalInputEvent()
	tests := []struct {
		name string
		line []byte
	}{
		{name: "unknown field", line: append(bytes.TrimSuffix(mustJSON(t, valid), []byte("}")), []byte(`,"request_url":"/private"}`)...)},
		{name: "duplicate key", line: append(bytes.TrimSuffix(mustJSON(t, valid), []byte("}")), []byte(`,"source":"browser_sensor"}`)...)},
		{name: "two values", line: append(mustJSON(t, valid), mustJSON(t, valid)...)},
		{name: "blank reference", line: mustJSON(t, func() LocalInputEvent { row := valid; row.SubjectRef = " synthetic "; return row }())},
		{name: "offset timestamp", line: mustJSON(t, func() LocalInputEvent { row := valid; row.ObservedAt = "2026-08-29T14:00:00+02:00"; return row }())},
		{name: "challenge is not human", line: mustJSON(t, func() LocalInputEvent {
			row := valid
			row.Evidence.ChallengeLifecycle = "passed"
			row.Label = LocalLabel{Class: "human_confirmed", Provenance: "none", Confidence: "confirmed"}
			return row
		}())},
		{name: "abuse requires review", line: mustJSON(t, func() LocalInputEvent {
			row := valid
			row.Label = LocalLabel{Class: "operator_confirmed_abuse", Provenance: "authenticated_account", Confidence: "confirmed"}
			return row
		}())},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := decodeLocalInputEvent(test.line); err == nil {
				t.Fatal("unsafe local evidence input was accepted")
			}
		})
	}
}

func TestRunLocalImportPublishesPrivateDeterministicContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	root := t.TempDir()
	input := filepath.Join(root, "authorized-input.txt")
	key := filepath.Join(root, "key.bin")
	output := filepath.Join(root, "normalized")
	first := validLocalInputEvent()
	second := first
	second.ObservedAt = "2026-08-29T12:00:01Z"
	second.SubjectRef = "synthetic-client-beta"
	second.SessionRef = ""
	content := append(mustJSON(t, first), '\n')
	content = append(content, mustJSON(t, second)...)
	content = append(content, '\n')
	if err := os.WriteFile(input, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, bytes.Repeat([]byte{0x7a}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := RunLocal(LocalConfig{
		InputFile: input, OutputDir: output, PseudonymKeyFile: key,
		DatasetID: "synthetic-dataset", PilotID: "synthetic-pilot",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 2 || result.ManifestPath != filepath.Join(output, "local-manifest.json") {
		t.Fatalf("result = %+v", result)
	}
	manifestBytes, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest LocalManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != LocalManifestSchemaVersion || manifest.Totals.Events != 2 || len(manifest.Shards) != 1 || !manifest.Config.ChronologicalRequired {
		t.Fatalf("manifest = %+v", manifest)
	}
	shard, err := os.ReadFile(filepath.Join(output, manifest.Shards[0].Filename))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{first.SubjectRef, first.SessionRef, second.SubjectRef} {
		if bytes.Contains(shard, []byte(forbidden)) || bytes.Contains(manifestBytes, []byte(forbidden)) {
			t.Fatalf("direct reference %q leaked into local artifacts", forbidden)
		}
	}
	if complete, err := os.ReadFile(filepath.Join(output, "LOCAL_COMPLETE")); err != nil || string(complete) != LocalManifestSchemaVersion+"\n" {
		t.Fatalf("completion marker = %q, %v", complete, err)
	}
	assertPrivateMode(t, output, 0o700)
	assertPrivateMode(t, result.ManifestPath, 0o600)
	assertPrivateMode(t, filepath.Join(output, "LOCAL_COMPLETE"), 0o600)
	assertPrivateMode(t, filepath.Join(output, manifest.Shards[0].Filename), 0o600)

	secondOutput := filepath.Join(root, "normalized-again")
	secondResult, err := RunLocal(LocalConfig{
		InputFile: input, OutputDir: secondOutput, PseudonymKeyFile: key,
		DatasetID: "synthetic-dataset", PilotID: "synthetic-pilot",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, err := os.ReadFile(secondResult.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	secondShard, err := os.ReadFile(filepath.Join(secondOutput, manifest.Shards[0].Filename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestBytes, secondManifest) || !bytes.Equal(shard, secondShard) {
		t.Fatal("identical local input and configuration did not produce deterministic artifacts")
	}
}

func TestRunLocalImportRejectsDecreasingTimeWithoutPublishing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	root := t.TempDir()
	input := filepath.Join(root, "authorized-input.txt")
	key := filepath.Join(root, "key.bin")
	output := filepath.Join(root, "normalized")
	late := validLocalInputEvent()
	early := late
	late.ObservedAt = "2026-08-29T12:01:00Z"
	early.ObservedAt = "2026-08-29T12:00:00Z"
	content := append(mustJSON(t, late), '\n')
	content = append(content, mustJSON(t, early)...)
	content = append(content, '\n')
	if err := os.WriteFile(input, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, bytes.Repeat([]byte{0x33}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := RunLocal(LocalConfig{InputFile: input, OutputDir: output, PseudonymKeyFile: key, DatasetID: "dataset", PilotID: "pilot"})
	if !errors.Is(err, ErrLocalEventOrder) {
		t.Fatalf("error = %v, want ErrLocalEventOrder", err)
	}
	if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
		t.Fatal("failed local import published an output directory")
	}
}

func validLocalInputEvent() LocalInputEvent {
	return LocalInputEvent{
		SchemaVersion: LocalInputSchemaVersion,
		ObservedAt:    "2026-08-29T12:00:00Z",
		SubjectRef:    "synthetic-client",
		SessionRef:    "synthetic-session",
		Source:        "access_gateway",
		EndpointClass: "public_content",
		ActionClass:   "read",
		StatusClass:   "success",
		Evidence: LocalEvidence{
			CollectionStatus: "complete", AutomationEvidence: "none", AbuseIntentEvidence: "none",
			ContinuityEvidence: "low", DecoyInteraction: "none", ChallengeLifecycle: "none",
		},
		Label: LocalLabel{Class: "unknown", Provenance: "none", Confidence: "unknown"},
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertPrivateMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

func TestLocalTimestampCanonicalization(t *testing.T) {
	input := validLocalInputEvent()
	input.ObservedAt = "2026-08-29T12:00:00.120000000Z"
	_, observedAt, err := decodeLocalInputEvent(mustJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	if got := observedAt.Format(time.RFC3339Nano); got != "2026-08-29T12:00:00.12Z" {
		t.Fatalf("canonical time = %q", got)
	}
}

func TestLocalEvidenceSchemaVersionsMatchCode(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate local import test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	tests := []struct {
		path       string
		version    string
		provenance bool
	}{
		{path: "schemas/local-evidence-input-v1.schema.json", version: LocalInputSchemaVersion},
		{path: "schemas/local-evidence-event-v1.schema.json", version: LocalEventSchemaVersion, provenance: true},
		{path: "schemas/local-evidence-manifest-v1.schema.json", version: LocalManifestSchemaVersion, provenance: true},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			encoded, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(test.path)))
			if err != nil {
				t.Fatal(err)
			}
			var schema struct {
				Properties map[string]struct {
					Const string `json:"const"`
				} `json:"properties"`
			}
			if err := json.Unmarshal(encoded, &schema); err != nil {
				t.Fatal(err)
			}
			if schema.Properties["schema_version"].Const != test.version {
				t.Fatalf("schema version = %q, want %q", schema.Properties["schema_version"].Const, test.version)
			}
			if test.provenance && schema.Properties["provenance"].Const != ProvenanceOperatorExport {
				t.Fatalf("schema provenance = %q", schema.Properties["provenance"].Const)
			}
		})
	}
}
