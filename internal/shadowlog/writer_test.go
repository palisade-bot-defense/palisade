package shadowlog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/core"
)

func TestEncryptedAppendRotationAndVerification(t *testing.T) {
	root := privateTempDir(t)
	directory := filepath.Join(root, "logs")
	keyFile := filepath.Join(root, "shadow.key")
	writePrivate(t, keyFile, strings.Repeat("k", 32))
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	sink, err := New(Config{
		Directory: directory, KeyFile: keyFile, MaxFileBytes: 4 << 10,
		MaxFileAge: time.Hour, Retention: 24 * time.Hour, QueueSize: 64, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := core.DecisionRequest{SessionID: "session-12345678", Action: "read", EndpointClass: "compare_noindex"}
	decision := core.Decision{
		DecisionID: "decision-0001", Action: core.ActionObserve, ComputedAction: core.ActionDelay,
		Mode: core.RuntimeModeShadow, Scores: core.Scores{AutomationRisk: .5, AbuseIntentRisk: .7, AccountContinuity: .6},
		ReasonCodes: []string{"STEP_UP_REQUIRED", "COMPARE_NOINDEX_CAMPAIGN_SURFACE"}, PolicyVersion: "default-v3", ModelVersion: "transparent-baseline-v6",
	}
	for index := 0; index < 20; index++ {
		decision.DecisionID = "decision-" + time.Unix(int64(index), 0).UTC().Format("150405")
		if err := sink.RecordDecision(request, decision, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.RecordOutcome(OutcomeRequest{
		SessionID: request.SessionID, DecisionID: decision.DecisionID, EndpointClass: "compare_noindex", Outcome: "challenge_passed",
		Provenance: "server_observed", Confidence: "confirmed",
	}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyDirectory(directory, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Records != 21 || verified.Decisions != 20 || verified.Outcomes != 1 || verified.Files < 2 {
		t.Fatalf("unexpected verification: %+v", verified)
	}
	if verified.FirstAt != "2026-08-26T12:00:00Z" || verified.LastAt != "2026-08-26T12:01:00Z" {
		t.Fatalf("record timestamps were not second-quantized: %+v", verified)
	}
	paths, err := filepath.Glob(filepath.Join(directory, "shadow-*.plog"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("log mode = %o", info.Mode().Perm())
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{request.SessionID, decision.DecisionID, "compare_noindex", "STEP_UP_REQUIRED"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("encrypted log contains plaintext %q", forbidden)
			}
		}
	}
}

func TestTamperAndWrongKeyAreRejected(t *testing.T) {
	root := privateTempDir(t)
	directory := filepath.Join(root, "logs")
	keyFile := filepath.Join(root, "shadow.key")
	wrongKey := filepath.Join(root, "wrong.key")
	writePrivate(t, keyFile, strings.Repeat("a", 32))
	writePrivate(t, wrongKey, strings.Repeat("b", 32))
	sink, err := New(Config{Directory: directory, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.RecordOutcome(OutcomeRequest{
		SessionID: "session-12345678", DecisionID: "decision-tamper", EndpointClass: "account", Outcome: "successful_action",
		Provenance: "server_observed", Confidence: "confirmed",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(directory, wrongKey); err == nil {
		t.Fatal("wrong key was accepted")
	}
	paths, _ := filepath.Glob(filepath.Join(directory, "shadow-*.plog"))
	encoded, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)-1] ^= 1
	if err := os.WriteFile(paths[0], encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(directory, keyFile); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestRetentionDeletesOnlyExpiredManagedRegularFiles(t *testing.T) {
	root := privateTempDir(t)
	directory := filepath.Join(root, "logs")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(root, "shadow.key")
	writePrivate(t, keyFile, strings.Repeat("c", 32))
	managed := filepath.Join(directory, "shadow-20260101T000000Z-0000000000000000.plog")
	unmanaged := filepath.Join(directory, "operator-note.txt")
	lookalike := filepath.Join(directory, "shadow-not-managed.plog")
	invalidDate := filepath.Join(directory, "shadow-20261399T000000Z-0000000000000000.plog")
	writePrivate(t, managed, "expired")
	writePrivate(t, unmanaged, "retain")
	writePrivate(t, lookalike, "retain")
	writePrivate(t, invalidDate, "retain")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	if err := os.Chtimes(managed, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(unmanaged, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(lookalike, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(invalidDate, old, old); err != nil {
		t.Fatal(err)
	}
	sink, err := New(Config{Directory: directory, KeyFile: keyFile, MaxFileAge: time.Hour, Retention: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(managed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired managed file survived: %v", err)
	}
	if _, err := os.Stat(unmanaged); err != nil {
		t.Fatalf("unmanaged file was removed: %v", err)
	}
	if _, err := os.Stat(lookalike); err != nil {
		t.Fatalf("lookalike file was removed: %v", err)
	}
	if _, err := os.Stat(invalidDate); err != nil {
		t.Fatalf("invalid-date lookalike file was removed: %v", err)
	}
}

func TestRestartCreatesNewFileWithoutMutatingRetainedFile(t *testing.T) {
	root := privateTempDir(t)
	directory := filepath.Join(root, "logs")
	keyFile := filepath.Join(root, "shadow.key")
	writePrivate(t, keyFile, strings.Repeat("r", 32))
	recordOnce := func() {
		sink, err := New(Config{Directory: directory, KeyFile: keyFile})
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.RecordOutcome(OutcomeRequest{
			SessionID: "session-12345678", DecisionID: "decision-restart", EndpointClass: "account", Outcome: "successful_action",
			Provenance: "server_observed", Confidence: "confirmed",
		}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	}
	recordOnce()
	paths, err := filepath.Glob(filepath.Join(directory, "shadow-*.plog"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("first log files = %v, error = %v", paths, err)
	}
	firstBefore, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	recordOnce()
	firstAfter, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	paths, err = filepath.Glob(filepath.Join(directory, "shadow-*.plog"))
	if err != nil || len(paths) != 2 || string(firstBefore) != string(firstAfter) {
		t.Fatalf("restart mutated a retained file: files=%d error=%v", len(paths), err)
	}
}

func TestAgeRotationAndBoundedQueue(t *testing.T) {
	root := privateTempDir(t)
	directory := filepath.Join(root, "logs")
	keyFile := filepath.Join(root, "shadow.key")
	writePrivate(t, keyFile, strings.Repeat("t", 32))
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	sink, err := New(Config{
		Directory: directory, KeyFile: keyFile, MaxFileAge: time.Minute,
		Retention: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	record := Record{
		SchemaVersion: SchemaVersion, Kind: "outcome", RecordedAt: now.Format(time.RFC3339),
		SessionKey: "AAAAAAAAAAAAAAAAAAAAAA",
		Outcome: &OutcomeEntry{
			DecisionID: "decision-rotation", EndpointClass: "account", Outcome: "successful_action",
			Provenance: "server_observed", Confidence: "confirmed",
		},
	}
	current, err := sink.writeRecord(nil, record)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	current, err = sink.writeRecord(current, record)
	if err != nil {
		t.Fatal(err)
	}
	if err := closeActive(current); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(directory, "shadow-*.plog"))
	if err != nil || len(paths) != 2 {
		t.Fatalf("age rotation files = %v, error = %v", paths, err)
	}

	queueOnly := &Sink{records: make(chan Record, 1)}
	if err := queueOnly.enqueue(Record{}); err != nil {
		t.Fatal(err)
	}
	if err := queueOnly.enqueue(Record{}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full queue error = %v", err)
	}
}

func TestOutcomeProvenanceContract(t *testing.T) {
	tests := []struct {
		name       string
		outcome    string
		provenance string
		confidence string
		valid      bool
	}{
		{name: "authenticated human", outcome: "human_confirmed", provenance: "authenticated_account", confidence: "confirmed", valid: true},
		{name: "challenge is not human", outcome: "human_confirmed", provenance: "server_observed", confidence: "confirmed"},
		{name: "server challenge result", outcome: "challenge_passed", provenance: "server_observed", confidence: "confirmed", valid: true},
		{name: "operator abuse", outcome: "operator_confirmed_abuse", provenance: "operator_review", confidence: "confirmed", valid: true},
		{name: "unknown stays unknown", outcome: "unknown", provenance: "unknown", confidence: "unknown", valid: true},
		{name: "unknown cannot be confirmed", outcome: "unknown", provenance: "unknown", confidence: "confirmed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (OutcomeRequest{
				SessionID: "session-12345678", DecisionID: "decision-provenance", EndpointClass: "account", Outcome: test.outcome,
				Provenance: test.provenance, Confidence: test.confidence,
			}).Validate()
			if (err == nil) != test.valid {
				t.Fatalf("validation error = %v, valid = %t", err, test.valid)
			}
		})
	}
}

func TestDirectoryRejectsRetainedLogsFromAnotherKey(t *testing.T) {
	root := privateTempDir(t)
	directory := filepath.Join(root, "logs")
	firstKey := filepath.Join(root, "first.key")
	secondKey := filepath.Join(root, "second.key")
	writePrivate(t, firstKey, strings.Repeat("f", 32))
	writePrivate(t, secondKey, strings.Repeat("g", 32))
	sink, err := New(Config{Directory: directory, KeyFile: firstKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.RecordOutcome(OutcomeRequest{
		SessionID: "session-12345678", DecisionID: "decision-key", EndpointClass: "account", Outcome: "successful_action",
		Provenance: "server_observed", Confidence: "confirmed",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Directory: directory, KeyFile: secondKey}); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("mixed-key directory error = %v", err)
	}
}

func TestUnsafePathsAndOutcomesFailClosed(t *testing.T) {
	root := privateTempDir(t)
	keyFile := filepath.Join(root, "shadow.key")
	writePrivate(t, keyFile, strings.Repeat("d", 32))
	insecureKey := filepath.Join(root, "insecure.key")
	if err := os.WriteFile(insecureKey, []byte(strings.Repeat("e", 32)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecureKey, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Directory: filepath.Join(root, "logs-insecure"), KeyFile: insecureKey}); err == nil {
		t.Fatal("insecure key was accepted")
	}
	worktree := filepath.Join(root, "worktree")
	if err := os.Mkdir(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(worktree, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Directory: filepath.Join(worktree, "logs"), KeyFile: keyFile}); err == nil {
		t.Fatal("Git-contained log directory was accepted")
	}
	if err := (OutcomeRequest{SessionID: "session-12345678", EndpointClass: "other", Outcome: "human_likely"}).Validate(); !errors.Is(err, ErrInvalidOutcome) {
		t.Fatalf("unsupported outcome error = %v", err)
	}
	if err := (OutcomeRequest{SessionID: "session-12345678", EndpointClass: "account", Outcome: "unknown", Provenance: "unknown", Confidence: "unknown"}).Validate(); !errors.Is(err, ErrInvalidOutcome) {
		t.Fatalf("outcome without decision ID error = %v", err)
	}
	if got := normalizeRequestAction("account-123456"); got != "other" {
		t.Fatalf("dynamic request action was retained as %q", got)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func writePrivate(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}
