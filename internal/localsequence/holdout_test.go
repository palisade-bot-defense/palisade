package localsequence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/internal/offlineimport"
)

func TestHoldoutEvaluationKeepsChronologyLabelsAndUnseenFamiliesSeparate(t *testing.T) {
	config, cutoff, err := normalizeHoldoutConfig(HoldoutConfig{
		Sequence: Config{}, HoldoutStart: "2026-08-29T12:00:00Z", MinConfirmedPerLabel: 1, MinUnseenAbuse: 1,
		FamilyAnnotations: "synthetic-private-annotations",
	})
	if err != nil {
		t.Fatal(err)
	}
	knownFamily := sequenceDigest("family:known")
	unseenFamily := sequenceDigest("family:unseen")
	assignments := map[[32]byte][32]byte{}
	for _, key := range []string{"session:baseline-human", "session:baseline-abuse", "session:holdout-human", "session:holdout-known-abuse", "session:boundary"} {
		assignments[sequenceDigest(key)] = knownFamily
	}
	assignments[sequenceDigest("session:holdout-unseen-abuse")] = unseenFamily
	evaluator := newHoldoutEvaluator(config, cutoff, familyIndex{
		assignments: assignments, records: uint64(len(assignments)), bytes: 400, sha256: strings.Repeat("a", 64),
	})
	baselineHuman := featureWindow("session:baseline-human", cutoff.Add(-2*time.Hour), "public_content", "human_confirmed")
	baselineHuman.automation = 3
	baselineAbuse := featureWindow("session:baseline-abuse", cutoff.Add(-time.Hour), "api", "operator_confirmed_abuse")
	baselineAbuse.burstShape = "clustered"
	holdoutHuman := featureWindow("session:holdout-human", cutoff.Add(time.Minute), "authentication", "human_confirmed")
	holdoutHuman.collectionIssue = true
	holdoutKnownAbuse := featureWindow("session:holdout-known-abuse", cutoff.Add(2*time.Minute), "api", "operator_confirmed_abuse")
	holdoutKnownAbuse.abuseIntent = 3
	holdoutUnseenAbuse := featureWindow("session:holdout-unseen-abuse", cutoff.Add(3*time.Minute), "decoy", "operator_confirmed_abuse")
	holdoutUnseenAbuse.decoy = 3
	unknown := featureWindow("session:holdout-unknown", cutoff.Add(4*time.Minute), "other", "unknown")
	unknown.challenge = challengePassed
	boundary := featureWindow("session:boundary", cutoff.Add(-time.Minute), "account", "unknown")
	boundary.last = cutoff.Add(time.Minute)
	boundary.humanLabel = true
	boundary.abuseLabel = true
	for _, window := range []windowFeature{baselineHuman, baselineAbuse, holdoutHuman, holdoutKnownAbuse, holdoutUnseenAbuse, unknown, boundary} {
		if err := evaluator.observe(window); err != nil {
			t.Fatal(err)
		}
	}
	evaluator.report.Source = SourceSummary{
		Shards: 1, Events: 7, Bytes: 700, Sequences: 7,
		FirstAt: baselineHuman.first.Format(time.RFC3339Nano), LastAt: unknown.last.Format(time.RFC3339Nano),
	}
	evaluator.finish()
	report := evaluator.report
	if err := ValidateHoldoutReport(report); err != nil {
		t.Fatal(err)
	}
	if report.Partitions.Baseline.Windows != 2 || report.Partitions.Holdout.Windows != 4 || report.Partitions.UnseenFamilyHoldout.Windows != 1 || report.Split.BoundaryWindowsExcluded != 1 {
		t.Fatalf("partitions = %+v split=%+v", report.Partitions, report.Split)
	}
	if report.Split.BoundaryLabels.Ambiguous != 1 || report.Partitions.Holdout.Collection.WithArtifact != 1 || report.Partitions.Holdout.Labels.Unknown != 1 {
		t.Fatalf("adversarial accounting = split:%+v holdout:%+v", report.Split, report.Partitions.Holdout)
	}
	if report.Readiness.State != "chronological_and_unseen_family_ready" || report.Readiness.AutomaticEnforcement {
		t.Fatalf("readiness = %+v", report.Readiness)
	}
	combined := report.Partitions.Baseline.Rules[4]
	if combined.Flagged.HumanConfirmed != 1 || combined.Flagged.OperatorConfirmedAbuse != 1 || combined.ConfirmedHumanFlagRate.Rate != 1 || combined.ConfirmedAbuseCaptureRate.Rate != 1 {
		t.Fatalf("combined baseline diagnostic = %+v", combined)
	}
	if report.Families.BaselineDistinct != 1 || report.Families.HoldoutDistinct != 2 || report.Families.UnseenDistinct != 1 || report.Families.UnannotatedWindows != 1 {
		t.Fatalf("family accounting = %+v", report.Families)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"baseline-human", "holdout-unseen-abuse", "family:known", "family:unseen", "sequence_id", "family_ref"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("private linkage leaked into holdout report: %q", forbidden)
		}
	}
}

func TestHoldoutReadinessDoesNotTreatUnknownAsHuman(t *testing.T) {
	config, cutoff, err := normalizeHoldoutConfig(HoldoutConfig{HoldoutStart: "2026-08-29T12:00:00Z", MinConfirmedPerLabel: 1, MinUnseenAbuse: 1})
	if err != nil {
		t.Fatal(err)
	}
	evaluator := newHoldoutEvaluator(config, cutoff, familyIndex{assignments: map[[32]byte][32]byte{}})
	for _, at := range []time.Time{cutoff.Add(-time.Hour), cutoff.Add(time.Hour)} {
		window := featureWindow("session:unknown", at, "public_content", "unknown")
		if err := evaluator.observe(window); err != nil {
			t.Fatal(err)
		}
	}
	evaluator.report.Source = SourceSummary{Shards: 1, Events: 2, Bytes: 200, Sequences: 2, FirstAt: cutoff.Add(-time.Hour).Format(time.RFC3339), LastAt: cutoff.Add(time.Hour).Format(time.RFC3339)}
	evaluator.finish()
	if evaluator.report.Readiness.State != "insufficient_confirmed_labels" || !slicesContain(evaluator.report.Readiness.Reasons, "holdout_confirmed_human_below_minimum") {
		t.Fatalf("unknown windows incorrectly satisfied label gates: %+v", evaluator.report.Readiness)
	}
	if err := ValidateHoldoutReport(evaluator.report); err != nil {
		t.Fatal(err)
	}
}

func TestFamilyAnnotationReaderIsBoundedStrictAndPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sequenceID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	annotation := FamilyAnnotation{SchemaVersion: FamilyAnnotationSchemaVersion, SequenceKind: "session", SequenceID: sequenceID, FamilyRef: "synthetic-family-alpha"}
	encoded, err := json.Marshal(annotation)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "family-annotations.txt")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	config, _, err := normalizeHoldoutConfig(HoldoutConfig{HoldoutStart: "2026-08-29T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	index, err := loadFamilyAnnotations(path, config)
	if err != nil {
		t.Fatal(err)
	}
	if index.records != 1 || index.bytes == 0 || !validHexSHA256(index.sha256) {
		t.Fatalf("family index metadata = %+v", index)
	}
	family, found := index.familyFor("session:" + sequenceID)
	if !found || family == [32]byte{} {
		t.Fatal("valid family assignment was not indexed")
	}
	serialized := fmt.Sprintf("%x", index.assignments)
	if strings.Contains(serialized, sequenceID) || strings.Contains(serialized, annotation.FamilyRef) {
		t.Fatal("family index retained a directly serializable private reference")
	}

	duplicatePath := filepath.Join(root, "duplicate.txt")
	duplicate := append(append(append([]byte{}, encoded...), '\n'), encoded...)
	duplicate = append(duplicate, '\n')
	if err := os.WriteFile(duplicatePath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFamilyAnnotations(duplicatePath, config); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate annotation error = %v", err)
	}

	unknownFieldPath := filepath.Join(root, "unknown-field.txt")
	unknownField := bytes.Replace(encoded, []byte(`"family_ref"`), []byte(`"unexpected":true,"family_ref"`), 1)
	if err := os.WriteFile(unknownFieldPath, append(unknownField, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFamilyAnnotations(unknownFieldPath, config); err == nil || !strings.Contains(err.Error(), "closed contract") {
		t.Fatalf("unknown annotation field error = %v", err)
	}

	publicModePath := filepath.Join(root, "public-mode.txt")
	if err := os.WriteFile(publicModePath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicModePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFamilyAnnotations(publicModePath, config); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("public annotation mode error = %v", err)
	}

	config.MaxFamilyRecords = 1
	second := annotation
	second.SequenceID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))
	secondEncoded, _ := json.Marshal(second)
	budgetPath := filepath.Join(root, "budget.txt")
	budget := append(append(append(append([]byte{}, encoded...), '\n'), secondEncoded...), '\n')
	if err := os.WriteFile(budgetPath, budget, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFamilyAnnotations(budgetPath, config); !errors.Is(err, ErrFamilyAnnotationBudget) {
		t.Fatalf("annotation budget error = %v", err)
	}
}

func TestAnalyzeHoldoutDirectoryEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "authorized-input.txt")
	keyPath := filepath.Join(root, "key.bin")
	outputDir := filepath.Join(root, "normalized")
	rows := []offlineimport.LocalInputEvent{
		holdoutInput("2026-08-29T10:00:00Z", "baseline-human", "human_confirmed"),
		holdoutInput("2026-08-29T10:01:00Z", "baseline-abuse", "operator_confirmed_abuse"),
		holdoutInput("2026-08-29T12:01:00Z", "holdout-human", "human_confirmed"),
		holdoutInput("2026-08-29T12:02:00Z", "holdout-abuse", "operator_confirmed_abuse"),
	}
	var input []byte
	for _, row := range rows {
		input = append(input, mustJSONValue(t, row)...)
		input = append(input, '\n')
	}
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x55}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := offlineimport.RunLocal(offlineimport.LocalConfig{InputFile: inputPath, OutputDir: outputDir, PseudonymKeyFile: keyPath, DatasetID: "synthetic", PilotID: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	shard, err := os.ReadFile(filepath.Join(outputDir, "evidence-000001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var normalized []offlineimport.LocalEvent
	for _, line := range bytes.Split(bytes.TrimSpace(shard), []byte{'\n'}) {
		var event offlineimport.LocalEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		normalized = append(normalized, event)
	}
	annotationPath := filepath.Join(root, "families.txt")
	annotations := []FamilyAnnotation{
		{SchemaVersion: FamilyAnnotationSchemaVersion, SequenceKind: "session", SequenceID: normalized[1].SessionID, FamilyRef: "known-family"},
		{SchemaVersion: FamilyAnnotationSchemaVersion, SequenceKind: "session", SequenceID: normalized[3].SessionID, FamilyRef: "unseen-family"},
	}
	var annotationBytes []byte
	for _, annotation := range annotations {
		annotationBytes = append(annotationBytes, mustJSONValue(t, annotation)...)
		annotationBytes = append(annotationBytes, '\n')
	}
	if err := os.WriteFile(annotationPath, annotationBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeHoldoutDirectory(outputDir, HoldoutConfig{
		HoldoutStart: "2026-08-29T12:00:00Z", MinConfirmedPerLabel: 1, MinUnseenAbuse: 1, FamilyAnnotations: annotationPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Partitions.Baseline.Windows != 2 || report.Partitions.Holdout.Windows != 2 || report.Partitions.UnseenFamilyHoldout.Labels.OperatorConfirmedAbuse != 1 ||
		report.Readiness.State != "chronological_and_unseen_family_ready" {
		t.Fatalf("end-to-end holdout report = %+v", report)
	}
	encodedReport := string(mustJSONValue(t, report))
	for _, event := range normalized {
		if strings.Contains(encodedReport, event.SubjectID) || strings.Contains(encodedReport, event.SessionID) {
			t.Fatal("normalized identifier leaked into holdout report")
		}
	}
}

func TestHoldoutValidationRejectsContractDrift(t *testing.T) {
	config, cutoff, err := normalizeHoldoutConfig(HoldoutConfig{HoldoutStart: "2026-08-29T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	evaluator := newHoldoutEvaluator(config, cutoff, familyIndex{assignments: map[[32]byte][32]byte{}})
	evaluator.finish()
	if err := ValidateHoldoutReport(evaluator.report); err != nil {
		t.Fatalf("valid empty report rejected: %v", err)
	}
	evaluator.report.RuleDefinitions[0].ID = "changed"
	if err := ValidateHoldoutReport(evaluator.report); err == nil {
		t.Fatal("changed rule contract was accepted")
	}
	if _, _, err := normalizeHoldoutConfig(HoldoutConfig{HoldoutStart: "2026-08-29T14:00:00+02:00"}); err == nil {
		t.Fatal("non-UTC holdout boundary was accepted")
	}
}

func featureWindow(key string, at time.Time, endpoint, label string) windowFeature {
	window := windowFeature{key: key, first: at, last: at, events: 1, burstShape: "single", peakMinuteBucket: "one"}
	window.endpointSeen[endpointIndex(endpoint)] = true
	switch label {
	case "human_confirmed":
		window.humanLabel = true
	case "operator_confirmed_abuse":
		window.abuseLabel = true
	}
	return window
}

func holdoutInput(at, reference, label string) offlineimport.LocalInputEvent {
	row := offlineimport.LocalInputEvent{
		SchemaVersion: offlineimport.LocalInputSchemaVersion, ObservedAt: at, SubjectRef: reference, SessionRef: reference + "-session",
		Source: "access_gateway", EndpointClass: "public_content", ActionClass: "read", StatusClass: "success",
		Evidence: offlineimport.LocalEvidence{
			CollectionStatus: "complete", AutomationEvidence: "none", AbuseIntentEvidence: "none",
			ContinuityEvidence: "none", DecoyInteraction: "none", ChallengeLifecycle: "none",
		},
		Label: offlineimport.LocalLabel{Class: "unknown", Provenance: "none", Confidence: "unknown"},
	}
	switch label {
	case "human_confirmed":
		row.Label = offlineimport.LocalLabel{Class: label, Provenance: "authenticated_account", Confidence: "confirmed"}
	case "operator_confirmed_abuse":
		row.Label = offlineimport.LocalLabel{Class: label, Provenance: "operator_review", Confidence: "confirmed"}
	}
	return row
}

func mustJSONValue(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func slicesContain(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
