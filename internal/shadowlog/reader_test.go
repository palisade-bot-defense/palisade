package shadowlog

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanDirectoryStreamsRecordsAndEnforcesBudgets(t *testing.T) {
	root := privateTempDir(t)
	directory := filepath.Join(root, "logs")
	keyFile := filepath.Join(root, "shadow.key")
	writePrivate(t, keyFile, strings.Repeat("s", 32))
	sink, err := New(Config{Directory: directory, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if err := sink.RecordOutcome(OutcomeRequest{
			SessionID: "session-12345678", DecisionID: "decision-reader-" + string(rune('a'+index)), EndpointClass: "account", Outcome: "successful_action",
			Provenance: "server_observed", Confidence: "confirmed",
		}, time.Date(2026, 8, 27, 12, 0, index, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	var visited uint64
	verified, err := ScanDirectory(directory, keyFile, ScanLimits{}, func(record Record) error {
		visited++
		if record.SessionKey == "" || record.Outcome == nil {
			t.Fatalf("unexpected record: %+v", record)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if visited != 2 || verified.Records != 2 || verified.EncryptedBytes <= headerSize {
		t.Fatalf("unexpected scan: visited=%d verified=%+v", visited, verified)
	}
	if _, err := ScanDirectory(directory, keyFile, ScanLimits{MaxRecords: 1}, nil); !errors.Is(err, ErrScanRecordLimit) {
		t.Fatalf("record budget error = %v", err)
	}
	if _, err := ScanDirectory(directory, keyFile, ScanLimits{MaxEncryptedBytes: headerSize}, nil); !errors.Is(err, ErrScanByteLimit) {
		t.Fatalf("byte budget error = %v", err)
	}
}

func TestDecodeRecordKeepsV1ReadableButRequiresLinkedModernOutcomes(t *testing.T) {
	legacy := `{"schema_version":"palisade.shadow-record.v1","kind":"outcome","recorded_at":"2026-08-27T12:00:00Z","session_key":"AAAAAAAAAAAAAAAAAAAAAA","outcome":{"endpoint_class":"account","outcome":"successful_action","provenance":"server_observed","confidence":"confirmed"}}`
	if record, err := decodeRecord([]byte(legacy)); err != nil || record.Outcome.DecisionID != "" {
		t.Fatalf("legacy record = %+v, %v", record, err)
	}
	v2 := strings.Replace(legacy, LegacySchemaVersion, PreviousSchemaVersion, 1)
	if _, err := decodeRecord([]byte(v2)); err == nil {
		t.Fatal("v2 outcome without decision_id was accepted")
	}
}

func TestDecodeRecordRequiresCanonicalV2Cohort(t *testing.T) {
	valid := `{"schema_version":"palisade.shadow-record.v2","kind":"decision","recorded_at":"2026-08-27T12:00:00Z","session_key":"AAAAAAAAAAAAAAAAAAAAAA","decision":{"decision_id":"decision-1","request_action":"read","endpoint_class":"account","evaluation_cohort":"unknown","action":"observe","computed_action":"allow","mode":"shadow","scores":{"automation_risk":0,"abuse_intent_risk":0,"account_continuity":0},"reason_codes":[],"policy_version":"default-v3","model_version":"transparent-baseline-v6"}}`
	if _, err := decodeRecord([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	missing := strings.Replace(valid, `,"evaluation_cohort":"unknown"`, "", 1)
	if _, err := decodeRecord([]byte(missing)); err == nil {
		t.Fatal("v2 decision without evaluation_cohort was accepted")
	}
}

func TestDecodeRecordAddsDelayOnlyInV3(t *testing.T) {
	v3 := `{"schema_version":"palisade.shadow-record.v3","kind":"decision","recorded_at":"2026-08-27T12:00:00Z","session_key":"AAAAAAAAAAAAAAAAAAAAAA","decision":{"decision_id":"decision-delay","request_action":"read","endpoint_class":"public_content","evaluation_cohort":"unknown","action":"observe","computed_action":"delay","mode":"shadow","scores":{"automation_risk":0.5,"abuse_intent_risk":0.5,"account_continuity":0.5},"reason_codes":["ELEVATED_RISK"],"policy_version":"default-v4","model_version":"transparent-baseline-v8"}}`
	if _, err := decodeRecord([]byte(v3)); err != nil {
		t.Fatal(err)
	}
	v2 := strings.Replace(v3, SchemaVersion, PreviousSchemaVersion, 1)
	if _, err := decodeRecord([]byte(v2)); err == nil {
		t.Fatal("v2 record with delay action was accepted")
	}
}
