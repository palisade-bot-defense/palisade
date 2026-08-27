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
			SessionID: "session-12345678", EndpointClass: "account", Outcome: "successful_action",
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
