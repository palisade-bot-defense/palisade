package offlineimport

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanLocalDirectoryVerifiesAndStreamsClosedEvents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	output := makeLocalOutput(t, 3)
	var observed []string
	manifest, verified, err := ScanLocalDirectory(output, LocalScanLimits{}, func(event LocalEvent) error {
		observed = append(observed, event.ObservedAt)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Totals.Events != 3 || verified.Events != 3 || verified.Shards != 1 || verified.Bytes <= 0 || len(observed) != 3 {
		t.Fatalf("manifest=%+v verified=%+v observed=%v", manifest.Totals, verified, observed)
	}
	for index := 1; index < len(observed); index++ {
		if observed[index] < observed[index-1] {
			t.Fatalf("events were not streamed chronologically: %v", observed)
		}
	}
}

func TestScanLocalDirectoryFailsClosedOnTamperingAndBudgets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	t.Run("shard fingerprint", func(t *testing.T) {
		output := makeLocalOutput(t, 2)
		path := filepath.Join(output, "evidence-000001.jsonl")
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		content[0] ^= 1
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ScanLocalDirectory(output, LocalScanLimits{}, func(LocalEvent) error { return nil }); err == nil || !strings.Contains(err.Error(), "fingerprint") {
			t.Fatalf("tampered shard error = %v", err)
		}
	})
	t.Run("undeclared entry", func(t *testing.T) {
		output := makeLocalOutput(t, 1)
		if err := os.WriteFile(filepath.Join(output, "extra.txt"), []byte("unexpected"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ScanLocalDirectory(output, LocalScanLimits{}, func(LocalEvent) error { return nil }); err == nil || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("undeclared entry error = %v", err)
		}
	})
	t.Run("event budget", func(t *testing.T) {
		output := makeLocalOutput(t, 2)
		if _, _, err := ScanLocalDirectory(output, LocalScanLimits{MaxEvents: 1}, func(LocalEvent) error { return nil }); err == nil || !strings.Contains(err.Error(), "scan limits") {
			t.Fatalf("event budget error = %v", err)
		}
	})
	t.Run("consumer detail is redacted", func(t *testing.T) {
		output := makeLocalOutput(t, 1)
		secret := "sensitive-callback-detail"
		_, _, err := ScanLocalDirectory(output, LocalScanLimits{}, func(LocalEvent) error { return errors.New(secret) })
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("consumer detail was exposed: %v", err)
		}
	})
}

func TestLocalManifestValidationRejectsContractDrift(t *testing.T) {
	limits, err := normalizeLocalScanLimits(LocalScanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	manifest := LocalManifest{
		SchemaVersion: LocalManifestSchemaVersion,
		Importer:      LocalImporterVersion,
		Provenance:    ProvenanceOperatorExport,
		Config: LocalManifestConfig{
			ShardSize: MinimumShardSize, MaxLineBytes: DefaultMaxLineSize, MaxInputBytes: 1, MaxInputRecords: 1,
			MaxEvents: 1, MaxShards: 1, MaxOutputBytes: 1, Pseudonymization: "domain_daily_hmac_sha256_v2",
			DomainID: "AAAAAAAAAAAAAAAA", ChronologicalRequired: true,
		},
		Input:    LocalInputStats{LogicalName: "operator-events.jsonl", SHA256: strings.Repeat("0", 64)},
		Shards:   []ShardStats{},
		Warnings: localManifestWarnings(),
	}
	if err := validateLocalManifest(manifest, limits); err != nil {
		t.Fatalf("valid empty manifest rejected: %v", err)
	}
	manifest.Warnings[0] = "changed warning"
	if err := validateLocalManifest(manifest, limits); err == nil {
		t.Fatal("changed warning contract was accepted")
	}
	if _, err := normalizeLocalScanLimits(LocalScanLimits{MaxEvents: MaximumLocalScanEvents + 1}); err == nil {
		t.Fatal("oversized scan budget was accepted")
	}
}

func makeLocalOutput(t *testing.T, count int) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "authorized-input.txt")
	key := filepath.Join(root, "key.bin")
	output := filepath.Join(root, "normalized")
	var content []byte
	for index := 0; index < count; index++ {
		event := validLocalInputEvent()
		event.ObservedAt = "2026-08-29T12:00:0" + string(rune('0'+index)) + "Z"
		event.SubjectRef = "synthetic-subject-" + string(rune('a'+index))
		content = append(content, mustJSON(t, event)...)
		content = append(content, '\n')
	}
	if err := os.WriteFile(input, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, bytes.Repeat([]byte{0x6b}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunLocal(LocalConfig{
		InputFile: input, OutputDir: output, PseudonymKeyFile: key,
		DatasetID: "synthetic-dataset", PilotID: "synthetic-pilot", ShardSize: MinimumShardSize,
	}); err != nil {
		t.Fatal(err)
	}
	return output
}
