package offlineimport

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	syntheticPeer = "192.0.2.10"
	syntheticXFF  = "198.51.100.25"
	syntheticUA   = "SyntheticFixture/1.0"
)

func testConfig(input, output, key string) Config {
	return Config{
		InputDir:         input,
		OutputDir:        output,
		PseudonymKeyFile: key,
		DatasetID:        "synthetic-dataset",
		PilotID:          "synthetic-pilot",
	}
}

func TestImportSanitizesAndAppliesWeakLabels(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	keyFile := filepath.Join(root, "key")
	output := filepath.Join(root, "normalized")
	writeSyntheticBundle(t, input, 1)
	writeKey(t, keyFile, 0o600)

	config := testConfig(input, output, keyFile)
	config.ShardSize = MinimumShardSize
	result, err := Run(config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 4 {
		t.Fatalf("events = %d, want 4", result.Events)
	}
	events := readEvents(t, output)
	if len(events) != 4 {
		t.Fatalf("event count = %d", len(events))
	}

	encoded, err := os.ReadFile(filepath.Join(output, "events-000001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		syntheticPeer,
		syntheticXFF,
		syntheticUA,
		"fixture-secret-value",
		"synthetic-referrer.invalid",
		"synthetic-query-value",
		"synthetic-rule-free-text",
		"synthetic-error-message",
		`"path"`, `"query"`, `"referer"`, `"user_agent"`, `"xff"`, `"message"`, `"rule"`,
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("normalized output contains forbidden value or field %q", forbidden)
		}
	}

	var access, alert, decision Event
	for _, event := range events {
		switch event.Source {
		case "access":
			access = event
		case "crowdsec_alert":
			alert = event
		case "crowdsec_decision":
			decision = event
		}
	}
	if access.EndpointClass != "compare_index" || access.ActionClass != "read" || access.StatusClass != "success" || access.Features.SizeBucket != 2 {
		t.Fatalf("unexpected normalized access event: %+v", access)
	}
	for _, event := range []Event{alert, decision} {
		if event.LabelClass != "probable_abuse" || event.LabelProvenance != "weak_policy_label" || event.LabelTrust != "weak_policy_label" {
			t.Fatalf("CrowdSec event was treated as stronger than a weak policy label: %+v", event)
		}
	}

	manifest := readManifest(t, result.ManifestPath)
	if manifest.Provenance != ProvenanceOffline || manifest.Totals.Events != 4 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	manifestBytes, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, privatePath := range []string{input, output, keyFile} {
		if strings.Contains(string(manifestBytes), privatePath) {
			t.Fatalf("manifest contains a private filesystem path")
		}
	}
	for _, inputStats := range manifest.Inputs {
		if inputStats.Filename == "error.log.gz" && (inputStats.Records != 1 || inputStats.Skipped != 1) {
			t.Fatalf("error log was not count-only: %+v", inputStats)
		}
	}
	for _, event := range events {
		if event.Source == "error" {
			t.Fatal("error log produced a row event")
		}
	}
}

func TestDailyPseudonymRotationAndSameDayLinkage(t *testing.T) {
	key := []byte("fixture-key-material-with-at-least-32-bytes")
	pseudonyms := newPseudonymizer(key, "synthetic-dataset", "synthetic-pilot")
	defer pseudonyms.Wipe()
	firstTime := time.Date(2026, 1, 12, 1, 0, 0, 0, time.UTC)
	secondTime := firstTime.Add(12 * time.Hour)
	nextDay := firstTime.Add(24 * time.Hour)
	first := baseEvent("access", firstTime, syntheticPeer, syntheticUA, pseudonyms)
	second := baseEvent("anubis", secondTime, syntheticPeer, syntheticUA, pseudonyms)
	rotated := baseEvent("access", nextDay, syntheticPeer, syntheticUA, pseudonyms)
	if first.SubjectID != second.SubjectID || first.SessionID != second.SessionID {
		t.Fatal("same-day identifiers did not link across allowed sources")
	}
	if first.SubjectID == rotated.SubjectID || first.SessionID == rotated.SessionID {
		t.Fatal("daily identifiers did not rotate")
	}
	if first.SubjectID == first.SessionID {
		t.Fatal("subject and session namespaces are not separated")
	}
}

func TestPseudonymDomainsAndBinaryKeyBytesAreSeparated(t *testing.T) {
	key := []byte("fixture-key-material-with-at-least-32-bytes\n")
	withoutNewline := key[:len(key)-1]
	first := newPseudonymizer(key, "synthetic-dataset", "synthetic-pilot-a")
	second := newPseudonymizer(withoutNewline, "synthetic-dataset", "synthetic-pilot-a")
	third := newPseudonymizer(key, "synthetic-dataset", "synthetic-pilot-b")
	defer first.Wipe()
	defer second.Wipe()
	defer third.Wipe()
	observedAt := time.Date(2026, 1, 12, 1, 0, 0, 0, time.UTC)
	firstID := first.pseudonym("subject", observedAt, syntheticPeer, "")
	if firstID == second.pseudonym("subject", observedAt, syntheticPeer, "") {
		t.Fatal("trailing binary key byte was trimmed")
	}
	if firstID == third.pseudonym("subject", observedAt, syntheticPeer, "") {
		t.Fatal("pilot KDF domain was not separated")
	}
}

func TestClosedClassifiers(t *testing.T) {
	tests := map[string]string{
		"/compare?synthetic=discarded":   "compare_index",
		"/de/compare#synthetic-fragment": "compare_index",
		"/zz/compare":                    "other_public",
		"/.within.website/x/challenge":   "anubis_worker",
		"/synthetic-public":              "other_public",
	}
	for input, expected := range tests {
		if got := endpointClass(input); got != expected {
			t.Errorf("endpointClass(%q) = %q, want %q", input, got, expected)
		}
	}
	if got := crowdSecReason("synthetic/unrecognized-scenario"); got != "unknown" {
		t.Fatalf("unknown scenario leaked or was not closed: %q", got)
	}
	if err := validateEvent(Event{Source: "deployment_local"}); err == nil {
		t.Fatal("future provenance/source category was accepted as an event source")
	}
	peerTests := map[string]string{
		"192.0.2.10:443":    "192.0.2.10",
		"[2001:db8::1]:443": "2001:db8::1",
		"::ffff:192.0.2.10": "192.0.2.10",
	}
	for input, expected := range peerTests {
		if got, ok := normalizePeer(input); !ok || got != expected {
			t.Errorf("normalizePeer(%q) = %q, %t; want %q, true", input, got, ok, expected)
		}
	}
	if _, ok := normalizePeer("synthetic-invalid-peer"); ok {
		t.Fatal("invalid peer was accepted")
	}
}

func TestImportRejectsUnsafeInputsAndOutput(t *testing.T) {
	t.Run("missing exact input", func(t *testing.T) {
		root := t.TempDir()
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		if err := os.Remove(filepath.Join(input, "error.log.gz")); err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o600)
		_, err := Run(testConfig(input, filepath.Join(root, "output"), keyFile))
		if err == nil || !strings.Contains(err.Error(), "required input error.log.gz is missing") {
			t.Fatalf("missing exact input was not rejected: %v", err)
		}
	})

	t.Run("insecure key mode", func(t *testing.T) {
		root := t.TempDir()
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o644)
		_, err := Run(testConfig(input, filepath.Join(root, "output"), keyFile))
		if err == nil || !strings.Contains(err.Error(), "owner-only") {
			t.Fatalf("unsafe key mode was not rejected: %v", err)
		}
	})

	t.Run("insecure input directory mode", func(t *testing.T) {
		root := t.TempDir()
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		if err := os.Chmod(input, 0o750); err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o600)
		_, err := Run(testConfig(input, filepath.Join(root, "output"), keyFile))
		if err == nil || !strings.Contains(err.Error(), "owner-only") {
			t.Fatalf("unsafe input directory mode was not rejected: %v", err)
		}
	})

	t.Run("insecure input file mode", func(t *testing.T) {
		root := t.TempDir()
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		if err := os.Chmod(filepath.Join(input, "access.log.gz"), 0o640); err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o600)
		_, err := Run(testConfig(input, filepath.Join(root, "output"), keyFile))
		if err == nil || !strings.Contains(err.Error(), "owner-only") {
			t.Fatalf("unsafe input file mode was not rejected: %v", err)
		}
	})

	t.Run("symlink input", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink semantics differ")
		}
		root := t.TempDir()
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		target := filepath.Join(input, "access-target.gz")
		if err := os.Rename(filepath.Join(input, "access.log.gz"), target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(input, "access.log.gz")); err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o600)
		_, err := Run(testConfig(input, filepath.Join(root, "output"), keyFile))
		if err == nil {
			t.Fatalf("symlink was not rejected: %v", err)
		}
	})

	t.Run("symlink key", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink semantics differ")
		}
		root := t.TempDir()
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		keyTarget := filepath.Join(root, "key-target")
		writeKey(t, keyTarget, 0o600)
		keyFile := filepath.Join(root, "key")
		if err := os.Symlink(keyTarget, keyFile); err != nil {
			t.Fatal(err)
		}
		_, err := Run(testConfig(input, filepath.Join(root, "output"), keyFile))
		if err == nil {
			t.Fatal("symlink key was accepted")
		}
	})

	t.Run("symlink parent", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink semantics differ")
		}
		root := t.TempDir()
		realParent := filepath.Join(root, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(realParent, "input")
		writeSyntheticBundle(t, input, 1)
		alias := filepath.Join(root, "alias")
		if err := os.Symlink(realParent, alias); err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o600)
		_, err := Run(testConfig(filepath.Join(alias, "input"), filepath.Join(root, "output"), keyFile))
		if err == nil {
			t.Fatal("symlinked input parent was accepted")
		}
	})

	t.Run("output in Git worktree", func(t *testing.T) {
		root := t.TempDir()
		worktree := filepath.Join(root, "worktree")
		if err := os.Mkdir(worktree, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(worktree, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o600)
		_, err := Run(testConfig(input, filepath.Join(worktree, "output"), keyFile))
		if err == nil || !strings.Contains(err.Error(), "outside every Git worktree") {
			t.Fatalf("Git-contained output was not rejected: %v", err)
		}
	})

	t.Run("input in Git worktree", func(t *testing.T) {
		root := t.TempDir()
		worktree := filepath.Join(root, "worktree")
		if err := os.Mkdir(worktree, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(worktree, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(worktree, "input")
		writeSyntheticBundle(t, input, 1)
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o600)
		_, err := Run(testConfig(input, filepath.Join(root, "output"), keyFile))
		if err == nil || !strings.Contains(err.Error(), "outside every Git worktree") {
			t.Fatalf("Git-contained input was not rejected: %v", err)
		}
	})

	t.Run("key in Git worktree", func(t *testing.T) {
		root := t.TempDir()
		worktree := filepath.Join(root, "worktree")
		if err := os.Mkdir(worktree, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(worktree, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		keyFile := filepath.Join(worktree, "key")
		writeKey(t, keyFile, 0o600)
		_, err := Run(testConfig(input, filepath.Join(root, "output"), keyFile))
		if err == nil || !strings.Contains(err.Error(), "outside every Git worktree") {
			t.Fatalf("Git-contained key was not rejected: %v", err)
		}
	})

	t.Run("existing output", func(t *testing.T) {
		root := t.TempDir()
		input := filepath.Join(root, "input")
		writeSyntheticBundle(t, input, 1)
		keyFile := filepath.Join(root, "key")
		writeKey(t, keyFile, 0o600)
		output := filepath.Join(root, "output")
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := Run(testConfig(input, output, keyFile))
		if err == nil || !strings.Contains(err.Error(), "refusing overwrite") {
			t.Fatalf("existing output was not rejected: %v", err)
		}
	})

	t.Run("future provenance", func(t *testing.T) {
		config := testConfig("synthetic", "synthetic", "synthetic")
		config.Provenance = "community_opt_in"
		_, err := Run(config)
		if err == nil || !strings.Contains(err.Error(), "only offline_export") {
			t.Fatalf("future provenance was not rejected: %v", err)
		}
	})

	t.Run("unknown Anubis peer source", func(t *testing.T) {
		config := testConfig("synthetic", "synthetic", "synthetic")
		config.AnubisPeerSource = "trust_every_header"
		_, err := Run(config)
		if err == nil || !strings.Contains(err.Error(), "unsupported Anubis peer source") {
			t.Fatalf("unknown Anubis peer source was not rejected: %v", err)
		}
	})
}

func TestMalformedLinesAreCountedWithoutRawOutput(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	keyFile := filepath.Join(root, "key")
	output := filepath.Join(root, "output")
	writeSyntheticBundle(t, input, 1)
	if err := os.Remove(filepath.Join(input, "access.log.gz")); err != nil {
		t.Fatal(err)
	}
	writeGzip(t, filepath.Join(input, "access.log.gz"), "synthetic malformed access row\n")
	if err := os.Remove(filepath.Join(input, "anubis-strain.jsonl.gz")); err != nil {
		t.Fatal(err)
	}
	writeGzip(t, filepath.Join(input, "anubis-strain.jsonl.gz"), "{synthetic malformed json}\n")
	writeKey(t, keyFile, 0o600)

	result, err := Run(testConfig(input, output, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if result.Invalid != 2 || result.Events != 2 {
		t.Fatalf("invalid=%d events=%d, want invalid=2 events=2", result.Invalid, result.Events)
	}
	encoded, err := os.ReadFile(filepath.Join(output, "events-000001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "synthetic malformed") {
		t.Fatal("malformed raw input reached normalized output")
	}
}

func TestShardingPermissionsDeterminismAndAtomicCleanup(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	keyFile := filepath.Join(root, "key")
	writeSyntheticBundle(t, input, 101)
	writeKey(t, keyFile, 0o600)
	firstOutput := filepath.Join(root, "first")
	secondOutput := filepath.Join(root, "second")
	firstConfig := testConfig(input, firstOutput, keyFile)
	firstConfig.ShardSize = MinimumShardSize
	firstConfig.SortChunkSize = MinimumSortChunkSize
	firstConfig.MaxEvents = 200
	first, err := Run(firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	secondConfig := testConfig(input, secondOutput, keyFile)
	secondConfig.ShardSize = MinimumShardSize
	secondConfig.SortChunkSize = MinimumSortChunkSize
	secondConfig.MaxEvents = 200
	second, err := Run(secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	firstManifest, _ := os.ReadFile(first.ManifestPath)
	secondManifest, _ := os.ReadFile(second.ManifestPath)
	if string(firstManifest) != string(secondManifest) {
		t.Fatal("manifest is not deterministic for identical input and config")
	}
	manifest := readManifest(t, first.ManifestPath)
	if len(manifest.Shards) != 2 {
		t.Fatalf("shards = %d, want 2", len(manifest.Shards))
	}
	assertMode(t, firstOutput, 0o700)
	for _, file := range append([]string{"manifest.json", "COMPLETE"}, manifestShardNames(manifest)...) {
		assertMode(t, filepath.Join(firstOutput, file), 0o600)
	}
	events := readEvents(t, firstOutput)
	for index := 1; index < len(events); index++ {
		previous, err := time.Parse(time.RFC3339Nano, events[index-1].ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		current, err := time.Parse(time.RFC3339Nano, events[index].ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		if current.Before(previous) {
			t.Fatalf("events are not globally chronological at %d across external sort runs or shards", index)
		}
	}
	var sourcesAtEqualTime []string
	for _, event := range events {
		if event.ObservedAt == "2026-01-12T01:01:00Z" {
			sourcesAtEqualTime = append(sourcesAtEqualTime, event.Source)
		}
	}
	if len(sourcesAtEqualTime) < 2 || sourcesAtEqualTime[len(sourcesAtEqualTime)-1] != "anubis" {
		t.Fatalf("equal-time stable source order was not preserved: %v", sourcesAtEqualTime)
	}

	overflowInput := filepath.Join(root, "overflow-input")
	writeSyntheticBundle(t, overflowInput, 1)
	writeGzipReplacing(t, filepath.Join(overflowInput, "access.log.gz"), strings.Repeat("x", MinimumMaxLineSize+1)+"\n")
	overflowOutput := filepath.Join(root, "overflow-output")
	overflowConfig := testConfig(overflowInput, overflowOutput, keyFile)
	overflowConfig.MaxLineBytes = MinimumMaxLineSize
	_, err = Run(overflowConfig)
	if err == nil {
		t.Fatal("oversized decompressed line was accepted")
	}
	if _, statErr := os.Stat(overflowOutput); !os.IsNotExist(statErr) {
		t.Fatalf("incomplete output was not removed: %v", statErr)
	}
}

func TestHardBudgetsFailClosedWithoutPublishedOutput(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	keyFile := filepath.Join(root, "key")
	writeSyntheticBundle(t, input, 101)
	writeKey(t, keyFile, 0o600)
	tests := []struct {
		name string
		set  func(*Config)
		want error
	}{
		{"decompressed", func(config *Config) { config.MaxDecompressedBytes = 1 }, ErrDecompressedBudget},
		{"records", func(config *Config) { config.MaxInputRecords = 1 }, ErrRecordBudget},
		{"events", func(config *Config) { config.MaxEvents = 1 }, ErrEventBudget},
		{"shards", func(config *Config) { config.ShardSize = MinimumShardSize; config.MaxShards = 1 }, ErrShardBudget},
		{"output", func(config *Config) { config.MaxOutputBytes = 1 }, ErrOutputBudget},
		{"working", func(config *Config) {
			config.SortChunkSize = MinimumSortChunkSize
			config.MaxEvents = 100
			config.MaxWorkingBytes = 1
		}, ErrWorkingBudget},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(root, "output-"+test.name)
			config := testConfig(input, output, keyFile)
			test.set(&config)
			_, err := Run(config)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want sentinel %v", err, test.want)
			}
			if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
				t.Fatalf("budget failure published output: %v", statErr)
			}
		})
	}
}

func TestConfigBoundsShardNamesAndSortRunMetadata(t *testing.T) {
	config := testConfig("synthetic-input", "synthetic-output", "synthetic-key")
	config.MaxShards = MaximumShardCount + 1
	if _, err := normalizeConfig(config); err == nil || !strings.Contains(err.Error(), "maximum shards") {
		t.Fatalf("oversized shard budget was accepted: %v", err)
	}
	config = testConfig("synthetic-input", "synthetic-output", "synthetic-key")
	config.SortChunkSize = MinimumSortChunkSize
	config.MaxEvents = uint64(MaximumSortRuns*MinimumSortChunkSize + 1)
	if _, err := normalizeConfig(config); err == nil || !strings.Contains(err.Error(), "initial sort runs") {
		t.Fatalf("oversized sort-run metadata budget was accepted: %v", err)
	}
}

func TestZeroEventManifestUsesEmptyShardArray(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	keyFile := filepath.Join(root, "key")
	output := filepath.Join(root, "output")
	writeSyntheticBundle(t, input, 1)
	writeGzipReplacing(t, filepath.Join(input, "access.log.gz"), "")
	writeGzipReplacing(t, filepath.Join(input, "anubis-strain.jsonl.gz"), "")
	writeFileReplacing(t, filepath.Join(input, "crowdsec-alerts.json"), "[]", 0o600)
	writeFileReplacing(t, filepath.Join(input, "crowdsec-decisions.json"), "[]", 0o600)
	writeKey(t, keyFile, 0o600)
	result, err := Run(testConfig(input, output, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 0 {
		t.Fatalf("events = %d, want 0", result.Events)
	}
	manifest := readManifest(t, result.ManifestPath)
	if manifest.Shards == nil || len(manifest.Shards) != 0 {
		t.Fatalf("zero-event shards must be a non-null empty array: %#v", manifest.Shards)
	}
	encoded, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"shards": []`) {
		t.Fatalf("zero-event manifest encoded null shards: %s", encoded)
	}
}

func TestSkippedRangesAndUntrustedForwarding(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	keyFile := filepath.Join(root, "key")
	output := filepath.Join(root, "output")
	writeSyntheticBundle(t, input, 1)
	writeGzipReplacing(t, filepath.Join(input, "access.log.gz"), `invalid-peer - - [12/Jan/2026:00:59:00 +0000] "GET /compare HTTP/1.1" 200 1 "-" "SyntheticFixture/1.0" "198.51.100.1"`+"\n")
	writeGzipReplacing(t, filepath.Join(input, "anubis-strain.jsonl.gz"), `{"observed_at":"2026-01-12T01:01:00Z","x-real-ip":"198.51.100.1","forwarded":"for=198.51.100.1","path":"/compare"}`+"\n")
	writeKey(t, keyFile, 0o600)
	result, err := Run(testConfig(input, output, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 2 {
		t.Fatalf("events = %d, want only the two CrowdSec events", result.Events)
	}
	manifest := readManifest(t, result.ManifestPath)
	for _, inputStats := range manifest.Inputs {
		switch inputStats.Filename {
		case "access.log.gz", "anubis-strain.jsonl.gz":
			if inputStats.Skipped != 1 || inputStats.FirstObservedAt == "" || inputStats.LastObservedAt == "" {
				t.Fatalf("parseable skipped record missing range: %+v", inputStats)
			}
		case "error.log.gz":
			if inputStats.FirstObservedAt != "" || inputStats.LastObservedAt != "" {
				t.Fatalf("count-only error log retained a time range: %+v", inputStats)
			}
		}
	}
}

func TestTrustedAnubisRealIPRequiresExplicitModeAndIgnoresHeaderMaps(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	keyFile := filepath.Join(root, "key")
	output := filepath.Join(root, "output")
	writeSyntheticBundle(t, input, 1)
	writeGzipReplacing(t, filepath.Join(input, "access.log.gz"), "")
	writeGzipReplacing(t, filepath.Join(input, "anubis-strain.jsonl.gz"), `{"observed_at":"2026-01-12T01:01:00Z","x-real-ip":"198.51.100.25:443","path":"/compare","headers":{"X-Real-IP":"203.0.113.99"},"challenge":true,"check_result":{"name":"failed","weight":0.81}}`+"\n")
	writeFileReplacing(t, filepath.Join(input, "crowdsec-alerts.json"), "[]", 0o600)
	writeFileReplacing(t, filepath.Join(input, "crowdsec-decisions.json"), "[]", 0o600)
	writeGzipReplacing(t, filepath.Join(input, "error.log.gz"), "")
	writeKey(t, keyFile, 0o600)

	config := testConfig(input, output, keyFile)
	config.AnubisPeerSource = AnubisPeerTrustedReal
	result, err := Run(config)
	if err != nil {
		t.Fatal(err)
	}
	events := readEvents(t, output)
	if len(events) != 1 || events[0].Source != "anubis" {
		t.Fatalf("trusted Anubis event missing: %+v", events)
	}
	pseudonyms := newPseudonymizer([]byte("fixture-key-material-with-at-least-32-bytes"), "synthetic-dataset", "synthetic-pilot")
	defer pseudonyms.Wipe()
	wantSubject := pseudonyms.pseudonym("subject", time.Date(2026, 1, 12, 1, 1, 0, 0, time.UTC), syntheticXFF, "")
	if events[0].SubjectID != wantSubject {
		t.Fatal("trusted top-level x-real-ip was not used, or an arbitrary header-map value was trusted")
	}
	if events[0].SourceVerdict != "failed" || events[0].Features.WeightBucket == 0 {
		t.Fatalf("nested Anubis result was not normalized: %+v", events[0])
	}
	manifest := readManifest(t, result.ManifestPath)
	if manifest.Config.AnubisPeerSource != AnubisPeerTrustedReal {
		t.Fatalf("manifest peer source = %q", manifest.Config.AnubisPeerSource)
	}
	if !slices.Contains(manifest.Warnings, "Anubis x-real-ip is trusted under an operator-asserted Cloudflare edge boundary and used only transiently") {
		t.Fatalf("manifest does not record trust assertion: %+v", manifest.Warnings)
	}
}

func TestInputMutationIsDetectedByConsumedFileRehash(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "synthetic.json")
	writeFile(t, path, "synthetic-before", 0o600)
	path, err := canonicalExistingPath(path)
	if err != nil {
		t.Fatal(err)
	}
	file, stats, err := openInput(path, "synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	writeFileReplacing(t, path, "synthetic-after-", 0o600)
	if err := verifyInput(file, path, stats); !errors.Is(err, ErrInputChanged) {
		t.Fatalf("verifyInput error = %v, want ErrInputChanged", err)
	}
	_ = file.Close()
}

func TestOversizedCrowdSecItemIsBoundedAndCleanedUp(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "input")
	keyFile := filepath.Join(root, "key")
	output := filepath.Join(root, "output")
	writeSyntheticBundle(t, input, 1)
	if err := os.Remove(filepath.Join(input, "crowdsec-alerts.json")); err != nil {
		t.Fatal(err)
	}
	oversized := fmt.Sprintf(`[{"created_at":"2026-01-12T01:02:00Z","source":{"ip":"%s"},"ignored":"%s"}]`, syntheticPeer, strings.Repeat("x", MinimumMaxLineSize))
	writeFile(t, filepath.Join(input, "crowdsec-alerts.json"), oversized, 0o600)
	writeKey(t, keyFile, 0o600)

	config := testConfig(input, output, keyFile)
	config.MaxLineBytes = MinimumMaxLineSize
	_, err := Run(config)
	if err == nil || !strings.Contains(err.Error(), "item exceeds size limit") {
		t.Fatalf("oversized CrowdSec item was not rejected: %v", err)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("partial output survived oversized CrowdSec item: %v", statErr)
	}
}

func writeSyntheticBundle(t *testing.T, dir string, accessRecords int) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var access strings.Builder
	for index := 0; index < accessRecords; index++ {
		fmt.Fprintf(&access, `%s - - [12/Jan/2026:01:%02d:00 +0000] "GET /compare?fixture=synthetic-query-value HTTP/1.1" 200 2048 "https://synthetic-referrer.invalid/" "%s" "%s"`+"\n", syntheticPeer, index%60, syntheticUA, syntheticXFF)
	}
	writeGzip(t, filepath.Join(dir, "access.log.gz"), access.String())
	anubis := fmt.Sprintf(`{"observed_at":"2026-01-12T01:01:00Z","request":{"remote_addr":"%s:443","path":"/.within.website/x/challenge?fixture=discarded","method":"POST","status":403,"user_agent":"%s","headers":{"X-Real-IP":"%s"}},"challenge":{"rule":"synthetic-rule-free-text"},"check_result":"failed","weight":0.81}`+"\n", syntheticPeer, syntheticUA, syntheticXFF)
	writeGzip(t, filepath.Join(dir, "anubis-strain.jsonl.gz"), anubis)
	writeFile(t, filepath.Join(dir, "crowdsec-alerts.json"), fmt.Sprintf(`[{"alert":{"created_at":"2026-01-12T01:02:00Z","scenario":"crowdsecurity/http-probing","source":{"ip":"%s"}},"message":"synthetic-rule-free-text"}]`, syntheticPeer), 0o600)
	writeFile(t, filepath.Join(dir, "crowdsec-decisions.json"), fmt.Sprintf(`[{"decision":{"start_at":"2026-01-12T01:03:00Z","scenario":"synthetic/unrecognized-scenario","type":"ip","value":"%s"}}]`, syntheticPeer), 0o600)
	writeGzip(t, filepath.Join(dir, "error.log.gz"), "2026/01/12 01:04:00 synthetic-error-message\n")
}

func writeGzip(t *testing.T, path, content string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	writer.ModTime = time.Unix(0, 0)
	writer.Name = ""
	if _, err := writer.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeGzipReplacing(t *testing.T, path, content string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeGzip(t, path, content)
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeFileReplacing(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeKey(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	writeFile(t, path, "fixture-key-material-with-at-least-32-bytes", mode)
}

func readEvents(t *testing.T, output string) []Event {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(output, "events-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var event Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				t.Fatal(err)
			}
			events = append(events, event)
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
	}
	return events
}

func readManifest(t *testing.T, path string) Manifest {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func assertMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != expected {
		t.Fatalf("%s mode = %o, want %o", filepath.Base(path), mode, expected)
	}
}

func manifestShardNames(manifest Manifest) []string {
	names := make([]string, 0, len(manifest.Shards))
	for _, shard := range manifest.Shards {
		names = append(names, shard.Filename)
	}
	return names
}
