package offlineimport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestHardBudgetsFailClosedWithoutPublishedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	tests := []struct {
		name      string
		events    int
		configure func(*LocalConfig)
		want      error
	}{
		{name: "input bytes", events: 1, configure: func(config *LocalConfig) { config.MaxInputBytes = 1 }, want: ErrInputByteBudget},
		{name: "records", events: 2, configure: func(config *LocalConfig) { config.MaxInputRecords = 1 }, want: ErrRecordBudget},
		{name: "events", events: 2, configure: func(config *LocalConfig) { config.MaxEvents = 1 }, want: ErrEventBudget},
		{name: "shards", events: 101, configure: func(config *LocalConfig) {
			config.ShardSize = MinimumShardSize
			config.MaxShards = 1
		}, want: ErrShardBudget},
		{name: "output bytes", events: 1, configure: func(config *LocalConfig) { config.MaxOutputBytes = 1 }, want: ErrOutputBudget},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "operator-events.jsonl")
			key := filepath.Join(root, "pseudonym.key")
			output := filepath.Join(root, "normalized")
			writeSyntheticLocalInput(t, input, test.events)
			writePrivateTestFile(t, key, bytes.Repeat([]byte{0x42}, 32))
			config := LocalConfig{
				InputFile: input, OutputDir: output, PseudonymKeyFile: key,
				DatasetID: "synthetic-dataset", PilotID: "synthetic-pilot",
			}
			test.configure(&config)
			_, err := RunLocal(config)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
				t.Fatalf("failed import published output: %v", statErr)
			}
		})
	}
}

func TestRunLocalRejectsUnsafePrivateBoundaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner-only mode semantics require a Unix filesystem")
	}
	t.Run("insecure input mode", func(t *testing.T) {
		root, input, key := localBoundaryFixture(t)
		if err := os.Chmod(input, 0o644); err != nil {
			t.Fatal(err)
		}
		assertLocalImportRejected(t, input, key, filepath.Join(root, "output"))
	})
	t.Run("insecure key mode", func(t *testing.T) {
		root, input, key := localBoundaryFixture(t)
		if err := os.Chmod(key, 0o644); err != nil {
			t.Fatal(err)
		}
		assertLocalImportRejected(t, input, key, filepath.Join(root, "output"))
	})
	t.Run("input symlink", func(t *testing.T) {
		root, input, key := localBoundaryFixture(t)
		link := filepath.Join(root, "input-link")
		if err := os.Symlink(input, link); err != nil {
			t.Fatal(err)
		}
		assertLocalImportRejected(t, link, key, filepath.Join(root, "output"))
	})
	t.Run("key symlink", func(t *testing.T) {
		root, input, key := localBoundaryFixture(t)
		link := filepath.Join(root, "key-link")
		if err := os.Symlink(key, link); err != nil {
			t.Fatal(err)
		}
		assertLocalImportRejected(t, input, link, filepath.Join(root, "output"))
	})
	t.Run("inside Git worktree", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(root, "operator-events.jsonl")
		key := filepath.Join(root, "pseudonym.key")
		writeSyntheticLocalInput(t, input, 1)
		writePrivateTestFile(t, key, bytes.Repeat([]byte{0x42}, 32))
		assertLocalImportRejected(t, input, key, filepath.Join(t.TempDir(), "output"))
	})
	t.Run("existing output", func(t *testing.T) {
		root, input, key := localBoundaryFixture(t)
		output := filepath.Join(root, "output")
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Fatal(err)
		}
		assertLocalImportRejected(t, input, key, output)
	})
	t.Run("input equals key", func(t *testing.T) {
		root, _, key := localBoundaryFixture(t)
		assertLocalImportRejected(t, key, key, filepath.Join(root, "output"))
	})
}

func TestPseudonymsRotateDailyAndSeparatePilotDomains(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	first := newPseudonymizer(key, "dataset", "pilot-a")
	second := newPseudonymizer(key, "dataset", "pilot-b")
	defer first.Wipe()
	defer second.Wipe()
	dayOne := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	dayTwo := dayOne.Add(24 * time.Hour)
	firstDay := first.pseudonym("subject", dayOne, "synthetic-client", "")
	if firstDay == first.pseudonym("session", dayOne, "synthetic-client", "synthetic-agent") {
		t.Fatal("subject and session pseudonym domains overlap")
	}
	if firstDay == first.pseudonym("subject", dayTwo, "synthetic-client", "") {
		t.Fatal("daily pseudonym rotation did not change the identifier")
	}
	if firstDay == second.pseudonym("subject", dayOne, "synthetic-client", "") {
		t.Fatal("pilot domains did not separate identifiers")
	}
}

func TestInputMutationIsDetectedByRehash(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "operator-events.jsonl")
	writePrivateTestFile(t, path, []byte("synthetic-before"))
	canonical, err := canonicalExistingPath(path)
	if err != nil {
		t.Fatal(err)
	}
	file, stats, err := openInput(canonical, "operator-events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writePrivateTestFile(t, canonical, []byte("synthetic-after-"))
	if err := verifyInput(file, canonical, stats); !errors.Is(err, ErrInputChanged) {
		t.Fatalf("verifyInput error = %v, want ErrInputChanged", err)
	}
}

func localBoundaryFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	input := filepath.Join(root, "operator-events.jsonl")
	key := filepath.Join(root, "pseudonym.key")
	writeSyntheticLocalInput(t, input, 1)
	writePrivateTestFile(t, key, bytes.Repeat([]byte{0x42}, 32))
	return root, input, key
}

func assertLocalImportRejected(t *testing.T, input, key, output string) {
	t.Helper()
	_, err := RunLocal(LocalConfig{
		InputFile: input, OutputDir: output, PseudonymKeyFile: key,
		DatasetID: "synthetic-dataset", PilotID: "synthetic-pilot",
	})
	if err == nil {
		t.Fatal("unsafe local import boundary was accepted")
	}
}

func writeSyntheticLocalInput(t *testing.T, path string, count int) {
	t.Helper()
	var content strings.Builder
	for index := 0; index < count; index++ {
		event := validLocalInputEvent()
		event.ObservedAt = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC).Add(time.Duration(index) * time.Second).Format(time.RFC3339)
		event.SubjectRef = fmt.Sprintf("synthetic-client-%06d", index)
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		content.Write(encoded)
		content.WriteByte('\n')
	}
	writePrivateTestFile(t, path, []byte(content.String()))
}

func writePrivateTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
