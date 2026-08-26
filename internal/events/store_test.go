package events

import (
	"testing"
	"time"
)

func TestStoreDeduplicatesSequences(t *testing.T) {
	store := NewStore(time.Minute)
	now := time.Now().UTC()
	batch := Batch{SessionID: "session-12345678", SensorVersion: "0.1.0", Events: []BrowserEvent{{Sequence: 1, Kind: "scroll"}, {Sequence: 2, Kind: "pointer"}}}
	if err := store.Ingest(batch, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(batch, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := store.Count(batch.SessionID, now.Add(2*time.Second)); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
}
