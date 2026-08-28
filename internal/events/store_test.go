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

func TestIngestReceiptUsesContiguousServerBatchSequence(t *testing.T) {
	store := NewStore(time.Minute)
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	first, err := store.IngestWithReceipt(Batch{
		SessionID: "session-12345678", SensorVersion: "0.2.0",
		Events: []BrowserEvent{{Sequence: 1, Kind: "navigation"}, {Sequence: 25, Kind: "pointer"}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	secondBatch := Batch{
		SessionID: "session-12345678", SensorVersion: "0.2.0",
		Events: []BrowserEvent{{Sequence: 50, Kind: "scroll"}, {Sequence: 64, Kind: "visibility"}},
	}
	second, err := store.IngestWithReceipt(secondBatch, now.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.IngestWithReceipt(secondBatch, now.Add(16*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.BatchSequence != 1 || second.BatchSequence != 2 || retry.BatchSequence != 3 {
		t.Fatalf("batch sequences = %d, %d, %d; want 1, 2, 3", first.BatchSequence, second.BatchSequence, retry.BatchSequence)
	}
	if first.TotalAcceptedEvents != 2 || second.TotalAcceptedEvents != 4 || retry.TotalAcceptedEvents != 4 || retry.AcceptedEvents != 0 {
		t.Fatalf("unexpected receipts: first=%+v second=%+v retry=%+v", first, second, retry)
	}
}

func TestIngestReceiptResetsAfterSessionTTL(t *testing.T) {
	store := NewStore(time.Minute)
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	batch := Batch{SessionID: "session-12345678", SensorVersion: "0.2.0", Events: []BrowserEvent{{Sequence: 1, Kind: "navigation"}}}
	if _, err := store.IngestWithReceipt(batch, now); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.IngestWithReceipt(batch, now.Add(time.Minute+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.BatchSequence != 1 || receipt.TotalAcceptedEvents != 1 {
		t.Fatalf("receipt after TTL = %+v, want a new bounded session", receipt)
	}
}
