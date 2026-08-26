package session

import (
	"testing"
	"time"
)

func TestObserveTracksSequenceGap(t *testing.T) {
	store := NewMemoryStore(5*time.Minute, 100)
	now := time.Unix(1_800_000_000, 0)
	store.Observe("s", 1, now)
	snapshot := store.Observe("s", 5, now.Add(time.Second))
	if snapshot.RequestCount != 2 || snapshot.MaxSequenceGap != 3 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}
