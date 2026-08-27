package session

import (
	"testing"
	"time"
)

func TestObserveTracksSequenceGap(t *testing.T) {
	store := NewMemoryStore(5*time.Minute, 100)
	now := time.Unix(1_800_000_000, 0)
	store.Observe("s", 1, "public_content", now)
	snapshot := store.Observe("s", 5, "account", now.Add(time.Second))
	if snapshot.RequestCount != 2 || snapshot.MaxSequenceGap != 3 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestObserveTracksBoundedNavigationGraph(t *testing.T) {
	store := NewMemoryStore(5*time.Minute, 100)
	now := time.Unix(1_800_000_000, 0)
	endpoints := []string{"public_content", "compare_index", "compare_noindex", "account", "public_content"}
	for index, endpoint := range endpoints {
		store.Observe("navigation", uint64(index+1), endpoint, now.Add(time.Duration(index)*time.Second))
	}
	current := store.Observe("navigation", 6, "public_content", now.Add(6*time.Second))
	if current.DistinctEndpointClasses != 4 || current.EndpointTransitions != 4 {
		t.Fatalf("navigation snapshot = %+v", current)
	}
	poisoned := store.Observe("navigation", 2, "checkout", now.Add(7*time.Second))
	if poisoned.DistinctEndpointClasses != 4 || poisoned.EndpointTransitions != 4 {
		t.Fatalf("out-of-order endpoint poisoned graph = %+v", poisoned)
	}
}

func TestStoreEvictsAtCapacity(t *testing.T) {
	store := NewMemoryStore(5*time.Minute, 2)
	now := time.Unix(1_800_000_000, 0)
	store.Observe("oldest", 1, "public_content", now)
	store.Observe("newer", 1, "public_content", now.Add(time.Second))
	store.Observe("newest", 1, "public_content", now.Add(2*time.Second))
	if len(store.entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(store.entries))
	}
	if _, exists := store.entries["oldest"]; exists {
		t.Fatal("oldest live session was not evicted at capacity")
	}
}
