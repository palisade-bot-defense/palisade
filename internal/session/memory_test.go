package session

import (
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
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

func TestEnforcementHistoryIsBoundedToLiveSessionAndDetectsPrematureRetry(t *testing.T) {
	store := NewMemoryStore(5*time.Minute, 100)
	now := time.Unix(1_800_000_000, 0).UTC()
	store.Observe("response-cost", 1, "public_content", now)
	store.RecordEnforcement("response-cost", core.EnforcementDirective{
		Handling: "throttle", RetryAfterSeconds: 5, ExpiresAt: now.Add(5 * time.Second),
	}, now)
	early := store.Observe("response-cost", 2, "public_content", now.Add(time.Second))
	if early.RecentEnforcements != 1 || early.PrematureRetries != 1 {
		t.Fatalf("early retry snapshot = %+v", early)
	}
	store.RecordEnforcement("response-cost", core.EnforcementDirective{
		Handling: "challenge", ExpiresAt: now.Add(time.Minute),
	}, now.Add(time.Second))
	onTime := store.Observe("response-cost", 3, "public_content", now.Add(6*time.Second))
	if onTime.RecentEnforcements != 2 || onTime.PrematureRetries != 1 {
		t.Fatalf("on-time snapshot = %+v", onTime)
	}
	reset := store.Observe("response-cost", 4, "public_content", now.Add(6*time.Minute))
	if reset.RecentEnforcements != 0 || reset.PrematureRetries != 0 {
		t.Fatalf("expired response history survived session TTL: %+v", reset)
	}
}

func TestRecordEnforcementIgnoresPassUnknownAndMissingSession(t *testing.T) {
	store := NewMemoryStore(time.Minute, 10)
	now := time.Unix(1_800_000_000, 0).UTC()
	store.Observe("known", 1, "public_content", now)
	store.RecordEnforcement("known", core.EnforcementDirective{Handling: "pass"}, now)
	store.RecordEnforcement("known", core.EnforcementDirective{Handling: "invented"}, now)
	store.RecordEnforcement("known", core.EnforcementDirective{Handling: "throttle", RetryAfterSeconds: 61}, now)
	store.RecordEnforcement("known", core.EnforcementDirective{Handling: "challenge", RetryAfterSeconds: 1}, now)
	store.RecordEnforcement("missing", core.EnforcementDirective{Handling: "block", RetryAfterSeconds: 60}, now)
	snapshot := store.Observe("known", 2, "public_content", now.Add(time.Second))
	if snapshot.RecentEnforcements != 0 || snapshot.PrematureRetries != 0 || len(store.entries) != 1 {
		t.Fatalf("invalid directive created response history: snapshot=%+v entries=%d", snapshot, len(store.entries))
	}
}
