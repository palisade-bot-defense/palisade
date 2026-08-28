package palisadehttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSignedCrawlerRegistryLifecycleAndLastKnownGood(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	registry, err := NewSignedCrawlerRegistry(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if status := registry.Status(now); status.State != "empty" {
		t.Fatalf("initial status=%+v", status)
	}
	if verified, _, _ := registry.verifyAt("ExampleSearchBot/1.0", netip.MustParseAddr("192.0.2.10"), now); verified {
		t.Fatal("empty signed registry verified a crawler")
	}

	document := signedCrawlerFixture(t, privateKey, 1, now, now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24")
	if err := registry.UpdateSignedJSON(document, now); err != nil {
		t.Fatal(err)
	}
	verified, class, method := registry.verifyAt("ExampleSearchBot/1.0", netip.MustParseAddr("192.0.2.10"), now)
	if !verified || class != CrawlerClassSearchIndexer || method != CrawlerVerificationIPUARegistry {
		t.Fatalf("verified tuple=%t/%s/%s", verified, class, method)
	}
	status := registry.Status(now)
	if status.State != "current" || status.Revision != 1 || status.IdentityCount != 1 || status.PrefixCount != 1 || len(status.DigestSHA256) != 64 {
		t.Fatalf("current status=%+v", status)
	}

	tampered := append([]byte(nil), document...)
	tampered = []byte(strings.Replace(string(tampered), "search_indexer", "answer_engine", 1))
	if err := registry.UpdateSignedJSON(tampered, now); !errors.Is(err, ErrInvalidCrawlerRegistry) {
		t.Fatalf("tampered error=%v", err)
	}
	verified, class, _ = registry.verifyAt("ExampleSearchBot/1.0", netip.MustParseAddr("192.0.2.10"), now)
	if !verified || class != CrawlerClassSearchIndexer || registry.Status(now).Revision != 1 {
		t.Fatal("invalid update replaced last known-good snapshot")
	}

	if err := registry.UpdateSignedJSON(document, now); !errors.Is(err, ErrCrawlerRegistryUnchanged) {
		t.Fatalf("replayed revision error=%v", err)
	}
	rollback := signedCrawlerFixture(t, privateKey, 1, now, now.Add(time.Hour), CrawlerClassAnswerEngine, "198.51.100.0/24")
	if err := registry.UpdateSignedJSON(rollback, now); !errors.Is(err, ErrCrawlerRegistryRollback) {
		t.Fatalf("changed non-increasing revision error=%v", err)
	}
	_, wrongPrivateKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongSigner := signedCrawlerFixture(t, wrongPrivateKey, 2, now, now.Add(time.Hour), CrawlerClassAnswerEngine, "198.51.100.0/24")
	if err := registry.UpdateSignedJSON(wrongSigner, now); !errors.Is(err, ErrInvalidCrawlerRegistry) {
		t.Fatalf("wrong signer error=%v", err)
	}
	if status := registry.Status(now); status.Revision != 1 || status.State != "current" {
		t.Fatalf("rejected update changed status=%+v", status)
	}
	if verified, _, _ := registry.verifyAt("ExampleSearchBot/1.0", netip.MustParseAddr("192.0.2.10"), now.Add(time.Hour)); verified {
		t.Fatal("expired registry continued to verify crawler")
	}
	if status := registry.Status(now.Add(time.Hour)); status.State != "expired" || status.Revision != 1 {
		t.Fatalf("expired status=%+v", status)
	}
}

func TestSignedCrawlerRegistryRejectsInvalidTimeSchemaAndEnvelope(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0).UTC()
	tests := []struct {
		name    string
		payload CrawlerRegistryPayload
		want    error
	}{
		{name: "expired", payload: crawlerPayload(1, now.Add(-2*time.Hour), now.Add(-time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24"), want: ErrCrawlerRegistryExpired},
		{name: "future issue", payload: crawlerPayload(1, now.Add(6*time.Minute), now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24"), want: ErrInvalidCrawlerRegistry},
		{name: "excess lifetime", payload: crawlerPayload(1, now, now.Add(32*24*time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24"), want: ErrInvalidCrawlerRegistry},
		{name: "zero revision", payload: crawlerPayload(0, now, now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24"), want: ErrInvalidCrawlerRegistry},
		{name: "wrong schema", payload: func() CrawlerRegistryPayload {
			value := crawlerPayload(1, now, now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24")
			value.SchemaVersion = "future"
			return value
		}(), want: ErrInvalidCrawlerRegistry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry, err := NewSignedCrawlerRegistry(publicKey)
			if err != nil {
				t.Fatal(err)
			}
			document, err := EncodeSignedCrawlerRegistry(test.payload, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := registry.UpdateSignedJSON(document, now); !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}

	registry, _ := NewSignedCrawlerRegistry(publicKey)
	valid := signedCrawlerFixture(t, privateKey, 1, now, now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24")
	unknown := []byte(strings.Replace(string(valid), `"signature":`, `"unexpected":true,"signature":`, 1))
	if err := registry.UpdateSignedJSON(unknown, now); !errors.Is(err, ErrInvalidCrawlerRegistry) {
		t.Fatalf("unknown envelope field error=%v", err)
	}
	if err := registry.UpdateSignedJSON(append(valid, []byte(` {}`)...), now); !errors.Is(err, ErrInvalidCrawlerRegistry) {
		t.Fatalf("trailing document error=%v", err)
	}
	if err := registry.UpdateSignedJSON(make([]byte, maxSignedCrawlerRegistrySize+1), now); !errors.Is(err, ErrInvalidCrawlerRegistry) {
		t.Fatalf("oversize error=%v", err)
	}
}

func TestSignedCrawlerRegistryFileAndConcurrentAtomicUpdates(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0).UTC()
	registry, _ := NewSignedCrawlerRegistry(publicKey)
	path := filepath.Join(t.TempDir(), "crawler-registry.json")
	first := signedCrawlerFixture(t, privateKey, 1, now, now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := registry.UpdateSignedFile(path, now); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	for reader := 0; reader < 8; reader++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 500; iteration++ {
				verified, class, method := registry.verifyAt("ExampleSearchBot/1.0", netip.MustParseAddr("192.0.2.10"), now)
				if verified && (class != CrawlerClassSearchIndexer || method != CrawlerVerificationIPUARegistry) {
					t.Errorf("torn verified tuple=%t/%s/%s", verified, class, method)
				}
			}
		}()
	}
	var writers sync.WaitGroup
	for revision := uint64(2); revision <= 20; revision++ {
		writers.Add(1)
		go func(revision uint64) {
			defer writers.Done()
			document, err := EncodeSignedCrawlerRegistry(
				crawlerPayload(revision, now, now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24"),
				privateKey,
			)
			if err != nil {
				t.Errorf("revision %d encode error=%v", revision, err)
				return
			}
			if err := registry.UpdateSignedJSON(document, now); err != nil && !errors.Is(err, ErrCrawlerRegistryRollback) {
				t.Errorf("revision %d update error=%v", revision, err)
			}
		}(revision)
	}
	writers.Wait()
	wait.Wait()
	if status := registry.Status(now); status.State != "current" || status.Revision != 20 {
		t.Fatalf("final status=%+v", status)
	}
}

func TestSignedCrawlerRegistryWatcherLoadsBeforeServingAndReportsClosedStatus(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	registry, _ := NewSignedCrawlerRegistry(publicKey)
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "crawler-registry.json")
	if err := os.WriteFile(path, signedCrawlerFixture(t, privateKey, 1, now, now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var events []CrawlerRegistryReloadEvent
	if err := registry.WatchSignedFile(ctx, path, minCrawlerRegistryWatch, func(event CrawlerRegistryReloadEvent) {
		events = append(events, event)
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].State != "updated" || events[0].Reason != "accepted" ||
		events[0].Status.State != "current" || events[0].Status.Revision != 1 {
		t.Fatalf("watch events=%+v", events)
	}
	encoded, _ := json.Marshal(events[0])
	for _, forbidden := range []string{"192.0.2.0", "ExampleSearchBot", path, "example-search"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("watch event exposed %q: %s", forbidden, encoded)
		}
	}
	if err := registry.WatchSignedFile(context.Background(), path, time.Second, nil); !errors.Is(err, ErrInvalidCrawlerRegistry) {
		t.Fatalf("short interval error=%v", err)
	}
}

func TestSignedCrawlerRegistryWatcherAcceptsPreloadedDocument(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	registry, _ := NewSignedCrawlerRegistry(publicKey)
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "crawler-registry.json")
	if err := os.WriteFile(path, signedCrawlerFixture(t, privateKey, 1, now, now.Add(time.Hour), CrawlerClassSearchIndexer, "192.0.2.0/24"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := registry.UpdateSignedFile(path, now); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var events []CrawlerRegistryReloadEvent
	if err := registry.WatchSignedFile(ctx, path, minCrawlerRegistryWatch, func(event CrawlerRegistryReloadEvent) {
		events = append(events, event)
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].State != "unchanged" || events[0].Reason != "same_document" || events[0].Status.Revision != 1 {
		t.Fatalf("watch events=%+v", events)
	}
}

func signedCrawlerFixture(t *testing.T, privateKey ed25519.PrivateKey, revision uint64, issuedAt, expiresAt time.Time, class, cidr string) []byte {
	t.Helper()
	encoded, err := EncodeSignedCrawlerRegistry(crawlerPayload(revision, issuedAt, expiresAt, class, cidr), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func crawlerPayload(revision uint64, issuedAt, expiresAt time.Time, class, cidr string) CrawlerRegistryPayload {
	return CrawlerRegistryPayload{
		SchemaVersion: CrawlerRegistrySchemaVersion, Revision: revision,
		IssuedAt: issuedAt.UTC().Format(time.RFC3339), ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		Entries: []CrawlerIdentity{{
			Name: "example-search", Class: class, UserAgentTokens: []string{"ExampleSearchBot"}, CIDRs: []string{cidr},
		}},
	}
}
