package palisadeedge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestSignedEnvelopeRoundTripAndReplayRejection(t *testing.T) {
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	verifier := newTestVerifier(t, now, 10)
	signals := Signals{
		ChallengeVerdict: "failed", ExternalRiskScore: .82, PolicyAlert: true,
		EdgeFingerprintClass: "automation_consistent", EdgeFingerprintMethod: "tls_http2",
		NetworkReputation: "high_risk", NetworkType: "hosting",
	}
	request := signedRequest(t, now, [16]byte{1}, signals, "203.0.113.8:443")
	got, present, err := verifier.Verify(request)
	if err != nil || !present || got != signals {
		t.Fatalf("verify = %+v/%v/%v", got, present, err)
	}
	if _, present, err := verifier.Verify(request); !errors.Is(err, ErrReplay) || present {
		t.Fatalf("replay = present %v err %v", present, err)
	}
}

func TestUntrustedPeerCannotInjectOrBreakSignals(t *testing.T) {
	verifier := newTestVerifier(t, time.Now().UTC().Truncate(time.Second), 10)
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
	request.RemoteAddr = "198.51.100.9:443"
	request.Header.Set(PayloadHeader, "attacker-controlled")
	request.Header.Set(SignatureHeader, "attacker-controlled")
	got, present, err := verifier.Verify(request)
	if err != nil || present || got != (Signals{}) {
		t.Fatalf("untrusted envelope = %+v/%v/%v", got, present, err)
	}
}

func TestTrustedPeerEnvelopeFailuresAreClosed(t *testing.T) {
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	validSignals := Signals{PolicyAlert: true}
	for name, mutate := range map[string]func(*http.Request){
		"partial":        func(request *http.Request) { request.Header.Del(SignatureHeader) },
		"duplicate":      func(request *http.Request) { request.Header.Add(PayloadHeader, request.Header.Get(PayloadHeader)) },
		"bad signature":  func(request *http.Request) { request.Header.Set(SignatureHeader, strings.Repeat("A", 43)) },
		"invalid base64": func(request *http.Request) { request.Header.Set(PayloadHeader, "not+base64") },
	} {
		t.Run(name, func(t *testing.T) {
			verifier := newTestVerifier(t, now, 10)
			request := signedRequest(t, now, [16]byte{2}, validSignals, "203.0.113.8:443")
			mutate(request)
			if _, present, err := verifier.Verify(request); !errors.Is(err, ErrInvalidEnvelope) || present {
				t.Fatalf("present=%v err=%v", present, err)
			}
		})
	}
}

func TestEnvelopeFreshnessAndNonceCapacity(t *testing.T) {
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	for name, issuedAt := range map[string]time.Time{
		"expired": now.Add(-31 * time.Second),
		"future":  now.Add(6 * time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			verifier := newTestVerifier(t, now, 10)
			request := signedRequest(t, issuedAt, [16]byte{3}, Signals{ExternalRiskScore: .5}, "203.0.113.8:443")
			if _, present, err := verifier.Verify(request); !errors.Is(err, ErrInvalidEnvelope) || present {
				t.Fatalf("present=%v err=%v", present, err)
			}
		})
	}
	verifier := newTestVerifier(t, now, 1)
	first := signedRequest(t, now, [16]byte{4}, Signals{PolicyAlert: true}, "203.0.113.8:443")
	second := signedRequest(t, now, [16]byte{5}, Signals{PolicyAlert: true}, "203.0.113.8:443")
	if _, _, err := verifier.Verify(first); err != nil {
		t.Fatal(err)
	}
	if _, present, err := verifier.Verify(second); !errors.Is(err, ErrInvalidEnvelope) || present {
		t.Fatalf("capacity = present %v err %v", present, err)
	}
	clock := now
	verifier = newTestVerifier(t, now, 1)
	verifier.now = func() time.Time { return clock }
	if _, _, err := verifier.Verify(first); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(DefaultMaxAge + DefaultFutureSkew + time.Second)
	replacement := signedRequest(t, clock, [16]byte{6}, Signals{PolicyAlert: true}, "203.0.113.8:443")
	if _, present, err := verifier.Verify(replacement); err != nil || !present {
		t.Fatalf("expired nonce was not reclaimed: present %v err %v", present, err)
	}
}

func TestClosedCanonicalPayloadRejectsPoisoning(t *testing.T) {
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	for name, raw := range map[string]string{
		"unknown field":   `{"version":"palisade.edge-signals.v1","issued_at":1788084000,"nonce":"AQAAAAAAAAAAAAAAAAAAAA","signals":{"policy_alert":true,"raw_vendor_label":"bad"}}`,
		"duplicate field": `{"version":"palisade.edge-signals.v1","issued_at":1788084000,"nonce":"AQAAAAAAAAAAAAAAAAAAAA","signals":{"policy_alert":true,"policy_alert":true}}`,
		"empty signals":   `{"version":"palisade.edge-signals.v1","issued_at":1788084000,"nonce":"AQAAAAAAAAAAAAAAAAAAAA","signals":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			verifier := newTestVerifier(t, now, 10)
			request := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
			request.RemoteAddr = "203.0.113.8:443"
			request.Header.Set(PayloadHeader, base64.RawURLEncoding.EncodeToString([]byte(raw)))
			request.Header.Set(SignatureHeader, base64.RawURLEncoding.EncodeToString(signatureFor(testKey, []byte(raw))))
			if _, present, err := verifier.Verify(request); !errors.Is(err, ErrInvalidEnvelope) || present {
				t.Fatalf("present=%v err=%v", present, err)
			}
		})
	}
}

func TestVerifierAcceptsLanguageNeutralJSONOrdering(t *testing.T) {
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	nonce := [16]byte{9}
	raw := []byte(fmt.Sprintf("{\n  \"signals\": {\"policy_alert\": true},\n  \"nonce\": %q,\n  \"issued_at\": %d,\n  \"version\": %q\n}",
		base64.RawURLEncoding.EncodeToString(nonce[:]), now.Unix(), Version))
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
	request.RemoteAddr = "203.0.113.8:443"
	request.Header.Set(PayloadHeader, base64.RawURLEncoding.EncodeToString(raw))
	request.Header.Set(SignatureHeader, base64.RawURLEncoding.EncodeToString(signatureFor(testKey, raw)))
	got, present, err := newTestVerifier(t, now, 10).Verify(request)
	if err != nil || !present || !got.PolicyAlert {
		t.Fatalf("language-neutral payload = %+v/%v/%v", got, present, err)
	}
}

func TestSignAndConfigurationBounds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	if _, _, err := Sign(testKey[:31], now, [16]byte{1}, Signals{PolicyAlert: true}); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("short signing key error = %v", err)
	}
	invalidSignals := []Signals{
		{},
		{ExternalRiskScore: 1.1},
		{EdgeFingerprintClass: "automation_consistent"},
		{NetworkReputation: "vendor-score"},
	}
	for _, signals := range invalidSignals {
		if _, _, err := Sign(testKey, now, [16]byte{1}, signals); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("invalid signals %+v error = %v", signals, err)
		}
	}
	invalidConfigs := []VerifierConfig{
		{Key: testKey},
		{Key: testKey[:31], TrustedPeerCIDRs: []string{"203.0.113.0/24"}},
		{Key: testKey, TrustedPeerCIDRs: []string{"0.0.0.0/0"}},
		{Key: testKey, TrustedPeerCIDRs: []string{"203.0.113.0/24", "203.0.113.0/25"}},
		{Key: testKey, TrustedPeerCIDRs: []string{"203.0.113.0/24"}, MaxNonces: -1},
	}
	for _, config := range invalidConfigs {
		if _, err := NewVerifier(config); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("config %+v error = %v", config, err)
		}
	}
	verifier := newTestVerifier(t, now, 10)
	if _, present, err := verifier.Verify(nil); !errors.Is(err, ErrInvalidEnvelope) || present {
		t.Fatalf("nil request = present %v err %v", present, err)
	}
}

func TestRepositorySchemaMatchesEnvelopeFields(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve source path")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "schemas", "edge-signal-envelope-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties  map[string]json.RawMessage `json:"properties"`
		Definitions map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(contents, &schema); err != nil {
		t.Fatal(err)
	}
	topLevel := sortedKeys(schema.Properties)
	signalFields := sortedKeys(schema.Definitions["signals"].Properties)
	wantTopLevel := []string{"issued_at", "nonce", "signals", "version"}
	wantSignals := []string{
		"challenge_verdict", "edge_fingerprint_class", "edge_fingerprint_method", "external_risk_score",
		"network_reputation", "network_type", "policy_alert",
	}
	if !reflect.DeepEqual(topLevel, wantTopLevel) || !reflect.DeepEqual(signalFields, wantSignals) {
		t.Fatalf("schema fields = %v/%v, want %v/%v", topLevel, signalFields, wantTopLevel, wantSignals)
	}
}

func sortedKeys(values map[string]json.RawMessage) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func newTestVerifier(t *testing.T, now time.Time, maxNonces int) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(VerifierConfig{
		Key: testKey, TrustedPeerCIDRs: []string{"203.0.113.0/24"}, MaxNonces: maxNonces,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	return verifier
}

func signedRequest(t *testing.T, issuedAt time.Time, nonce [16]byte, signals Signals, remoteAddr string) *http.Request {
	t.Helper()
	payload, signature, err := Sign(testKey, issuedAt, nonce, signals)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/private?secret=value", nil)
	request.RemoteAddr = remoteAddr
	request.Header.Set(PayloadHeader, payload)
	request.Header.Set(SignatureHeader, signature)
	return request
}
