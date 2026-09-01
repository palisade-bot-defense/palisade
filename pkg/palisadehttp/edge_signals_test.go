package palisadehttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadeedge"
)

var edgeTestKey = []byte("0123456789abcdef0123456789abcdef")

func TestMiddlewareConsumesOnlyVerifiedClosedEdgeSignals(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	verifier := newEdgeVerifier(t)
	fake := &fakePalisade{t: t, now: now}
	service := httptest.NewServer(fake)
	defer service.Close()
	middleware, err := New(Config{
		BaseURL: service.URL, APIKey: "adapter-key", FailureMode: FailClosed,
		Classifier:  StaticClassification("read", "public_content"),
		EdgeSignals: verifier,
		Signals: func(*http.Request) (Signals, error) {
			return Signals{ExternalRiskScore: .2, NetworkReputation: "unknown", NetworkType: "unknown"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	middleware.now = func() time.Time { return now }
	payload, signature := signedEdgeHeaders(t, now, [16]byte{1}, palisadeedge.Signals{
		ChallengeVerdict: "failed", ExternalRiskScore: .8, PolicyAlert: true,
		EdgeFingerprintClass: "automation_consistent", EdgeFingerprintMethod: "tls_http2",
		NetworkReputation: "high_risk", NetworkType: "hosting",
	})
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/private?secret=value", nil)
	request.RemoteAddr = "203.0.113.7:443"
	request.Header.Set(palisadeedge.PayloadHeader, payload)
	request.Header.Set(palisadeedge.SignatureHeader, signature)
	response := httptest.NewRecorder()
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get(palisadeedge.PayloadHeader) != "" || request.Header.Get(palisadeedge.SignatureHeader) != "" {
			t.Error("signed edge headers reached the application handler")
		}
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(response, request)
	if response.Code != http.StatusOK || fake.originChecks.Load() != 1 || len(fake.originBodies) != 1 {
		t.Fatalf("response/origin = %d/%d", response.Code, fake.originChecks.Load())
	}
	body := fake.originBodies[0]
	for _, expected := range []string{
		`"challenge_verdict":"failed"`, `"external_risk_score":0.8`, `"policy_alert":true`,
		`"edge_fingerprint_class":"automation_consistent"`, `"edge_fingerprint_method":"tls_http2"`,
		`"network_reputation":"high_risk"`, `"network_type":"hosting"`,
	} {
		if !bytes.Contains(body, []byte(expected)) {
			t.Errorf("origin body omitted %s: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"private", "secret=value", payload, signature, palisadeedge.PayloadHeader} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Errorf("origin body exposed %q: %s", forbidden, body)
		}
	}
}

func TestMiddlewareRejectsTrustedEdgeConflictAndIgnoresUntrustedSpoof(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for name, test := range map[string]struct {
		remoteAddr     string
		signatureValue string
		wantStatus     int
		wantOrigin     int32
	}{
		"trusted conflict": {"203.0.113.7:443", "valid", http.StatusInternalServerError, 0},
		"trusted tamper":   {"203.0.113.7:443", strings.Repeat("A", 43), http.StatusInternalServerError, 0},
		"untrusted spoof":  {"198.51.100.7:443", strings.Repeat("A", 43), http.StatusOK, 1},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakePalisade{t: t, now: now}
			service := httptest.NewServer(fake)
			defer service.Close()
			middleware, err := New(Config{
				BaseURL: service.URL, APIKey: "adapter-key", FailureMode: FailOpen,
				Classifier: StaticClassification("read", "public_content"), EdgeSignals: newEdgeVerifier(t),
				Signals: func(*http.Request) (Signals, error) { return Signals{NetworkType: "residential"}, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			middleware.now = func() time.Time { return now }
			payload, signature := signedEdgeHeaders(t, now, [16]byte{2}, palisadeedge.Signals{NetworkType: "hosting"})
			if test.signatureValue != "valid" {
				signature = test.signatureValue
			}
			request := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set(palisadeedge.PayloadHeader, payload)
			request.Header.Set(palisadeedge.SignatureHeader, signature)
			response := httptest.NewRecorder()
			middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Header.Get(palisadeedge.PayloadHeader) != "" || request.Header.Get(palisadeedge.SignatureHeader) != "" {
					t.Error("spoofed edge headers reached the application handler")
				}
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(response, request)
			if response.Code != test.wantStatus || fake.originChecks.Load() != test.wantOrigin {
				t.Fatalf("response/origin = %d/%d, want %d/%d", response.Code, fake.originChecks.Load(), test.wantStatus, test.wantOrigin)
			}
		})
	}
}

func newEdgeVerifier(t *testing.T) *palisadeedge.Verifier {
	t.Helper()
	verifier, err := palisadeedge.NewVerifier(palisadeedge.VerifierConfig{
		Key: edgeTestKey, TrustedPeerCIDRs: []string{"203.0.113.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func signedEdgeHeaders(t *testing.T, now time.Time, nonce [16]byte, signals palisadeedge.Signals) (string, string) {
	t.Helper()
	payload, signature, err := palisadeedge.Sign(edgeTestKey, now, nonce, signals)
	if err != nil {
		t.Fatal(err)
	}
	return payload, signature
}
