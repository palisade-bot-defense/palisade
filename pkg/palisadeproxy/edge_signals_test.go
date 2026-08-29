package palisadeproxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/pkg/palisadeedge"
)

var edgeTestKey = []byte("0123456789abcdef0123456789abcdef")

func TestProxyConsumesVerifiedEdgeSignalsAndRejectsTrustedTampering(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for name, test := range map[string]struct {
		remoteAddr    string
		signatureMode string
		wantStatus    int
		wantOrigin    int32
	}{
		"verified":         {"203.0.113.9:443", "valid", http.StatusOK, 1},
		"trusted tamper":   {"203.0.113.9:443", "invalid", http.StatusInternalServerError, 0},
		"untrusted spoof":  {"198.51.100.9:443", "invalid", http.StatusOK, 1},
		"trusted conflict": {"203.0.113.9:443", "conflict", http.StatusInternalServerError, 0},
	} {
		t.Run(name, func(t *testing.T) {
			serviceHandler := &conformanceService{
				t: t, now: now,
				response: fixtureServiceResponse{Status: http.StatusNoContent, Headers: fixtureHeaders{
					DecisionID: "edge-fixture", Action: "observe", Handling: "pass", Mode: "shadow",
				}},
			}
			service := httptest.NewServer(serviceHandler)
			defer service.Close()
			verifier, err := palisadeedge.NewVerifier(palisadeedge.VerifierConfig{
				Key: edgeTestKey, TrustedPeerCIDRs: []string{"203.0.113.0/24"},
			})
			if err != nil {
				t.Fatal(err)
			}
			var upstream atomic.Int32
			proxy, err := New(Config{
				BaseURL: service.URL, APIKey: "synthetic", FailureMode: FailOpen, EdgeSignals: verifier,
				Classifier: StaticClassification("read", "public_content"),
				Signals: func(*http.Request) (Signals, error) {
					if test.signatureMode == "conflict" {
						return Signals{NetworkReputation: "low_risk"}, nil
					}
					return Signals{}, nil
				},
				Upstream: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					if request.Header.Get(palisadeedge.PayloadHeader) != "" || request.Header.Get(palisadeedge.SignatureHeader) != "" {
						t.Error("edge headers reached the upstream handler")
					}
					upstream.Add(1)
					w.WriteHeader(http.StatusOK)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			proxy.now = func() time.Time { return now }
			payload, signature, err := palisadeedge.Sign(edgeTestKey, now, [16]byte{3}, palisadeedge.Signals{
				PolicyAlert: true, ExternalRiskScore: .7, EdgeFingerprintClass: "anomalous", EdgeFingerprintMethod: "http2",
				NetworkReputation: "high_risk", NetworkType: "anonymizer",
			})
			if err != nil {
				t.Fatal(err)
			}
			if test.signatureMode == "invalid" {
				signature = strings.Repeat("A", 43)
			}
			request := httptest.NewRequest(http.MethodGet, "https://origin.example/private?secret=value", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set(palisadeedge.PayloadHeader, payload)
			request.Header.Set(palisadeedge.SignatureHeader, signature)
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			if response.Code != test.wantStatus || serviceHandler.originChecks.Load() != test.wantOrigin {
				t.Fatalf("response/origin = %d/%d, want %d/%d", response.Code, serviceHandler.originChecks.Load(), test.wantStatus, test.wantOrigin)
			}
			if name == "verified" {
				if upstream.Load() != 1 || len(serviceHandler.bodies) != 3 {
					t.Fatalf("upstream/bodies = %d/%d", upstream.Load(), len(serviceHandler.bodies))
				}
				originBody := serviceHandler.bodies[2]
				for _, expected := range []string{`"policy_alert":true`, `"external_risk_score":0.7`, `"edge_fingerprint_class":"anomalous"`, `"network_reputation":"high_risk"`} {
					if !bytes.Contains(originBody, []byte(expected)) {
						t.Errorf("origin body omitted %s: %s", expected, originBody)
					}
				}
				for _, forbidden := range []string{"private", "secret=value", payload, signature} {
					if bytes.Contains(originBody, []byte(forbidden)) {
						t.Errorf("origin body exposed %q", forbidden)
					}
				}
			}
		})
	}
}
