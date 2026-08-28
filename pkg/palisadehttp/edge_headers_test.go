package palisadehttp

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestEdgeHeaderNormalizerTrustsOnlyConfiguredTCPPeer(t *testing.T) {
	config := Config{TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedEdgeHeaders: true}
	transport, err := newTransportNormalizer(config)
	if err != nil {
		t.Fatal(err)
	}
	normalizer, err := newEdgeHeaderNormalizer(config, transport)
	if err != nil {
		t.Fatal(err)
	}

	trusted := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
	trusted.RemoteAddr = "203.0.113.8:443"
	setTrustedEdgeHeaders(trusted)
	got, err := normalizer.normalize(trusted)
	if err != nil {
		t.Fatal(err)
	}
	if got.fingerprintClass != "automation_consistent" || got.fingerprintMethod != "tls_http2" ||
		got.networkReputation != "elevated_risk" || got.networkType != "hosting" {
		t.Fatalf("trusted edge normalization = %+v", got)
	}

	direct := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
	direct.RemoteAddr = "198.51.100.8:443"
	setTrustedEdgeHeaders(direct)
	direct.Header.Set(TrustedEdgeFingerprintClassHeader, "ja4:client-spoof")
	got, err = normalizer.normalize(direct)
	if err != nil {
		t.Fatalf("untrusted headers must be ignored, not parsed: %v", err)
	}
	if got.fingerprintClass != "unknown" || got.fingerprintMethod != "unknown" || got.networkReputation != "unknown" || got.networkType != "unknown" {
		t.Fatalf("direct client influenced trusted edge result: %+v", got)
	}
}

func TestEdgeHeaderNormalizerRejectsMalformedTrustedValues(t *testing.T) {
	config := Config{TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedEdgeHeaders: true}
	transport, err := newTransportNormalizer(config)
	if err != nil {
		t.Fatal(err)
	}
	normalizer, err := newEdgeHeaderNormalizer(config, transport)
	if err != nil {
		t.Fatal(err)
	}

	tests := []func(*http.Request){
		func(request *http.Request) { request.Header.Set(TrustedEdgeFingerprintClassHeader, "ja4:raw") },
		func(request *http.Request) { request.Header.Set(TrustedEdgeFingerprintMethodHeader, "tls") },
		func(request *http.Request) { request.Header.Add(TrustedNetworkTypeHeader, "hosting") },
		func(request *http.Request) { request.Header.Set(TrustedNetworkReputationHeader, "provider-score-92") },
	}
	for index, mutate := range tests {
		request := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
		request.RemoteAddr = "203.0.113.9:443"
		if index == 2 {
			request.Header.Add(TrustedNetworkTypeHeader, "hosting")
		}
		mutate(request)
		if _, err := normalizer.normalize(request); !errors.Is(err, ErrInvalidSignals) {
			t.Fatalf("malformed case %d error = %v", index, err)
		}
	}
}

func TestTrustedEdgeHeadersRequireExplicitProxyBoundary(t *testing.T) {
	if _, err := New(Config{
		BaseURL: "https://service.example", APIKey: "adapter-key", FailureMode: FailClosed,
		Classifier: StaticClassification("read", "public_content"), TrustedEdgeHeaders: true,
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("trusted edge headers without proxy boundary error = %v", err)
	}
}

func TestMiddlewareOverwritesProviderEdgeClaimsFromTrustedHeaders(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now}
	service := httptest.NewServer(fake)
	defer service.Close()
	guard, err := New(Config{
		BaseURL: service.URL, APIKey: "adapter-key", FailureMode: FailClosed,
		Classifier:        StaticClassification("read", "public_content"),
		TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedEdgeHeaders: true,
		Signals: func(*http.Request) (Signals, error) {
			return Signals{
				EdgeFingerprintClass: "ja4:provider-raw", EdgeFingerprintMethod: "raw-method",
				NetworkReputation: "vendor-score-99", NetworkType: "AS64500",
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	guard.now = func() time.Time { return now }
	var nextCalls atomic.Int32
	handler := guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	request := httptest.NewRequest(http.MethodGet, "https://origin.example/private?raw=must-not-leave", nil)
	request.RemoteAddr = "203.0.113.10:443"
	setTrustedEdgeHeaders(request)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || nextCalls.Load() != 1 {
		t.Fatalf("response=%d next=%d body=%s", response.Code, nextCalls.Load(), response.Body.String())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.originBodies) != 1 {
		t.Fatalf("origin bodies = %d", len(fake.originBodies))
	}
	body := fake.originBodies[0]
	for _, forbidden := range [][]byte{[]byte("ja4:provider-raw"), []byte("raw-method"), []byte("vendor-score-99"), []byte("AS64500"), []byte("must-not-leave")} {
		if bytes.Contains(body, forbidden) {
			t.Fatalf("raw edge value left adapter: %s", body)
		}
	}
	for _, expected := range [][]byte{
		[]byte(`"edge_fingerprint_class":"automation_consistent"`),
		[]byte(`"edge_fingerprint_method":"tls_http2"`),
		[]byte(`"network_reputation":"elevated_risk"`),
		[]byte(`"network_type":"hosting"`),
	} {
		if !bytes.Contains(body, expected) {
			t.Fatalf("closed trusted edge field %s missing: %s", expected, body)
		}
	}
}

func TestMiddlewareRejectsMalformedTrustedHeadersBeforeOriginCheck(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	fake := &fakePalisade{t: t, now: now}
	service := httptest.NewServer(fake)
	defer service.Close()
	guard, err := New(Config{
		BaseURL: service.URL, APIKey: "adapter-key", FailureMode: FailOpen,
		Classifier:        StaticClassification("read", "public_content"),
		TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedEdgeHeaders: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	guard.now = func() time.Time { return now }
	var nextCalls atomic.Int32
	request := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
	request.RemoteAddr = "203.0.113.11:443"
	request.Header.Set(TrustedEdgeFingerprintClassHeader, "automation_consistent")
	response := httptest.NewRecorder()
	guard.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalls.Add(1)
	})).ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || nextCalls.Load() != 0 || fake.originChecks.Load() != 0 || fake.sessionIssues.Load() != 0 {
		t.Fatalf("malformed trusted edge response=%d next=%d sessions=%d origins=%d", response.Code, nextCalls.Load(), fake.sessionIssues.Load(), fake.originChecks.Load())
	}
}

func setTrustedEdgeHeaders(request *http.Request) {
	request.Header.Set(TrustedEdgeFingerprintClassHeader, "automation_consistent")
	request.Header.Set(TrustedEdgeFingerprintMethodHeader, "tls_http2")
	request.Header.Set(TrustedNetworkReputationHeader, "elevated_risk")
	request.Header.Set(TrustedNetworkTypeHeader, "hosting")
}
