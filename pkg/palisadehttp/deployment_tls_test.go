package palisadehttp

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrustedTLSTerminatorDeploymentRejectsDirectHeaderSpoof(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	serviceHandler := &fakePalisade{t: t, now: now}
	service := httptest.NewUnstartedServer(serviceHandler)
	service.EnableHTTP2 = true
	service.StartTLS()
	defer service.Close()

	registry, err := NewCrawlerRegistry([]CrawlerIdentity{{
		Name: "synthetic-search", Class: CrawlerClassSearchIndexer,
		UserAgentTokens: []string{"SyntheticSearchBot"}, CIDRs: []string{"192.0.2.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := New(Config{
		BaseURL: service.URL, APIKey: "adapter-key", HTTPClient: service.Client(), FailureMode: FailClosed,
		Classifier:            StaticClassification("read", "public_content"),
		TrustedProxyCIDRs:     []string{"127.0.0.1/32"},
		TrustedClientIPHeader: "CF-Connecting-IP",
		TrustedProtoHeader:    "X-Forwarded-Proto",
		CrawlerRegistry:       registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	guard.now = func() time.Time { return now }
	var protectedHits atomic.Int32
	origin := httptest.NewUnstartedServer(guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		protectedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	edgeProxy := httputil.NewSingleHostReverseProxy(originURL)
	edgeProxy.Transport = origin.Client().Transport
	director := edgeProxy.Director
	edgeProxy.Director = func(request *http.Request) {
		director(request)
		request.Header.Set("CF-Connecting-IP", "192.0.2.15")
		request.Header.Set("X-Forwarded-Proto", "https")
	}
	edge := httptest.NewUnstartedServer(edgeProxy)
	edge.EnableHTTP2 = true
	edge.StartTLS()
	defer edge.Close()

	edgeRequest, err := http.NewRequest(http.MethodGet, edge.URL+"/edge-path-secret?edge-query-secret=value", nil)
	if err != nil {
		t.Fatal(err)
	}
	edgeRequest.Header.Set("User-Agent", "SyntheticSearchBot/1.0 edge-user-agent-secret")
	edgeRequest.Header.Set("CF-Connecting-IP", "198.51.100.200")
	edgeRequest.Header.Set("X-Forwarded-Proto", "http")
	edgeResponse, err := edge.Client().Do(edgeRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, edgeResponse.Body)
	_ = edgeResponse.Body.Close()
	if edgeResponse.StatusCode != http.StatusOK || edgeResponse.Header.Get("X-Palisade-Adapter") != "pass" {
		t.Fatalf("trusted edge response = %d/%q", edgeResponse.StatusCode, edgeResponse.Header.Get("X-Palisade-Adapter"))
	}

	directTransport := origin.Client().Transport.(*http.Transport).Clone()
	directTransport.ForceAttemptHTTP2 = true
	directTransport.DialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).DialContext
	directClient := &http.Client{Transport: directTransport, Timeout: 5 * time.Second}
	directRequest, err := http.NewRequest(http.MethodGet, origin.URL+"/direct-path-secret?direct-query-secret=value", nil)
	if err != nil {
		t.Fatal(err)
	}
	directRequest.Header.Set("User-Agent", "SyntheticSearchBot/1.0 direct-user-agent-secret")
	directRequest.Header.Set("CF-Connecting-IP", "192.0.2.15")
	directRequest.Header.Set("X-Forwarded-Proto", "https")
	directResponse, err := directClient.Do(directRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, directResponse.Body)
	_ = directResponse.Body.Close()
	if directResponse.StatusCode != http.StatusOK || directResponse.Header.Get("X-Palisade-Adapter") != "pass" {
		t.Fatalf("direct response = %d/%q", directResponse.StatusCode, directResponse.Header.Get("X-Palisade-Adapter"))
	}
	if protectedHits.Load() != 2 || serviceHandler.originChecks.Load() != 2 {
		t.Fatalf("protected/origin checks = %d/%d, want 2/2", protectedHits.Load(), serviceHandler.originChecks.Load())
	}

	serviceHandler.mu.Lock()
	bodies := append([][]byte(nil), serviceHandler.originBodies...)
	serviceHandler.mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("origin payloads = %d, want 2", len(bodies))
	}
	type originPayload struct {
		Sequence     uint64  `json:"sequence"`
		Observations Signals `json:"observations"`
	}
	var trusted, direct originPayload
	if err := json.Unmarshal(bodies[0], &trusted); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bodies[1], &direct); err != nil {
		t.Fatal(err)
	}
	if trusted.Observations.TransportProtocol != TransportProtocolHTTP2 ||
		trusted.Observations.TransportSecurity != TransportSecurityTrustedProxyTLS ||
		trusted.Observations.ClientAddressSource != ClientAddressSourceTrustedProxy ||
		!trusted.Observations.VerifiedBot || trusted.Observations.CrawlerClass != CrawlerClassSearchIndexer ||
		trusted.Observations.CrawlerVerification != CrawlerVerificationIPUARegistry {
		t.Fatalf("trusted observations = %+v", trusted.Observations)
	}
	if direct.Observations.TransportProtocol != TransportProtocolHTTP2 ||
		direct.Observations.TransportSecurity != TransportSecurityDirectTLS ||
		direct.Observations.ClientAddressSource != ClientAddressSourceDirect || direct.Observations.VerifiedBot ||
		direct.Observations.CrawlerClass != CrawlerClassUnknown || direct.Observations.CrawlerVerification != CrawlerVerificationUnknown {
		t.Fatalf("direct spoof observations = %+v", direct.Observations)
	}
	for index, body := range bodies {
		for _, forbidden := range [][]byte{
			[]byte("edge-path-secret"), []byte("edge-query-secret"), []byte("direct-path-secret"), []byte("direct-query-secret"),
			[]byte("edge-user-agent-secret"), []byte("direct-user-agent-secret"), []byte("CF-Connecting-IP"), []byte("X-Forwarded-Proto"),
			[]byte("192.0.2.15"), []byte("198.51.100.200"),
		} {
			if bytes.Contains(body, forbidden) {
				t.Errorf("origin payload %d exposed %q", index, forbidden)
			}
		}
	}
}
