package palisadeproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type tlsHopRecorder struct {
	mu        sync.Mutex
	protocols []int
	tls       []bool
	next      http.Handler
}

func (r *tlsHopRecorder) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.mu.Lock()
	r.protocols = append(r.protocols, request.ProtoMajor)
	r.tls = append(r.tls, request.TLS != nil)
	r.mu.Unlock()
	r.next.ServeHTTP(w, request)
}

func TestTLSHTTP2ReverseProxyDeploymentKeepsPrivateRequestAtUpstream(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	serviceHandler := &conformanceService{
		t: t, now: now,
		response: fixtureServiceResponse{Status: http.StatusNoContent, Headers: fixtureHeaders{
			DecisionID: "tls-deployment", Action: "observe", Handling: "pass", Mode: "shadow",
		}},
	}
	serviceRecorder := &tlsHopRecorder{next: serviceHandler}
	service := httptest.NewUnstartedServer(serviceRecorder)
	service.EnableHTTP2 = true
	service.StartTLS()
	defer service.Close()

	type upstreamRequest struct {
		Protocol int
		TLS      bool
		Path     string
		Query    string
		Body     string
		UA       string
		Cookie   string
	}
	var upstreamMu sync.Mutex
	var upstreamSeen upstreamRequest
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		upstreamMu.Lock()
		upstreamSeen = upstreamRequest{
			Protocol: request.ProtoMajor, TLS: request.TLS != nil, Path: request.URL.EscapedPath(), Query: request.URL.RawQuery,
			Body: string(body), UA: request.UserAgent(), Cookie: request.Header.Get("Cookie"),
		}
		upstreamMu.Unlock()
		w.Header().Set("X-Synthetic-Upstream", "reached")
		w.WriteHeader(http.StatusAccepted)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	reverse := httputil.NewSingleHostReverseProxy(upstreamURL)
	reverse.Transport = upstream.Client().Transport
	proxy, err := New(Config{
		BaseURL: service.URL, APIKey: "synthetic-adapter-key", HTTPClient: service.Client(), FailureMode: FailClosed,
		Classifier: StaticClassification("write", "account"), Upstream: reverse,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy.now = func() time.Time { return now }
	ingress := httptest.NewUnstartedServer(proxy)
	ingress.EnableHTTP2 = true
	ingress.StartTLS()
	defer ingress.Close()

	request, err := http.NewRequest(http.MethodPost, ingress.URL+"/private-path-secret?private-query-secret=value", strings.NewReader("private-body-secret"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", "private-user-agent-secret")
	request.Header.Set("CF-Connecting-IP", "192.0.2.15")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.AddCookie(&http.Cookie{Name: "application_session", Value: "private-cookie-secret"})
	response, err := ingress.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted || response.Header.Get("X-Palisade-Adapter") != "pass" || response.Header.Get("X-Synthetic-Upstream") != "reached" {
		t.Fatalf("ingress response = %d/%q/%q", response.StatusCode, response.Header.Get("X-Palisade-Adapter"), response.Header.Get("X-Synthetic-Upstream"))
	}

	serviceRecorder.mu.Lock()
	protocols := append([]int(nil), serviceRecorder.protocols...)
	tlsStates := append([]bool(nil), serviceRecorder.tls...)
	serviceRecorder.mu.Unlock()
	if len(protocols) != 3 || len(tlsStates) != 3 {
		t.Fatalf("service hops = %d/%d, want 3/3", len(protocols), len(tlsStates))
	}
	for index := range protocols {
		if protocols[index] != 2 || !tlsStates[index] {
			t.Fatalf("service hop %d protocol/tls = %d/%t, want 2/true", index, protocols[index], tlsStates[index])
		}
	}

	serviceHandler.mu.Lock()
	serviceBodies := append([][]byte(nil), serviceHandler.bodies...)
	serviceHeaders := append([]http.Header(nil), serviceHandler.headers...)
	serviceHandler.mu.Unlock()
	if len(serviceBodies) != 3 || serviceHandler.originChecks.Load() != 1 {
		t.Fatalf("service bodies/origin checks = %d/%d, want 3/1", len(serviceBodies), serviceHandler.originChecks.Load())
	}
	var payload struct {
		Observations Signals `json:"observations"`
	}
	if err := json.Unmarshal(serviceBodies[2], &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Observations.TransportProtocol != "http2" || payload.Observations.TransportSecurity != "direct_tls" ||
		payload.Observations.ClientAddressSource != "direct" || payload.Observations.VerifiedBot ||
		payload.Observations.CrawlerClass != "unknown" || payload.Observations.CrawlerVerification != "unknown" {
		t.Fatalf("normalized transport = %+v", payload.Observations)
	}
	for index, body := range serviceBodies {
		for _, forbidden := range []string{
			"private-path-secret", "private-query-secret", "private-body-secret", "private-user-agent-secret", "private-cookie-secret",
			"application_session", "CF-Connecting-IP", "X-Forwarded-Proto", "192.0.2.15",
		} {
			if bytes.Contains(body, []byte(forbidden)) {
				t.Errorf("service body %d exposed %q", index, forbidden)
			}
			for name, values := range serviceHeaders[index] {
				if strings.Contains(strings.Join(values, "\n"), forbidden) {
					t.Errorf("service header %d %s exposed %q", index, name, forbidden)
				}
			}
		}
	}

	upstreamMu.Lock()
	seen := upstreamSeen
	upstreamMu.Unlock()
	if seen.Protocol != 2 || !seen.TLS || seen.Path != "/private-path-secret" || seen.Query != "private-query-secret=value" ||
		seen.Body != "private-body-secret" || seen.UA != "private-user-agent-secret" || !strings.Contains(seen.Cookie, "private-cookie-secret") {
		t.Fatalf("upstream request = %+v", seen)
	}
}
