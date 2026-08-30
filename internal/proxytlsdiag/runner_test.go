package proxytlsdiag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/pkg/palisadehttp"
	"github.com/palisade-bot-defense/palisade/pkg/palisadeproxy"
)

const (
	privatePath           = "/private-path-marker"
	privateQuery          = "private-query-marker=value"
	privateBody           = "private-body-marker"
	privateAgent          = "private-user-agent-marker"
	privateCookie         = "private-cookie-marker"
	apiKey                = "synthetic-local-diagnostic-api-key"
	serviceHTTP2TLS       = "http2_tls"
	serviceHTTP1Plaintext = "http1_plaintext"
)

var privateMarkers = []string{
	"private-path-marker", "private-query-marker", "private-body-marker", "private-user-agent-marker",
	"private-cookie-marker", "application_session", "192.0.2.15", "cf-connecting-ip",
	"192.0.2.30", "198.51.100.77", "x-forwarded-for", "x-forwarded-proto", "x-real-ip",
}

type boundaryState struct {
	protocol atomic.Int64
	privacy  atomic.Int64
	service  atomic.Int64
	upstream atomic.Int64
}

func (state *boundaryState) counts() BoundaryCounts {
	return BoundaryCounts{
		Protocol: int(state.protocol.Load()), Privacy: int(state.privacy.Load()),
		Service: int(state.service.Load()), Upstream: int(state.upstream.Load()),
	}
}

type diagnosticScenario struct {
	name       string
	url        string
	client     *http.Client
	service    *serviceFixture
	upstream   *upstreamFixture
	boundaries *boundaryState
	close      func()
}

type workerResult struct {
	completed int
	failed    int
	latencies []int64
	failures  FailureCounts
}

func Run(ctx context.Context, config Config) (Report, error) {
	config, err := NormalizeConfig(config)
	if err != nil {
		return Report{}, err
	}
	if ctx == nil {
		return Report{}, ErrInvalidConfig
	}
	report := Report{
		SchemaVersion: ReportSchemaVersion, SyntheticOnly: true, RawDeploymentRecordsUsed: false,
		NetworkScope: "loopback_only", Configured: config, Limitations: slices.Clone(limitations), Result: "passed",
	}
	builders := []func() (*diagnosticScenario, error){newOriginMiddlewareScenario, newReverseProxyScenario}
	for _, build := range builders {
		scenario, err := build()
		if err != nil {
			return Report{}, fmt.Errorf("%w: initialize loopback profile", ErrBoundary)
		}
		profile := runProfile(ctx, config, scenario)
		scenario.close()
		report.Profiles = append(report.Profiles, profile)
		if profile.Result != "passed" {
			report.Result = "failed"
		}
	}
	if err := ValidateReport(report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func runProfile(ctx context.Context, config Config, scenario *diagnosticScenario) ProfileReport {
	started := time.Now()
	deadline := started.Add(time.Duration(config.DurationSeconds) * time.Second)
	var tickets atomic.Int64
	results := make(chan workerResult, config.Concurrency)
	var workers sync.WaitGroup
	for range config.Concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- runWorker(ctx, scenario, deadline, config.MaxOperations, &tickets)
		}()
	}
	workers.Wait()
	close(results)
	elapsed := time.Since(started)
	var combined workerResult
	for result := range results {
		combined.completed += result.completed
		combined.failed += result.failed
		combined.latencies = append(combined.latencies, result.latencies...)
		combined.failures.Client += result.failures.Client
		combined.failures.ResponseTooLarge += result.failures.ResponseTooLarge
		combined.failures.AdapterResponse += result.failures.AdapterResponse
	}
	attempted := combined.completed + combined.failed
	stopReason := "duration"
	if attempted >= config.MaxOperations {
		stopReason = "max_operations"
	}
	boundaries := scenario.boundaries.counts()
	result := "passed"
	if combined.failed > 0 || boundaries.Total() > 0 {
		result = "failed"
	}
	seconds := math.Max(elapsed.Seconds(), 0.000001)
	return ProfileReport{
		Name: scenario.name, WallDurationMS: rounded(elapsed.Seconds() * 1000), AttemptedOperations: attempted,
		CompletedOperations: combined.completed, FailedOperations: combined.failed,
		ServiceRequests: int(scenario.service.requests.Load()), ProtectedUpstreamRequests: int(scenario.upstream.requests.Load()),
		ThroughputOperationsPerSecond: rounded(float64(combined.completed) / seconds), StopReason: stopReason,
		LatencyMS: latencyReport(combined.latencies), Failures: combined.failures, BoundaryViolations: boundaries, Result: result,
	}
}

func runWorker(ctx context.Context, scenario *diagnosticScenario, deadline time.Time, maximum int, tickets *atomic.Int64) workerResult {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: scenario.client.Transport, Jar: jar, Timeout: RequestTimeoutSec * time.Second}
	var result workerResult
	for time.Now().Before(deadline) && claimTicket(tickets, maximum) {
		started := time.Now()
		failure := executeOperation(ctx, client, scenario.url)
		if failure == "" {
			result.completed++
			result.latencies = append(result.latencies, time.Since(started).Nanoseconds())
			continue
		}
		result.failed++
		switch failure {
		case "client":
			result.failures.Client++
		case "response_too_large":
			result.failures.ResponseTooLarge++
		default:
			result.failures.AdapterResponse++
		}
	}
	return result
}

func claimTicket(counter *atomic.Int64, maximum int) bool {
	for {
		current := counter.Load()
		if current >= int64(maximum) {
			return false
		}
		if counter.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func executeOperation(parent context.Context, client *http.Client, baseURL string) string {
	ctx, cancel := context.WithTimeout(parent, RequestTimeoutSec*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+privatePath+"?"+privateQuery, strings.NewReader(privateBody))
	if err != nil {
		return "client"
	}
	request.Header.Set("Content-Type", "text/plain")
	request.Header.Set("User-Agent", privateAgent)
	request.AddCookie(&http.Cookie{Name: "application_session", Value: privateCookie})
	response, err := client.Do(request)
	if err != nil {
		return "client"
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, MaximumResponseSize+1))
	if err != nil {
		return "client"
	}
	if len(contents) > MaximumResponseSize {
		return "response_too_large"
	}
	if response.StatusCode != http.StatusNoContent || len(bytes.TrimSpace(contents)) != 0 || response.Header.Get("X-Palisade-Adapter") != "pass" {
		return "adapter_response"
	}
	return ""
}

func newOriginMiddlewareScenario() (*diagnosticScenario, error) {
	boundaries := &boundaryState{}
	serviceFixture := &serviceFixture{expectedRequestTransport: serviceHTTP2TLS, expectedProtocol: "http2", expectedSecurity: "trusted_proxy_tls", expectedSource: "trusted_proxy", boundaries: boundaries}
	service := startHTTP2TLSServer(serviceFixture)
	guard, err := palisadehttp.New(palisadehttp.Config{
		BaseURL: service.URL, APIKey: apiKey, HTTPClient: service.Client(), FailureMode: palisadehttp.FailClosed,
		Classifier: palisadehttp.StaticClassification("write", "account"), TrustedProxyCIDRs: []string{"127.0.0.1/32"},
		TrustedClientIPHeader: "CF-Connecting-IP", TrustedProtoHeader: "X-Forwarded-Proto",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		service.Close()
		return nil, err
	}
	upstreamFixture := &upstreamFixture{boundaries: boundaries}
	origin := startHTTP2TLSServer(guard.Handler(upstreamFixture))
	originURL, _ := url.Parse(origin.URL)
	edgeProxy := httputil.NewSingleHostReverseProxy(originURL)
	edgeProxy.Transport = origin.Client().Transport
	director := edgeProxy.Director
	edgeProxy.Director = func(request *http.Request) {
		director(request)
		request.Header.Set("CF-Connecting-IP", "192.0.2.15")
		request.Header.Set("X-Forwarded-Proto", "https")
	}
	ingress := startHTTP2TLSServer(&ingressBoundary{boundaries: boundaries, next: edgeProxy})
	return &diagnosticScenario{
		name: ProfileOriginMiddleware, url: ingress.URL, client: ingress.Client(), service: serviceFixture,
		upstream: upstreamFixture, boundaries: boundaries, close: func() {
			closeClientIdle(ingress.Client())
			closeClientIdle(origin.Client())
			closeClientIdle(service.Client())
			ingress.Close()
			origin.Close()
			service.Close()
		},
	}, nil
}

func newReverseProxyScenario() (*diagnosticScenario, error) {
	boundaries := &boundaryState{}
	serviceFixture := &serviceFixture{expectedRequestTransport: serviceHTTP2TLS, expectedProtocol: "http2", expectedSecurity: "direct_tls", expectedSource: "direct", boundaries: boundaries}
	service := startHTTP2TLSServer(serviceFixture)
	upstreamFixture := &upstreamFixture{boundaries: boundaries}
	upstream := startHTTP2TLSServer(upstreamFixture)
	upstreamURL, _ := url.Parse(upstream.URL)
	reverse := httputil.NewSingleHostReverseProxy(upstreamURL)
	reverse.Transport = upstream.Client().Transport
	proxy, err := palisadeproxy.New(palisadeproxy.Config{
		BaseURL: service.URL, APIKey: apiKey, HTTPClient: service.Client(), FailureMode: palisadeproxy.FailClosed,
		Classifier: palisadeproxy.StaticClassification("write", "account"), Upstream: reverse,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		upstream.Close()
		service.Close()
		return nil, err
	}
	ingress := startHTTP2TLSServer(&ingressBoundary{boundaries: boundaries, next: proxy})
	return &diagnosticScenario{
		name: ProfileReverseProxy, url: ingress.URL, client: ingress.Client(), service: serviceFixture,
		upstream: upstreamFixture, boundaries: boundaries, close: func() {
			closeClientIdle(ingress.Client())
			closeClientIdle(upstream.Client())
			closeClientIdle(service.Client())
			ingress.Close()
			upstream.Close()
			service.Close()
		},
	}, nil
}

func startHTTP2TLSServer(handler http.Handler) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	return server
}

func closeClientIdle(client *http.Client) {
	if transport, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}

func latencyReport(values []int64) Latency {
	if len(values) == 0 {
		return Latency{Method: "nearest_rank_successes"}
	}
	sort.Slice(values, func(left, right int) bool { return values[left] < values[right] })
	value := func(percentile int) *float64 {
		rank := int(math.Ceil(float64(percentile*len(values))/100.0)) - 1
		result := rounded(float64(values[max(rank, 0)]) / 1_000_000)
		return &result
	}
	maximum := rounded(float64(values[len(values)-1]) / 1_000_000)
	return Latency{Samples: len(values), P50: value(50), P95: value(95), P99: value(99), Maximum: &maximum, Method: "nearest_rank_successes"}
}

func rounded(value float64) float64 { return math.Round(value*1000) / 1000 }

type ingressBoundary struct {
	boundaries *boundaryState
	next       http.Handler
}

func (handler *ingressBoundary) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.TLS == nil || request.ProtoMajor != 2 {
		handler.boundaries.protocol.Add(1)
	}
	handler.next.ServeHTTP(writer, request)
}

type upstreamFixture struct {
	requests   atomic.Int64
	boundaries *boundaryState
}

func (fixture *upstreamFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	fixture.requests.Add(1)
	body, err := io.ReadAll(io.LimitReader(request.Body, MaximumResponseSize+1))
	cookie, cookieErr := request.Cookie("application_session")
	valid := err == nil && len(body) <= MaximumResponseSize && request.TLS != nil && request.ProtoMajor == 2 &&
		request.Method == http.MethodPost && request.URL.EscapedPath() == privatePath && request.URL.RawQuery == privateQuery &&
		string(body) == privateBody && request.UserAgent() == privateAgent && cookieErr == nil && cookie.Value == privateCookie
	if !valid {
		fixture.boundaries.upstream.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type serviceFixture struct {
	expectedRequestTransport string
	expectedProtocol         string
	expectedSecurity         string
	expectedSource           string
	requests                 atomic.Int64
	sessions                 atomic.Int64
	decisions                atomic.Int64
	boundaries               *boundaryState
}

func (fixture *serviceFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	fixture.requests.Add(1)
	invalid := false
	validTransport := fixture.expectedRequestTransport == serviceHTTP2TLS && request.TLS != nil && request.ProtoMajor == 2
	validTransport = validTransport || fixture.expectedRequestTransport == serviceHTTP1Plaintext && request.TLS == nil && request.ProtoMajor == 1
	if !validTransport {
		fixture.boundaries.protocol.Add(1)
		invalid = true
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, MaximumResponseSize+1))
	if err != nil || len(body) > MaximumResponseSize {
		fixture.boundaries.service.Add(1)
		invalid = true
	}
	for _, marker := range privateMarkers {
		if bytes.Contains(body, []byte(marker)) || strings.Contains(strings.ToLower(request.URL.RawQuery), marker) || headerContains(request.Header, marker) {
			fixture.boundaries.privacy.Add(1)
			invalid = true
		}
	}
	if request.URL.RawQuery != "" {
		fixture.boundaries.service.Add(1)
		invalid = true
	}
	if invalid {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	switch request.URL.Path {
	case "/v1/session":
		fixture.serveSession(writer, request)
	case "/v1/token":
		fixture.serveToken(writer, request, body)
	case "/v1/origin-check":
		fixture.serveOrigin(writer, request, body)
	default:
		fixture.boundaries.service.Add(1)
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (fixture *serviceFixture) serveSession(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer "+apiKey {
		fixture.boundaries.service.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	value := fmt.Sprintf("%032d", fixture.sessions.Add(1))
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	http.SetCookie(writer, &http.Cookie{
		Name: "__Host-palisade_session", Value: value, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 3600, Expires: expires,
	})
	writeJSON(writer, http.StatusCreated, map[string]any{"session_id": value, "expires_at": expires})
}

func (fixture *serviceFixture) serveToken(writer http.ResponseWriter, request *http.Request, body []byte) {
	var payload struct {
		Action     string `json:"action"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	cookie, cookieErr := request.Cookie("__Host-palisade_session")
	if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer "+apiKey || cookieErr != nil ||
		cookie.Value == "" || decodeStrict(body, &payload) != nil || payload.Action != "write" || payload.TTLSeconds != 60 {
		fixture.boundaries.service.Add(1)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"proof_token": "synthetic-proof-token-00000000000000000000000000000000", "expires_in": 60})
}

func (fixture *serviceFixture) serveOrigin(writer http.ResponseWriter, request *http.Request, body []byte) {
	var payload struct {
		Action        string `json:"action"`
		EndpointClass string `json:"endpoint_class"`
		Sequence      uint64 `json:"sequence"`
		ProofToken    string `json:"proof_token"`
		Observations  struct {
			TransportProtocol   string `json:"transport_protocol"`
			TransportSecurity   string `json:"transport_security"`
			ClientAddressSource string `json:"client_address_source"`
		} `json:"observations"`
	}
	cookie, cookieErr := request.Cookie("__Host-palisade_session")
	binding := request.Header.Get("X-Palisade-Challenge-Binding")
	if request.Method != http.MethodPost || cookieErr != nil || cookie.Value == "" || decodeLoose(body, &payload) != nil ||
		payload.Action != "write" || payload.EndpointClass != "account" || payload.Sequence == 0 || payload.ProofToken == "" ||
		payload.Observations.TransportProtocol != fixture.expectedProtocol || payload.Observations.TransportSecurity != fixture.expectedSecurity ||
		payload.Observations.ClientAddressSource != fixture.expectedSource || len(binding) != 43 {
		fixture.boundaries.service.Add(1)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	decision := fixture.decisions.Add(1)
	writer.Header().Set("X-Palisade-Decision-ID", fmt.Sprintf("diagnostic-%08d", decision))
	writer.Header().Set("X-Palisade-Action", "observe")
	writer.Header().Set("X-Palisade-Handling", "pass")
	writer.Header().Set("X-Palisade-Mode", "shadow")
	writer.WriteHeader(http.StatusNoContent)
}

func headerContains(header http.Header, marker string) bool {
	for name, values := range header {
		if strings.Contains(strings.ToLower(name), marker) || strings.Contains(strings.ToLower(strings.Join(values, "\n")), marker) {
			return true
		}
	}
	return false
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	encoded, _ := json.Marshal(value)
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func decodeStrict(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrBoundary
	}
	return nil
}

func decodeLoose(encoded []byte, target any) error {
	if !json.Valid(encoded) {
		return ErrBoundary
	}
	return json.Unmarshal(encoded, target)
}

func TestReferenceAdaptersOverLoopbackHTTP2TLS(t *testing.T) {
	report, err := Run(context.Background(), Config{DurationSeconds: 1, Concurrency: 4, MaxOperations: 32})
	if err != nil {
		t.Fatal(err)
	}
	assertSuccessfulReport(t, report, 32)
	assertClosedReport(t, report)
}

func TestExecuteOperationRejectsOversizedAndInvalidResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		want    string
	}{
		{"oversized", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("X-Palisade-Adapter", "pass")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(bytes.Repeat([]byte("x"), MaximumResponseSize+1))
		}), "response_too_large"},
		{"invalid_status", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("X-Palisade-Adapter", "pass")
			writer.WriteHeader(http.StatusOK)
		}), "adapter_response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			if got := executeOperation(context.Background(), server.Client(), server.URL); got != test.want {
				t.Fatalf("failure = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProxyTLSLoadPlan(t *testing.T) {
	plan, err := ExecutionPlan(Config{
		DurationSeconds: environmentInteger(t, "PALISADE_PROXY_TLS_DURATION_SECONDS", 5),
		Concurrency:     environmentInteger(t, "PALISADE_PROXY_TLS_CONCURRENCY", 4),
		MaxOperations:   environmentInteger(t, "PALISADE_PROXY_TLS_MAX_OPERATIONS", MaximumOperations),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encoded))
}

func TestProxyTLSLoadDiagnostic(t *testing.T) {
	if os.Getenv("PALISADE_RUN_PROXY_TLS_LOAD") != "1" {
		t.Skip("set PALISADE_RUN_PROXY_TLS_LOAD=1 or run make proxy-tls-load-local")
	}
	config := Config{
		DurationSeconds: environmentInteger(t, "PALISADE_PROXY_TLS_DURATION_SECONDS", 5),
		Concurrency:     environmentInteger(t, "PALISADE_PROXY_TLS_CONCURRENCY", 4),
		MaxOperations:   environmentInteger(t, "PALISADE_PROXY_TLS_MAX_OPERATIONS", MaximumOperations),
	}
	report, err := Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	assertSuccessfulReport(t, report, config.MaxOperations)
	assertClosedReport(t, report)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encoded))
}

func environmentInteger(t *testing.T, name string, fallback int) int {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("%s must be an integer", name)
	}
	return parsed
}

func assertSuccessfulReport(t *testing.T, report Report, maximum int) {
	t.Helper()
	if err := ValidateReport(report); err != nil {
		t.Fatal(err)
	}
	if report.Result != "passed" || len(report.Profiles) != 2 {
		t.Fatalf("unexpected report result: %+v", report)
	}
	for _, profile := range report.Profiles {
		if profile.Result != "passed" || profile.AttemptedOperations == 0 || profile.AttemptedOperations > maximum ||
			profile.CompletedOperations != profile.AttemptedOperations || profile.ProtectedUpstreamRequests != profile.CompletedOperations ||
			profile.ServiceRequests < profile.CompletedOperations*2+1 || profile.ServiceRequests > profile.CompletedOperations*2+report.Configured.Concurrency ||
			profile.Failures.Total() != 0 || profile.BoundaryViolations.Total() != 0 {
			t.Fatalf("unexpected profile result: %+v", profile)
		}
	}
}

func assertClosedReport(t *testing.T, report Report) {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range append(slices.Clone(privateMarkers), "http://", "https://", "127.0.0.1", "192.0.2.15", "proof_token", "session_id", "cookie") {
		if strings.Contains(lower, strings.ToLower(forbidden)) {
			t.Fatalf("report contains forbidden value %q", forbidden)
		}
	}
}
