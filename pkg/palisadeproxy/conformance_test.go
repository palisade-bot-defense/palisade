package palisadeproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	conformanceSessionID    = "ABCDEFGHIJKLMNOPQRSTUVWX12345678"
	conformanceSessionValue = "synthetic-conformance-session"
)

type conformanceSuite struct {
	SchemaVersion     string                `json:"schema_version"`
	Contract          string                `json:"contract"`
	Scope             string                `json:"scope"`
	SyntheticOnly     bool                  `json:"synthetic_only"`
	PrivacyAssertions []string              `json:"privacy_assertions"`
	Scenarios         []conformanceScenario `json:"scenarios"`
}

type conformanceScenario struct {
	ID              string                 `json:"id"`
	Description     string                 `json:"description"`
	FailureMode     FailureMode            `json:"failure_mode"`
	RequestMethod   string                 `json:"request_method"`
	Classification  fixtureClassification  `json:"classification"`
	ServiceResponse fixtureServiceResponse `json:"service_response"`
	Expected        fixtureExpectation     `json:"expected"`
}

type fixtureClassification struct {
	Action           string `json:"action"`
	EndpointClass    string `json:"endpoint_class"`
	EvaluationCohort string `json:"evaluation_cohort"`
}

type fixtureServiceResponse struct {
	Status  int            `json:"status"`
	Headers fixtureHeaders `json:"headers"`
	Body    string         `json:"body"`
}

type fixtureHeaders struct {
	DecisionID  string `json:"decision_id"`
	Action      string `json:"action"`
	Handling    string `json:"handling"`
	Mode        string `json:"mode"`
	RolloutID   string `json:"rollout_id"`
	ChallengeID string `json:"challenge_id"`
	Location    string `json:"location"`
	RetryAfter  int    `json:"retry_after"`
}

type fixtureExpectation struct {
	Status       int             `json:"status"`
	NextCalls    int32           `json:"next_calls"`
	OriginChecks int32           `json:"origin_checks"`
	Headers      expectedHeaders `json:"headers"`
	ErrorCode    string          `json:"error_code"`
}

type expectedHeaders struct {
	Adapter     string `json:"adapter"`
	Action      string `json:"action"`
	ChallengeID string `json:"challenge_id"`
	Location    string `json:"location"`
	RetryAfter  int    `json:"retry_after"`
	ContentType string `json:"content_type"`
}

type conformanceService struct {
	t            *testing.T
	now          time.Time
	response     fixtureServiceResponse
	originChecks atomic.Int32
	mu           sync.Mutex
	bodies       [][]byte
	headers      []http.Header
}

func (s *conformanceService) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		s.t.Errorf("read synthetic service request: %v", err)
	}
	s.mu.Lock()
	s.bodies = append(s.bodies, append([]byte(nil), body...))
	s.headers = append(s.headers, request.Header.Clone())
	s.mu.Unlock()
	switch request.URL.Path {
	case "/v1/session":
		http.SetCookie(w, &http.Cookie{
			Name: SessionCookieName, Value: conformanceSessionValue, Path: "/", Expires: s.now.Add(time.Hour), MaxAge: 3600,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		writeFixtureJSON(w, http.StatusCreated, map[string]any{"session_id": conformanceSessionID, "expires_at": s.now.Add(time.Hour)})
	case "/v1/token":
		writeFixtureJSON(w, http.StatusCreated, map[string]any{"proof_token": "synthetic-proof", "expires_in": 60})
	case "/v1/origin-check":
		s.originChecks.Add(1)
		applyFixtureResponse(w, s.response)
	default:
		s.t.Errorf("unexpected service request %s", request.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestOriginAdapterConformanceSuiteV1(t *testing.T) {
	suite := loadConformanceSuite(t)
	if suite.SchemaVersion != "palisade.origin-adapter-conformance-suite.v1" || suite.Contract != "palisade.origin-adapter.v1" ||
		suite.Scope != "http_origin_middleware" || !suite.SyntheticOnly || len(suite.Scenarios) != 9 {
		t.Fatal("canonical conformance suite header or scenario count is invalid")
	}
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	for _, scenario := range suite.Scenarios {
		scenario := scenario
		t.Run(scenario.ID, func(t *testing.T) {
			serviceHandler := &conformanceService{t: t, now: now, response: scenario.ServiceResponse}
			service := httptest.NewServer(serviceHandler)
			defer service.Close()
			var upstreamCalls atomic.Int32
			proxy, err := New(Config{
				BaseURL: service.URL, APIKey: "synthetic-adapter-key", FailureMode: scenario.FailureMode,
				Upstream: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					upstreamCalls.Add(1)
					w.WriteHeader(http.StatusOK)
				}),
				Classifier: func(*http.Request) (Classification, error) {
					return Classification{
						Action: scenario.Classification.Action, EndpointClass: scenario.Classification.EndpointClass,
						EvaluationCohort: scenario.Classification.EvaluationCohort,
					}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			proxy.now = func() time.Time { return now }
			request := httptest.NewRequest(
				scenario.RequestMethod,
				"https://origin.example/conformance-path-secret?query_secret=conformance-query-secret",
				strings.NewReader("conformance-request-body-secret"),
			)
			request.Header.Set("User-Agent", "conformance-user-agent-secret")
			request.AddCookie(&http.Cookie{Name: "application_session", Value: "conformance-application-cookie-secret"})
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			if response.Code != scenario.Expected.Status || upstreamCalls.Load() != scenario.Expected.NextCalls ||
				serviceHandler.originChecks.Load() != scenario.Expected.OriginChecks {
				t.Fatalf("status/upstream/origin-checks = %d/%d/%d, want %d/%d/%d", response.Code, upstreamCalls.Load(), serviceHandler.originChecks.Load(),
					scenario.Expected.Status, scenario.Expected.NextCalls, scenario.Expected.OriginChecks)
			}
			assertHeaders(t, response, scenario.Expected.Headers)
			assertError(t, response.Body.Bytes(), scenario.Expected.ErrorCode)
			assertPrivateSentinelsAbsent(t, serviceHandler)
		})
	}
}

func TestLocalInputFailuresAlwaysFailClosed(t *testing.T) {
	for name, configure := range map[string]func(*Config){
		"classification": func(config *Config) {
			config.Classifier = func(*http.Request) (Classification, error) { return Classification{}, ErrInvalidClassification }
		},
		"signals": func(config *Config) {
			config.Signals = func(*http.Request) (Signals, error) { return Signals{}, ErrInvalidSignals }
		},
	} {
		t.Run(name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			config := Config{
				BaseURL: "http://127.0.0.1:1", APIKey: "synthetic", FailureMode: FailOpen,
				Classifier: StaticClassification("read", "public_content"),
				Upstream:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls.Add(1) }),
			}
			configure(&config)
			proxy, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://origin.example/", nil))
			if response.Code != http.StatusInternalServerError || upstreamCalls.Load() != 0 {
				t.Fatalf("status/upstream = %d/%d", response.Code, upstreamCalls.Load())
			}
		})
	}
}

func TestFailOpenPreservesApplicationBody(t *testing.T) {
	var got string
	proxy, err := New(Config{
		BaseURL: "http://127.0.0.1:1", APIKey: "synthetic", FailureMode: FailOpen,
		Classifier: StaticClassification("write", "account"),
		Upstream: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			contents, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Error(readErr)
			}
			got = string(contents)
			w.WriteHeader(http.StatusAccepted)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://origin.example/private?token=secret", strings.NewReader("private-body")))
	if response.Code != http.StatusAccepted || got != "private-body" {
		t.Fatalf("status/body = %d/%q", response.Code, got)
	}
}

func TestChallengeBindingChangesWithPrivateTargetButNeverExposesIt(t *testing.T) {
	state, err := newSequenceState(10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	class := Classification{Action: "read", EndpointClass: "public_content"}
	first := httptest.NewRequest(http.MethodGet, "https://origin.example/a?private=one", nil)
	second := httptest.NewRequest(http.MethodGet, "https://origin.example/b?private=two", nil)
	firstBinding := state.challengeBinding(first, class, "session", 1)
	secondBinding := state.challengeBinding(second, class, "session", 1)
	if firstBinding == secondBinding {
		t.Fatal("different private targets produced the same binding")
	}
	if bytes.Contains(firstBinding[:], []byte("private")) || bytes.Contains(secondBinding[:], []byte("private")) {
		t.Fatal("binding exposed private target material")
	}
}

func loadConformanceSuite(t *testing.T) conformanceSuite {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture path")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "examples", "conformance", "origin-adapter-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var suite conformanceSuite
	if err := decoder.Decode(&suite); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("trailing conformance JSON")
	}
	return suite
}

func applyFixtureResponse(w http.ResponseWriter, response fixtureServiceResponse) {
	for name, value := range map[string]string{
		"X-Palisade-Decision-ID": response.Headers.DecisionID, "X-Palisade-Action": response.Headers.Action,
		"X-Palisade-Handling": response.Headers.Handling, "X-Palisade-Mode": response.Headers.Mode,
		"X-Palisade-Rollout-ID": response.Headers.RolloutID, "X-Palisade-Challenge-ID": response.Headers.ChallengeID,
		"Location": response.Headers.Location,
	} {
		if value != "" {
			w.Header().Set(name, value)
		}
	}
	if response.Headers.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(response.Headers.RetryAfter))
	}
	w.WriteHeader(response.Status)
}

func assertHeaders(t *testing.T, response *httptest.ResponseRecorder, expected expectedHeaders) {
	t.Helper()
	for name, pair := range map[string][2]string{
		"X-Palisade-Adapter":      {response.Header().Get("X-Palisade-Adapter"), expected.Adapter},
		"X-Palisade-Action":       {response.Header().Get("X-Palisade-Action"), expected.Action},
		"X-Palisade-Challenge-ID": {response.Header().Get("X-Palisade-Challenge-ID"), expected.ChallengeID},
		"Location":                {response.Header().Get("Location"), expected.Location},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
	wantRetry := ""
	if expected.RetryAfter > 0 {
		wantRetry = strconv.Itoa(expected.RetryAfter)
	}
	if got := response.Header().Get("Retry-After"); got != wantRetry {
		t.Errorf("Retry-After = %q, want %q", got, wantRetry)
	}
	if expected.ContentType != "" && !strings.HasPrefix(response.Header().Get("Content-Type"), expected.ContentType) {
		t.Errorf("Content-Type = %q", response.Header().Get("Content-Type"))
	}
}

func assertError(t *testing.T, body []byte, want string) {
	t.Helper()
	if want == "" {
		if len(bytes.TrimSpace(body)) != 0 {
			t.Errorf("unexpected response body %q", body)
		}
		return
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Error != want {
		t.Errorf("error payload = %q decode=%v", payload.Error, err)
	}
}

func assertPrivateSentinelsAbsent(t *testing.T, service *conformanceService) {
	t.Helper()
	service.mu.Lock()
	defer service.mu.Unlock()
	forbidden := []string{"conformance-path-secret", "conformance-query-secret", "conformance-request-body-secret", "conformance-user-agent-secret", "conformance-application-cookie-secret", "application_session"}
	for index, body := range service.bodies {
		for _, sentinel := range forbidden {
			if bytes.Contains(body, []byte(sentinel)) {
				t.Errorf("service body %d exposed %q", index, sentinel)
			}
		}
	}
	for index, header := range service.headers {
		for name, values := range header {
			joined := strings.Join(values, "\n")
			for _, sentinel := range forbidden {
				if strings.Contains(joined, sentinel) {
					t.Errorf("service header %d %s exposed %q", index, name, sentinel)
				}
			}
		}
	}
}

func writeFixtureJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
