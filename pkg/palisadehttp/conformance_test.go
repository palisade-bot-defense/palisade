package palisadehttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	adapterConformanceSuiteVersion = "palisade.origin-adapter-conformance-suite.v1"
	adapterContractVersion         = "palisade.origin-adapter.v1"
	conformanceSessionValue        = "synthetic-conformance-session"
)

type adapterConformanceSuite struct {
	SchemaVersion     string                       `json:"schema_version"`
	Contract          string                       `json:"contract"`
	Scope             string                       `json:"scope"`
	SyntheticOnly     bool                         `json:"synthetic_only"`
	PrivacyAssertions []string                     `json:"privacy_assertions"`
	Scenarios         []adapterConformanceScenario `json:"scenarios"`
}

type adapterConformanceScenario struct {
	ID              string                    `json:"id"`
	Description     string                    `json:"description"`
	FailureMode     FailureMode               `json:"failure_mode"`
	RequestMethod   string                    `json:"request_method"`
	Classification  adapterFixtureClass       `json:"classification"`
	ServiceResponse adapterFixtureResponse    `json:"service_response"`
	Expected        adapterFixtureExpectation `json:"expected"`
}

type adapterFixtureClass struct {
	Action           string `json:"action"`
	EndpointClass    string `json:"endpoint_class"`
	EvaluationCohort string `json:"evaluation_cohort"`
}

type adapterFixtureResponse struct {
	Status  int                   `json:"status"`
	Headers adapterFixtureHeaders `json:"headers"`
	Body    string                `json:"body"`
}

type adapterFixtureHeaders struct {
	DecisionID  string `json:"decision_id"`
	Action      string `json:"action"`
	Handling    string `json:"handling"`
	Mode        string `json:"mode"`
	RolloutID   string `json:"rollout_id"`
	ChallengeID string `json:"challenge_id"`
	Location    string `json:"location"`
	RetryAfter  int    `json:"retry_after"`
}

type adapterFixtureExpectation struct {
	Status       int                    `json:"status"`
	NextCalls    int32                  `json:"next_calls"`
	OriginChecks int32                  `json:"origin_checks"`
	Headers      adapterExpectedHeaders `json:"headers"`
	ErrorCode    string                 `json:"error_code"`
}

type adapterExpectedHeaders struct {
	Adapter     string `json:"adapter"`
	Action      string `json:"action"`
	ChallengeID string `json:"challenge_id"`
	Location    string `json:"location"`
	RetryAfter  int    `json:"retry_after"`
	ContentType string `json:"content_type"`
}

type conformanceService struct {
	t              *testing.T
	now            time.Time
	response       adapterFixtureResponse
	originChecks   atomic.Int32
	mu             sync.Mutex
	serviceBodies  [][]byte
	serviceHeaders []http.Header
}

func (s *conformanceService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.t.Errorf("read synthetic service request: %v", err)
	}
	s.mu.Lock()
	s.serviceBodies = append(s.serviceBodies, append([]byte(nil), body...))
	s.serviceHeaders = append(s.serviceHeaders, r.Header.Clone())
	s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/session":
		http.SetCookie(w, &http.Cookie{
			Name: SessionCookieName, Value: conformanceSessionValue, Path: "/", Expires: s.now.Add(time.Hour), MaxAge: 3600,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		writeFakeJSON(w, http.StatusCreated, map[string]any{
			"session_id": testSessionID, "expires_at": s.now.Add(time.Hour),
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/token":
		writeFakeJSON(w, http.StatusCreated, map[string]any{"proof_token": "synthetic-proof", "expires_in": 60})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/origin-check":
		s.originChecks.Add(1)
		applyFixtureResponse(w, s.response)
	default:
		s.t.Errorf("unexpected synthetic service request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestOriginAdapterConformanceSuiteV1(t *testing.T) {
	suite := readAdapterConformanceSuite(t)
	if err := validateAdapterConformanceSuite(suite); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)

	for _, scenario := range suite.Scenarios {
		scenario := scenario
		t.Run(scenario.ID, func(t *testing.T) {
			serviceHandler := &conformanceService{t: t, now: now, response: scenario.ServiceResponse}
			service := httptest.NewServer(serviceHandler)
			defer service.Close()

			guard, err := New(Config{
				BaseURL:     service.URL,
				APIKey:      "synthetic-adapter-key",
				FailureMode: scenario.FailureMode,
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
			guard.now = func() time.Time { return now }

			var nextCalls atomic.Int32
			handler := guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			request := httptest.NewRequest(
				scenario.RequestMethod,
				"https://origin.example/conformance-path-secret?query_secret=conformance-query-secret",
				strings.NewReader("conformance-request-body-secret"),
			)
			request.Header.Set("User-Agent", "conformance-user-agent-secret")
			request.AddCookie(&http.Cookie{Name: "application_session", Value: "conformance-application-cookie-secret"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != scenario.Expected.Status || nextCalls.Load() != scenario.Expected.NextCalls ||
				serviceHandler.originChecks.Load() != scenario.Expected.OriginChecks {
				t.Fatalf("status/next/origin-checks = %d/%d/%d, want %d/%d/%d", response.Code, nextCalls.Load(), serviceHandler.originChecks.Load(),
					scenario.Expected.Status, scenario.Expected.NextCalls, scenario.Expected.OriginChecks)
			}
			assertExpectedAdapterHeaders(t, response, scenario.Expected.Headers)
			assertExpectedAdapterError(t, response.Body.Bytes(), scenario.Expected.ErrorCode)
			assertNoApplicationRequestDataReachedService(t, serviceHandler)
		})
	}
}

func TestOriginAdapterConformanceSuiteRejectsContractPoisoning(t *testing.T) {
	canonical := readAdapterConformanceSuite(t)
	for name, mutate := range map[string]func(*adapterConformanceSuite){
		"wrong contract version": func(suite *adapterConformanceSuite) { suite.Contract = "palisade.origin-adapter.v2" },
		"not synthetic":          func(suite *adapterConformanceSuite) { suite.SyntheticOnly = false },
		"missing privacy assertion": func(suite *adapterConformanceSuite) {
			suite.PrivacyAssertions = suite.PrivacyAssertions[:len(suite.PrivacyAssertions)-1]
		},
		"missing scenario":       func(suite *adapterConformanceSuite) { suite.Scenarios = suite.Scenarios[:len(suite.Scenarios)-1] },
		"duplicate scenario id":  func(suite *adapterConformanceSuite) { suite.Scenarios[1].ID = suite.Scenarios[0].ID },
		"nonempty service body":  func(suite *adapterConformanceSuite) { suite.Scenarios[0].ServiceResponse.Body = "unsafe" },
		"invalid response tuple": func(suite *adapterConformanceSuite) { suite.Scenarios[0].ServiceResponse.Headers.Action = "block" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := canonical
			mutated.PrivacyAssertions = append([]string(nil), canonical.PrivacyAssertions...)
			mutated.Scenarios = append([]adapterConformanceScenario(nil), canonical.Scenarios...)
			mutate(&mutated)
			if err := validateAdapterConformanceSuite(mutated); err == nil {
				t.Fatal("poisoned conformance suite was accepted")
			}
		})
	}

	encoded, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{
		"unknown field": bytes.Replace(encoded, []byte(`{"schema_version"`), []byte(`{"unknown":true,"schema_version"`), 1),
		"trailing JSON": append(append([]byte(nil), encoded...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAdapterConformanceSuite(contents); err == nil {
				t.Fatal("invalid JSON contract was accepted")
			}
		})
	}
}

func readAdapterConformanceSuite(t *testing.T) adapterConformanceSuite {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve conformance test path")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "examples", "conformance", "origin-adapter-v1.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	suite, err := decodeAdapterConformanceSuite(contents)
	if err != nil {
		t.Fatalf("decode conformance suite: %v", err)
	}
	return suite
}

func decodeAdapterConformanceSuite(contents []byte) (adapterConformanceSuite, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var suite adapterConformanceSuite
	if err := decoder.Decode(&suite); err != nil {
		return adapterConformanceSuite{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return adapterConformanceSuite{}, fmt.Errorf("trailing JSON")
		}
		return adapterConformanceSuite{}, fmt.Errorf("trailing JSON: %w", err)
	}
	return suite, nil
}

func validateAdapterConformanceSuite(suite adapterConformanceSuite) error {
	if suite.SchemaVersion != adapterConformanceSuiteVersion || suite.Contract != adapterContractVersion ||
		suite.Scope != "http_origin_middleware" || !suite.SyntheticOnly {
		return fmt.Errorf("invalid conformance suite header")
	}
	wantPrivacy := []string{"no_application_cookie", "no_application_url", "no_query_string", "no_raw_user_agent", "no_request_body"}
	gotPrivacy := append([]string(nil), suite.PrivacyAssertions...)
	sort.Strings(gotPrivacy)
	if fmt.Sprint(gotPrivacy) != fmt.Sprint(wantPrivacy) {
		return fmt.Errorf("privacy assertions = %v, want %v", gotPrivacy, wantPrivacy)
	}
	wantIDs := []string{
		"canary_challenge_unsafe_method", "canary_delay", "canary_throttle", "enforce_temporary_block", "risky_shadow_fail_closed",
		"risky_shadow_fail_open", "shadow_pass", "unavailable_fail_closed", "unavailable_fail_open",
	}
	seen := make(map[string]bool, len(suite.Scenarios))
	for _, scenario := range suite.Scenarios {
		if seen[scenario.ID] {
			return fmt.Errorf("duplicate conformance scenario %q", scenario.ID)
		}
		seen[scenario.ID] = true
		if scenario.Description == "" || (scenario.RequestMethod != http.MethodGet && scenario.RequestMethod != http.MethodPost) ||
			(scenario.FailureMode != FailOpen && scenario.FailureMode != FailClosed) ||
			!validClassification(Classification{
				Action: scenario.Classification.Action, EndpointClass: scenario.Classification.EndpointClass,
				EvaluationCohort: scenario.Classification.EvaluationCohort,
			}) || scenario.ServiceResponse.Body != "" {
			return fmt.Errorf("invalid conformance scenario %q", scenario.ID)
		}
		if err := validateFixtureServiceResponse(scenario); err != nil {
			return err
		}
	}
	gotIDs := make([]string, 0, len(seen))
	for id := range seen {
		gotIDs = append(gotIDs, id)
	}
	sort.Strings(gotIDs)
	if fmt.Sprint(gotIDs) != fmt.Sprint(wantIDs) {
		return fmt.Errorf("scenario ids = %v, want %v", gotIDs, wantIDs)
	}
	return nil
}

func validateFixtureServiceResponse(scenario adapterConformanceScenario) error {
	h := scenario.ServiceResponse.Headers
	validPass := scenario.ServiceResponse.Status == http.StatusNoContent && h.DecisionID != "" && (h.Action == "allow" || h.Action == "observe") && h.Handling == "pass" && h.Mode == "shadow" && h.RolloutID == "" && h.RetryAfter == 0 && h.ChallengeID == "" && h.Location == ""
	validDelay := scenario.ServiceResponse.Status == http.StatusTooManyRequests && h.DecisionID != "" && h.Action == "delay" && h.Handling == "delay" && h.Mode == "canary" && h.RolloutID != "" && h.RetryAfter == 1 && h.ChallengeID == "" && h.Location == ""
	validThrottle := scenario.ServiceResponse.Status == http.StatusTooManyRequests && h.DecisionID != "" && h.Action == "throttle" && h.Handling == "throttle" && h.Mode == "canary" && h.RolloutID != "" && h.RetryAfter >= 1 && h.RetryAfter <= 60 && h.ChallengeID == "" && h.Location == ""
	validChallenge := scenario.ServiceResponse.Status == http.StatusForbidden && h.DecisionID != "" && h.Action == "challenge" && h.Handling == "challenge" && h.Mode == "canary" && h.RolloutID != "" && validChallengeID(h.ChallengeID) && h.Location == "/v1/challenge/"+h.ChallengeID && h.RetryAfter == 0
	validBlock := scenario.ServiceResponse.Status == http.StatusForbidden && h.DecisionID != "" && h.Action == "block" && h.Handling == "block" && h.Mode == "enforce" && h.RolloutID != "" && h.RetryAfter >= 1 && h.RetryAfter <= 3600 && h.ChallengeID == "" && h.Location == ""
	unavailable := scenario.ServiceResponse.Status == http.StatusServiceUnavailable && h == (adapterFixtureHeaders{})
	riskyShadow := strings.HasPrefix(scenario.ID, "risky_shadow_") && scenario.ServiceResponse.Status == http.StatusForbidden && h.Action == "block" && h.Handling == "block" && h.Mode == "shadow"
	if !(validPass || validDelay || validThrottle || validChallenge || validBlock || unavailable || riskyShadow) {
		return fmt.Errorf("scenario %q has an invalid synthetic service response", scenario.ID)
	}
	return nil
}

func applyFixtureResponse(w http.ResponseWriter, response adapterFixtureResponse) {
	headers := response.Headers
	for name, value := range map[string]string{
		"X-Palisade-Decision-ID":  headers.DecisionID,
		"X-Palisade-Action":       headers.Action,
		"X-Palisade-Handling":     headers.Handling,
		"X-Palisade-Mode":         headers.Mode,
		"X-Palisade-Rollout-ID":   headers.RolloutID,
		"X-Palisade-Challenge-ID": headers.ChallengeID,
		"Location":                headers.Location,
	} {
		if value != "" {
			w.Header().Set(name, value)
		}
	}
	if headers.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(headers.RetryAfter))
	}
	w.WriteHeader(response.Status)
}

func assertExpectedAdapterHeaders(t *testing.T, response *httptest.ResponseRecorder, expected adapterExpectedHeaders) {
	t.Helper()
	for name, values := range map[string]struct{ got, want string }{
		"X-Palisade-Adapter":      {response.Header().Get("X-Palisade-Adapter"), expected.Adapter},
		"X-Palisade-Action":       {response.Header().Get("X-Palisade-Action"), expected.Action},
		"X-Palisade-Challenge-ID": {response.Header().Get("X-Palisade-Challenge-ID"), expected.ChallengeID},
		"Location":                {response.Header().Get("Location"), expected.Location},
	} {
		if values.got != values.want {
			t.Errorf("%s = %q, want %q", name, values.got, values.want)
		}
	}
	retry := ""
	if expected.RetryAfter > 0 {
		retry = strconv.Itoa(expected.RetryAfter)
	}
	if got := response.Header().Get("Retry-After"); got != retry {
		t.Errorf("Retry-After = %q, want %q", got, retry)
	}
	if expected.ContentType != "" && !strings.HasPrefix(response.Header().Get("Content-Type"), expected.ContentType) {
		t.Errorf("Content-Type = %q, want prefix %q", response.Header().Get("Content-Type"), expected.ContentType)
	}
}

func assertExpectedAdapterError(t *testing.T, body []byte, want string) {
	t.Helper()
	if want == "" {
		if len(bytes.TrimSpace(body)) != 0 {
			t.Errorf("unexpected adapter response body %q", body)
		}
		return
	}
	var payload struct {
		Error string `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Error != want {
		t.Errorf("adapter error = %q decode=%v, want %q", payload.Error, err, want)
	}
}

func assertNoApplicationRequestDataReachedService(t *testing.T, service *conformanceService) {
	t.Helper()
	service.mu.Lock()
	defer service.mu.Unlock()
	forbidden := []string{
		"conformance-path-secret", "conformance-query-secret", "conformance-request-body-secret",
		"conformance-user-agent-secret", "conformance-application-cookie-secret", "application_session",
	}
	for index, body := range service.serviceBodies {
		for _, value := range forbidden {
			if bytes.Contains(body, []byte(value)) {
				t.Errorf("service request %d body exposed application sentinel %q", index, value)
			}
		}
	}
	for index, header := range service.serviceHeaders {
		for name, values := range header {
			joined := strings.Join(values, "\n")
			for _, value := range forbidden {
				if strings.Contains(joined, value) {
					t.Errorf("service request %d header %s exposed application sentinel %q", index, name, value)
				}
			}
		}
	}
}
