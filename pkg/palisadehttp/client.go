package palisadehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const maxServiceBody = 64 << 10

type Middleware struct {
	baseURL      *url.URL
	apiKey       string
	client       *http.Client
	classifier   Classifier
	signals      SignalProvider
	failureMode  FailureMode
	prefix       string
	fallbackPath string
	logger       *slog.Logger
	now          func() time.Time
	state        *boundedState
	transport    transportNormalizer
}

type apiStatusError struct {
	status int
	op     string
}

func (e apiStatusError) Error() string { return fmt.Sprintf("%s returned HTTP %d", e.op, e.status) }

type originResult struct {
	status      int
	action      string
	handling    string
	mode        string
	rolloutID   string
	retryAfter  int
	challengeID string
	location    string
}

func New(config Config) (*Middleware, error) {
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || !validBaseURL(baseURL) {
		return nil, ErrInvalidConfig
	}
	if config.APIKey == "" || len(config.APIKey) > 4096 || strings.ContainsAny(config.APIKey, "\r\n\x00") || config.Classifier == nil ||
		(config.FailureMode != FailOpen && config.FailureMode != FailClosed) {
		return nil, ErrInvalidConfig
	}
	if config.Prefix == "" {
		config.Prefix = DefaultPrefix
	}
	if !validPrefix(config.Prefix) || !validFallbackPath(config.FallbackPath) {
		return nil, ErrInvalidConfig
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = DefaultMaxSessions
	}
	if config.MaxGrants == 0 {
		config.MaxGrants = DefaultMaxGrants
	}
	if config.StateTTL == 0 {
		config.StateTTL = DefaultStateTTL
	}
	if config.GrantTTL == 0 {
		config.GrantTTL = DefaultGrantTTL
	}
	if config.PendingTTL == 0 {
		config.PendingTTL = DefaultPendingTTL
	}
	if config.MaxSessions < 1 || config.MaxSessions > 1_000_000 || config.MaxGrants < 1 || config.MaxGrants > 1_000_000 ||
		config.StateTTL < time.Minute || config.StateTTL > 24*time.Hour || config.GrantTTL < time.Second || config.GrantTTL > time.Minute ||
		config.PendingTTL < time.Minute || config.PendingTTL > 30*time.Minute {
		return nil, ErrInvalidConfig
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	transport, err := newTransportNormalizer(config)
	if err != nil {
		return nil, err
	}
	client := http.DefaultClient
	if config.HTTPClient != nil {
		clone := *config.HTTPClient
		client = &clone
	} else {
		clone := *http.DefaultClient
		client = &clone
	}
	if client.Timeout == 0 {
		client.Timeout = 3 * time.Second
	}
	// Per-browser PALISADE cookies are forwarded explicitly. A shared client jar
	// would mix sessions across concurrent origin users.
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")
	baseURL.RawPath = ""
	state, err := newBoundedState(config.MaxSessions, config.MaxGrants, config.StateTTL, config.GrantTTL, config.PendingTTL)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize bounded state: %v", ErrInvalidConfig, err)
	}
	return &Middleware{
		baseURL: baseURL, apiKey: config.APIKey, client: client, classifier: config.Classifier, signals: config.Signals,
		failureMode: config.FailureMode, prefix: config.Prefix, fallbackPath: config.FallbackPath,
		logger: config.Logger, now: time.Now,
		state: state, transport: transport,
	}, nil
}

func validBaseURL(baseURL *url.URL) bool {
	if baseURL == nil || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.Opaque != "" || baseURL.RawPath != "" || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return false
	}
	if baseURL.Path != "" && baseURL.Path != "/" && (path.Clean(baseURL.Path) != baseURL.Path || strings.HasSuffix(baseURL.Path, "/")) {
		return false
	}
	if baseURL.Scheme == "https" {
		return true
	}
	hostname := baseURL.Hostname()
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	address := net.ParseIP(hostname)
	return address != nil && address.IsLoopback()
}

func validPrefix(value string) bool {
	return len(value) >= 2 && len(value) <= 64 && strings.HasPrefix(value, "/") && !strings.HasSuffix(value, "/") &&
		path.Clean(value) == value && !strings.ContainsAny(value, "?%#\\\r\n\x00")
}

func validFallbackPath(value string) bool {
	return value == "" || (len(value) <= 256 && strings.HasPrefix(value, "/") && path.Clean(value) == value && !strings.ContainsAny(value, "?%#\\\r\n\x00"))
}

func (m *Middleware) endpoint(apiPath string) string {
	copy := *m.baseURL
	copy.Path = m.baseURL.Path + apiPath
	copy.RawPath = ""
	copy.RawQuery = ""
	copy.Fragment = ""
	return copy.String()
}

func (m *Middleware) issueSession(ctx context.Context) (http.Cookie, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint("/v1/session"), nil)
	if err != nil {
		return http.Cookie{}, err
	}
	request.Header.Set("Authorization", "Bearer "+m.apiKey)
	response, err := m.client.Do(request)
	if err != nil {
		return http.Cookie{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = readBounded(response.Body, maxServiceBody)
		return http.Cookie{}, apiStatusError{status: response.StatusCode, op: "session issuance"}
	}
	var payload struct {
		SessionID string    `json:"session_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	now := m.now().UTC()
	if err := decodeBounded(response.Body, &payload); err != nil || len(payload.SessionID) != 32 || !stableValue(payload.SessionID) ||
		!payload.ExpiresAt.After(now) || payload.ExpiresAt.After(now.Add(25*time.Hour)) {
		return http.Cookie{}, ErrInvalidResponse
	}
	var selected *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == SessionCookieName {
			if selected != nil {
				return http.Cookie{}, ErrInvalidResponse
			}
			copy := *cookie
			selected = &copy
		}
	}
	if selected == nil || selected.Value == "" || len(selected.Value) > 4096 || selected.Path != "/" || selected.Domain != "" || !selected.Secure || !selected.HttpOnly ||
		selected.SameSite != http.SameSiteLaxMode || selected.MaxAge < 1 || selected.MaxAge > 24*60*60 || !selected.Expires.After(now) ||
		selected.Expires.After(now.Add(25*time.Hour)) || selected.Expires.Sub(payload.ExpiresAt) < -time.Second || selected.Expires.Sub(payload.ExpiresAt) > time.Second {
		return http.Cookie{}, ErrInvalidResponse
	}
	return *selected, nil
}

func (m *Middleware) issueProof(ctx context.Context, cookie http.Cookie, action string) (string, error) {
	payload := struct {
		Action     string `json:"action"`
		TTLSeconds int    `json:"ttl_seconds"`
	}{Action: action, TTLSeconds: 60}
	var result struct {
		ProofToken string `json:"proof_token"`
		ExpiresIn  int    `json:"expires_in"`
	}
	status, err := m.postJSON(ctx, "/v1/token", payload, &cookie, true, &result)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", apiStatusError{status: status, op: "proof issuance"}
	}
	if result.ProofToken == "" || len(result.ProofToken) > 8192 || result.ExpiresIn < 1 || result.ExpiresIn > 300 {
		return "", ErrInvalidResponse
	}
	return result.ProofToken, nil
}

func (m *Middleware) checkOrigin(ctx context.Context, cookie http.Cookie, classification Classification, signals Signals, sequence uint64, proof string) (originResult, error) {
	payload := struct {
		Action           string  `json:"action"`
		EndpointClass    string  `json:"endpoint_class"`
		EvaluationCohort string  `json:"evaluation_cohort,omitempty"`
		Sequence         uint64  `json:"sequence"`
		ProofToken       string  `json:"proof_token"`
		Observations     Signals `json:"observations"`
	}{Action: classification.Action, EndpointClass: classification.EndpointClass, EvaluationCohort: classification.EvaluationCohort, Sequence: sequence, ProofToken: proof, Observations: signals}
	body, err := json.Marshal(payload)
	if err != nil {
		return originResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint("/v1/origin-check"), bytes.NewReader(body))
	if err != nil {
		return originResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&cookie)
	response, err := m.client.Do(request)
	if err != nil {
		return originResult{}, err
	}
	contents, err := readBounded(response.Body, maxServiceBody)
	if err != nil || len(bytes.TrimSpace(contents)) != 0 {
		return originResult{}, ErrInvalidResponse
	}
	result := originResult{
		status: response.StatusCode, action: response.Header.Get("X-Palisade-Action"), handling: response.Header.Get("X-Palisade-Handling"),
		mode: response.Header.Get("X-Palisade-Mode"), rolloutID: response.Header.Get("X-Palisade-Rollout-ID"),
		challengeID: response.Header.Get("X-Palisade-Challenge-ID"), location: response.Header.Get("Location"),
	}
	if !stableValue(response.Header.Get("X-Palisade-Decision-ID")) || (result.mode != "shadow" && result.mode != "canary" && result.mode != "enforce") {
		return originResult{}, ErrInvalidResponse
	}
	if result.rolloutID != "" && !stableValue(result.rolloutID) {
		return originResult{}, ErrInvalidResponse
	}
	if retry := response.Header.Get("Retry-After"); retry != "" {
		result.retryAfter, err = strconv.Atoi(retry)
		if err != nil || retry != integerString(result.retryAfter) {
			return originResult{}, ErrInvalidResponse
		}
	}
	switch result.status {
	case http.StatusNoContent:
		if result.handling != "pass" || (result.action != "allow" && result.action != "observe") || result.retryAfter != 0 || result.challengeID != "" || result.location != "" {
			return originResult{}, ErrInvalidResponse
		}
	case http.StatusTooManyRequests:
		validDelay := result.handling == "delay" && result.action == "delay" && result.retryAfter == 1
		validThrottle := result.handling == "throttle" && result.action == "throttle" && result.retryAfter >= 1 && result.retryAfter <= 60
		if result.mode == "shadow" || result.rolloutID == "" || (!validDelay && !validThrottle) || result.challengeID != "" || result.location != "" {
			return originResult{}, ErrInvalidResponse
		}
	case http.StatusForbidden:
		if result.handling == "challenge" && result.action == "challenge" {
			if result.mode == "shadow" || result.rolloutID == "" || !validChallengeID(result.challengeID) || result.location != "/v1/challenge/"+result.challengeID || result.retryAfter != 0 {
				return originResult{}, ErrInvalidResponse
			}
		} else if result.handling == "block" && result.action == "block" {
			if result.mode == "shadow" || result.rolloutID == "" || result.retryAfter < 1 || result.retryAfter > 3600 || result.challengeID != "" || result.location != "" {
				return originResult{}, ErrInvalidResponse
			}
		} else {
			return originResult{}, ErrInvalidResponse
		}
	default:
		return originResult{}, apiStatusError{status: result.status, op: "origin check"}
	}
	return result, nil
}

func (m *Middleware) postJSON(ctx context.Context, apiPath string, payload any, cookie *http.Cookie, authorized bool, target any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint(apiPath), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	if authorized {
		request.Header.Set("Authorization", "Bearer "+m.apiKey)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := m.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if target == nil {
		contents, readErr := readBounded(response.Body, maxServiceBody)
		if readErr != nil || (response.StatusCode == http.StatusNoContent && len(bytes.TrimSpace(contents)) != 0) {
			return 0, ErrInvalidResponse
		}
		return response.StatusCode, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = readBounded(response.Body, maxServiceBody)
		return response.StatusCode, nil
	}
	if err := decodeBounded(response.Body, target); err != nil {
		return 0, ErrInvalidResponse
	}
	return response.StatusCode, nil
}

func decodeBounded(reader io.Reader, target any) error {
	contents, err := readBounded(reader, maxServiceBody)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidResponse
	}
	return nil
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		return nil, ErrInvalidResponse
	}
	return contents, nil
}

func stableValue(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') ||
			character == '_' || character == '.' || character == ':' || character == '-') {
			return false
		}
	}
	return true
}

func validChallengeID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}
