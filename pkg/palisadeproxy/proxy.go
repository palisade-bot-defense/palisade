package palisadeproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadecontract"
	"github.com/palisade-human-trust/palisade/pkg/palisadeedge"
)

const maxServiceBody = 64 << 10

type Proxy struct {
	baseURL     *url.URL
	apiKey      string
	client      *http.Client
	upstream    http.Handler
	classifier  Classifier
	signals     SignalProvider
	failureMode FailureMode
	prefix      string
	logger      *slog.Logger
	state       *sequenceState
	edgeSignals *palisadeedge.Verifier
	now         func() time.Time
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

func New(config Config) (*Proxy, error) {
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || !validBaseURL(baseURL) || config.Upstream == nil || config.Classifier == nil ||
		config.APIKey == "" || len(config.APIKey) > 4096 || strings.ContainsAny(config.APIKey, "\r\n\x00") ||
		(config.FailureMode != FailOpen && config.FailureMode != FailClosed) {
		return nil, ErrInvalidConfig
	}
	if config.Prefix == "" {
		config.Prefix = DefaultPrefix
	}
	if !validPrefix(config.Prefix) {
		return nil, ErrInvalidConfig
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = DefaultMaxSessions
	}
	if config.StateTTL == 0 {
		config.StateTTL = DefaultStateTTL
	}
	if config.MaxSessions < 1 || config.MaxSessions > 1_000_000 || config.StateTTL < time.Minute || config.StateTTL > 24*time.Hour {
		return nil, ErrInvalidConfig
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
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
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")
	baseURL.RawPath, baseURL.RawQuery, baseURL.Fragment = "", "", ""
	state, err := newSequenceState(config.MaxSessions, config.StateTTL)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize bounded state: %v", ErrInvalidConfig, err)
	}
	return &Proxy{
		baseURL: baseURL, apiKey: config.APIKey, client: client, upstream: config.Upstream,
		classifier: config.Classifier, signals: config.Signals, failureMode: config.FailureMode,
		prefix: config.Prefix, logger: config.Logger, state: state, edgeSignals: config.EdgeSignals, now: time.Now,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	classification, err := p.classifier(request)
	if err != nil || !validClassification(classification) {
		writeError(w, http.StatusInternalServerError, "palisade_classification_failed")
		return
	}
	signals := Signals{UserAgentPresent: strings.TrimSpace(request.UserAgent()) != ""}
	if p.signals != nil {
		signals, err = p.signals(request)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "palisade_signals_failed")
			return
		}
	}
	signals.TransportProtocol, signals.TransportSecurity, signals.ClientAddressSource = normalizeTransport(request)
	// This generic adapter has no crawler registry. A custom signal provider
	// therefore cannot promote a client claim into verified identity.
	signals.VerifiedBot = false
	signals.CrawlerClass = "unknown"
	signals.CrawlerVerification = "unknown"
	if p.edgeSignals != nil {
		edgeSignals, present, verifyErr := p.edgeSignals.Verify(request)
		if verifyErr != nil || (present && !mergeEdgeSignals(&signals, edgeSignals)) {
			writeError(w, http.StatusInternalServerError, "palisade_signals_failed")
			return
		}
		request.Header.Del(palisadeedge.PayloadHeader)
		request.Header.Del(palisadeedge.SignatureHeader)
	}
	if !validSignals(signals) {
		writeError(w, http.StatusInternalServerError, "palisade_signals_failed")
		return
	}

	cookie, incoming, err := sessionCookie(request)
	if err != nil {
		p.unavailable(w, request, "session", err)
		return
	}
	if !incoming {
		cookie, err = p.issueSession(request.Context())
		if err != nil {
			p.unavailable(w, request, "session", err)
			return
		}
		http.SetCookie(w, &cookie)
	}
	proof, err := p.issueProof(request.Context(), cookie, classification.Action)
	var statusError apiStatusError
	if incoming && errors.As(err, &statusError) && statusError.status == http.StatusUnauthorized {
		cookie, err = p.issueSession(request.Context())
		if err == nil {
			http.SetCookie(w, &cookie)
			proof, err = p.issueProof(request.Context(), cookie, classification.Action)
		}
	}
	if err != nil {
		p.unavailable(w, request, "proof", err)
		return
	}
	sequence, err := p.state.next(cookie.Value, p.now().UTC())
	if err != nil {
		p.unavailable(w, request, "sequence", err)
		return
	}
	binding := p.state.challengeBinding(request, classification, cookie.Value, sequence)
	result, err := p.checkOrigin(request.Context(), cookie, classification, signals, sequence, proof, base64.RawURLEncoding.EncodeToString(binding[:]))
	if err != nil {
		p.unavailable(w, request, "origin_check", err)
		return
	}
	switch result.status {
	case http.StatusNoContent:
		w.Header().Set("X-Palisade-Adapter", "pass")
		p.upstream.ServeHTTP(w, request)
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", strconv.Itoa(result.retryAfter))
		w.Header().Set("X-Palisade-Action", result.action)
		w.WriteHeader(http.StatusTooManyRequests)
	case http.StatusForbidden:
		w.Header().Set("X-Palisade-Action", result.action)
		if result.handling == "block" {
			w.Header().Set("Retry-After", strconv.Itoa(result.retryAfter))
		} else {
			w.Header().Set("X-Palisade-Challenge-ID", result.challengeID)
			w.Header().Set("Location", p.prefix+"/challenge/"+result.challengeID)
		}
		w.WriteHeader(http.StatusForbidden)
	}
}

func mergeEdgeSignals(target *Signals, source palisadeedge.Signals) bool {
	if !mergeClosedSignal(&target.ChallengeVerdict, source.ChallengeVerdict) ||
		!mergeClosedSignal(&target.EdgeFingerprintClass, source.EdgeFingerprintClass) ||
		!mergeClosedSignal(&target.EdgeFingerprintMethod, source.EdgeFingerprintMethod) ||
		!mergeClosedSignal(&target.NetworkReputation, source.NetworkReputation) ||
		!mergeClosedSignal(&target.NetworkType, source.NetworkType) {
		return false
	}
	if source.ExternalRiskScore > target.ExternalRiskScore {
		target.ExternalRiskScore = source.ExternalRiskScore
	}
	target.PolicyAlert = target.PolicyAlert || source.PolicyAlert
	return true
}

func mergeClosedSignal(target *string, source string) bool {
	if source == "" || source == "unknown" {
		return true
	}
	if *target == "" || *target == "unknown" {
		*target = source
		return true
	}
	return *target == source
}

func (p *Proxy) unavailable(w http.ResponseWriter, request *http.Request, operation string, err error) {
	p.logger.Warn("PALISADE reverse-proxy dependency unavailable", "operation", operation, "error", err)
	if p.failureMode == FailOpen {
		w.Header().Set("X-Palisade-Adapter", "bypass_unavailable")
		p.upstream.ServeHTTP(w, request)
		return
	}
	writeError(w, http.StatusServiceUnavailable, "palisade_unavailable")
}

func (p *Proxy) endpoint(apiPath string) string {
	copy := *p.baseURL
	copy.Path = p.baseURL.Path + apiPath
	return copy.String()
}

func (p *Proxy) issueSession(ctx context.Context) (http.Cookie, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint("/v1/session"), nil)
	if err != nil {
		return http.Cookie{}, err
	}
	request.Header.Set("Authorization", "Bearer "+p.apiKey)
	response, err := p.client.Do(request)
	if err != nil {
		return http.Cookie{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = readBounded(response.Body)
		return http.Cookie{}, apiStatusError{status: response.StatusCode, op: "session issuance"}
	}
	var payload struct {
		SessionID string    `json:"session_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := decodeBounded(response.Body, &payload); err != nil {
		return http.Cookie{}, ErrInvalidResponse
	}
	now := p.now().UTC()
	if len(payload.SessionID) != 32 || !stableValue(payload.SessionID) || !payload.ExpiresAt.After(now) || payload.ExpiresAt.After(now.Add(25*time.Hour)) {
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
	if selected == nil || selected.Value == "" || len(selected.Value) > 4096 || selected.Path != "/" || selected.Domain != "" ||
		!selected.Secure || !selected.HttpOnly || selected.SameSite != http.SameSiteLaxMode || selected.MaxAge < 1 || selected.MaxAge > 86400 ||
		!selected.Expires.After(now) || selected.Expires.After(now.Add(25*time.Hour)) || selected.Expires.Sub(payload.ExpiresAt) < -time.Second || selected.Expires.Sub(payload.ExpiresAt) > time.Second {
		return http.Cookie{}, ErrInvalidResponse
	}
	return *selected, nil
}

func (p *Proxy) issueProof(ctx context.Context, cookie http.Cookie, action string) (string, error) {
	payload := struct {
		Action     string `json:"action"`
		TTLSeconds int    `json:"ttl_seconds"`
	}{action, 60}
	var result struct {
		ProofToken string `json:"proof_token"`
		ExpiresIn  int    `json:"expires_in"`
	}
	status, err := p.postJSON(ctx, "/v1/token", payload, &cookie, true, &result)
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

func (p *Proxy) checkOrigin(ctx context.Context, cookie http.Cookie, classification Classification, signals Signals, sequence uint64, proof, binding string) (originResult, error) {
	payload := struct {
		Action           string  `json:"action"`
		EndpointClass    string  `json:"endpoint_class"`
		EvaluationCohort string  `json:"evaluation_cohort,omitempty"`
		Sequence         uint64  `json:"sequence"`
		ProofToken       string  `json:"proof_token"`
		Observations     Signals `json:"observations"`
	}{classification.Action, classification.EndpointClass, classification.EvaluationCohort, sequence, proof, signals}
	body, err := json.Marshal(payload)
	if err != nil {
		return originResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint("/v1/origin-check"), bytes.NewReader(body))
	if err != nil {
		return originResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Palisade-Challenge-Binding", binding)
	request.AddCookie(&cookie)
	response, err := p.client.Do(request)
	if err != nil {
		return originResult{}, err
	}
	defer response.Body.Close()
	contents, err := readBounded(response.Body)
	if err != nil || len(bytes.TrimSpace(contents)) != 0 {
		return originResult{}, ErrInvalidResponse
	}
	result := originResult{
		status: response.StatusCode, action: response.Header.Get("X-Palisade-Action"), handling: response.Header.Get("X-Palisade-Handling"),
		mode: response.Header.Get("X-Palisade-Mode"), rolloutID: response.Header.Get("X-Palisade-Rollout-ID"),
		challengeID: response.Header.Get("X-Palisade-Challenge-ID"), location: response.Header.Get("Location"),
	}
	if !stableValue(response.Header.Get("X-Palisade-Decision-ID")) || !palisadecontract.ValidRuntimeMode(result.mode) ||
		(result.rolloutID != "" && !stableValue(result.rolloutID)) {
		return originResult{}, ErrInvalidResponse
	}
	if retry := response.Header.Get("Retry-After"); retry != "" {
		result.retryAfter, err = strconv.Atoi(retry)
		if err != nil || retry != strconv.Itoa(result.retryAfter) {
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
		validChallenge := result.handling == "challenge" && result.action == "challenge" && validChallengeID(result.challengeID) && result.location == "/v1/challenge/"+result.challengeID && result.retryAfter == 0
		validBlock := result.handling == "block" && result.action == "block" && result.retryAfter >= 1 && result.retryAfter <= 3600 && result.challengeID == "" && result.location == ""
		if result.mode == "shadow" || result.rolloutID == "" || (!validChallenge && !validBlock) {
			return originResult{}, ErrInvalidResponse
		}
	default:
		return originResult{}, apiStatusError{status: result.status, op: "origin check"}
	}
	return result, nil
}

func (p *Proxy) postJSON(ctx context.Context, apiPath string, payload any, cookie *http.Cookie, authorized bool, target any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint(apiPath), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	if authorized {
		request.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = readBounded(response.Body)
		return response.StatusCode, nil
	}
	if err := decodeBounded(response.Body, target); err != nil {
		return 0, ErrInvalidResponse
	}
	return response.StatusCode, nil
}

func sessionCookie(request *http.Request) (http.Cookie, bool, error) {
	cookie, err := request.Cookie(SessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return http.Cookie{}, false, nil
	}
	if err != nil || cookie.Value == "" || len(cookie.Value) > 4096 {
		return http.Cookie{}, false, ErrInvalidResponse
	}
	return *cookie, true, nil
}

func validBaseURL(value *url.URL) bool {
	if value == nil || (value.Scheme != "http" && value.Scheme != "https") || value.Host == "" || value.User != nil || value.Opaque != "" ||
		value.RawPath != "" || value.RawQuery != "" || value.Fragment != "" {
		return false
	}
	if value.Path != "" && value.Path != "/" && (path.Clean(value.Path) != value.Path || strings.HasSuffix(value.Path, "/")) {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	if strings.EqualFold(value.Hostname(), "localhost") {
		return true
	}
	address := net.ParseIP(value.Hostname())
	return address != nil && address.IsLoopback()
}

func validPrefix(value string) bool {
	return len(value) >= 2 && len(value) <= 64 && strings.HasPrefix(value, "/") && !strings.HasSuffix(value, "/") &&
		path.Clean(value) == value && !strings.ContainsAny(value, "?%#\\\r\n\x00")
}

func validClassification(value Classification) bool {
	return palisadecontract.ValidRequestAction(value.Action) && palisadecontract.ValidEndpointClass(value.EndpointClass) &&
		palisadecontract.ValidOptionalUnknownClass(value.EvaluationCohort, palisadecontract.ValidEvaluationCohort)
}

func validSignals(value Signals) bool {
	if value.BrowserEventCount < 0 || value.BrowserEventCount > 10_000 || value.HoneypotHits < 0 || value.HoneypotHits > 100 ||
		math.IsNaN(value.ExternalRiskScore) || math.IsInf(value.ExternalRiskScore, 0) || value.ExternalRiskScore < 0 || value.ExternalRiskScore > 1 ||
		!palisadecontract.ValidTransportProtocol(value.TransportProtocol) || !palisadecontract.ValidTransportSecurity(value.TransportSecurity) ||
		!palisadecontract.ValidClientAddressSource(value.ClientAddressSource) ||
		!palisadecontract.ValidOptionalUnknownClass(value.ChallengeVerdict, palisadecontract.ValidChallengeVerdict) ||
		!palisadecontract.ValidOptionalUnknownClass(value.CrawlerClass, palisadecontract.ValidCrawlerClass) ||
		!palisadecontract.ValidOptionalUnknownClass(value.CrawlerVerification, palisadecontract.ValidCrawlerVerification) ||
		!palisadecontract.ValidCrawlerIdentity(value.VerifiedBot, value.CrawlerClass, value.CrawlerVerification) {
		return false
	}
	return palisadecontract.ValidEdgeIntelligence(value.EdgeFingerprintClass, value.EdgeFingerprintMethod, value.NetworkReputation, value.NetworkType)
}

func normalizeTransport(request *http.Request) (protocol, security, addressSource string) {
	switch request.ProtoMajor {
	case 1:
		protocol = "http1"
	case 2:
		protocol = "http2"
	case 3:
		protocol = "http3"
	default:
		protocol = "unknown"
	}
	if request.TLS == nil {
		security = "plaintext"
	} else {
		security = "direct_tls"
	}
	addressSource = "unknown"
	if address, err := netip.ParseAddrPort(request.RemoteAddr); err == nil && address.Addr().Zone() == "" {
		addressSource = "direct"
	} else if address, err := netip.ParseAddr(request.RemoteAddr); err == nil && address.Zone() == "" {
		addressSource = "direct"
	}
	return protocol, security, addressSource
}

func stableValue(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validChallengeID(value string) bool { return len(value) == 32 && stableValue(value) }

func readBounded(reader io.Reader) ([]byte, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maxServiceBody+1))
	if err != nil || len(contents) > maxServiceBody {
		return nil, ErrInvalidResponse
	}
	return contents, nil
}

func decodeBounded(reader io.Reader, target any) error {
	contents, err := readBounded(reader)
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

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}` + "\n"))
}
