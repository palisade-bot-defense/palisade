package palisadehttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
)

type challengeMetadata struct {
	ChallengeID       string    `json:"challenge_id"`
	Family            string    `json:"family"`
	ReadyAt           time.Time `json:"ready_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	AttemptsRemaining int       `json:"attempts_remaining"`
	VerificationToken string    `json:"verification_token"`
	Accessibility     struct {
		NonVisual       bool `json:"non_visual"`
		KeyboardOnly    bool `json:"keyboard_only"`
		FallbackOffered bool `json:"fallback_offered"`
	} `json:"accessibility"`
}

type challengeVerification struct {
	ChallengeID     string    `json:"challenge_id"`
	RedemptionToken string    `json:"redemption_token"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type challengeVerifyRequest struct {
	ChallengeID       string `json:"challenge_id"`
	VerificationToken string `json:"verification_token"`
}

type challengeRedeemRequest struct {
	ChallengeID     string `json:"challenge_id"`
	RedemptionToken string `json:"redemption_token"`
	Action          string `json:"action"`
	EndpointClass   string `json:"endpoint_class"`
}

type challengeServiceRedeemRequest struct {
	ChallengeID       string `json:"challenge_id"`
	RedemptionToken   string `json:"redemption_token"`
	RedemptionBinding string `json:"redemption_binding"`
	Action            string `json:"action"`
	EndpointClass     string `json:"endpoint_class"`
}

type challengeFallbackRequest struct {
	ChallengeID string `json:"challenge_id"`
}

var challengePage = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Request verification</title>
  <script src="{{.Prefix}}/challenge.js" defer></script>
</head>
<body>
  <main id="palisade-challenge" data-prefix="{{.Prefix}}" data-challenge-id="{{.ChallengeID}}" data-action="{{.Action}}" data-endpoint-class="{{.EndpointClass}}" data-fallback-path="{{.FallbackPath}}">
    <h1>Verify this request</h1>
    <p>This short confirmation protects the service from abusive automation. It does not identify you.</p>
    <p id="palisade-status" role="status" aria-live="polite">Loading verification…</p>
    <button id="palisade-continue" type="button" disabled>Continue</button>
    <button id="palisade-fallback" type="button">Use another verification method</button>
    <noscript>This verification needs JavaScript. Use the site support or fallback path instead.</noscript>
  </main>
</body>
</html>
`))

const challengeScript = `(() => {
  "use strict";
  const root = document.getElementById("palisade-challenge");
  const status = document.getElementById("palisade-status");
  const proceed = document.getElementById("palisade-continue");
  const fallback = document.getElementById("palisade-fallback");
  if (!root || !status || !proceed || !fallback) return;
  const prefix = root.dataset.prefix;
  const challengeId = root.dataset.challengeId;
  const action = root.dataset.action;
  const endpointClass = root.dataset.endpointClass;
  const fallbackPath = root.dataset.fallbackPath;
  let verificationToken = "";
  let timer = 0;

  const jsonRequest = async (path, body) => fetch(prefix + path, {
    method: "POST",
    credentials: "same-origin",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  });

  const load = async () => {
    window.clearTimeout(timer);
    proceed.disabled = true;
    try {
      const response = await fetch(prefix + "/challenge/" + encodeURIComponent(challengeId), {credentials: "same-origin", cache: "no-store"});
      if (!response.ok) throw new Error("metadata");
      const metadata = await response.json();
      verificationToken = metadata.verification_token;
      const remaining = Math.max(0, Date.parse(metadata.ready_at) - Date.now());
      if (remaining > 0) {
        status.textContent = "Verification will be ready shortly.";
        timer = window.setTimeout(load, Math.min(remaining + 25, 30000));
        return;
      }
      status.textContent = "Verification is ready.";
      proceed.disabled = false;
      proceed.focus();
    } catch (_) {
      status.textContent = "Verification is unavailable. Try again or use the fallback.";
    }
  };

  proceed.addEventListener("click", async () => {
    proceed.disabled = true;
    status.textContent = "Verifying request…";
    try {
      const verified = await jsonRequest("/challenge/verify", {challenge_id: challengeId, verification_token: verificationToken});
      if (verified.status === 425) { await load(); return; }
      if (!verified.ok) throw new Error("verify");
      const capability = await verified.json();
      const redeemed = await jsonRequest("/challenge/redeem", {
        challenge_id: challengeId,
        redemption_token: capability.redemption_token,
        action: action,
        endpoint_class: endpointClass
      });
      if (!redeemed.ok) throw new Error("redeem");
      status.textContent = "Verification complete. Continuing…";
      window.location.reload();
    } catch (_) {
      status.textContent = "Verification failed. Try again or use the fallback.";
      proceed.disabled = false;
    }
  });

  fallback.addEventListener("click", async () => {
    fallback.disabled = true;
    try {
      const response = await jsonRequest("/challenge/fallback", {challenge_id: challengeId});
      if (!response.ok) throw new Error("fallback");
      if (fallbackPath) { window.location.assign(fallbackPath); return; }
      status.textContent = "Use the site's support channel for another verification method.";
    } catch (_) {
      status.textContent = "The fallback is unavailable. Contact site support.";
      fallback.disabled = false;
    }
  });

  load();
})();
`

func (m *Middleware) handleAdapterRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != m.prefix && !strings.HasPrefix(r.URL.Path, m.prefix+"/") {
		return false
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == m.prefix+"/challenge.js":
		writeChallengeSecurityHeaders(w)
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write([]byte(challengeScript))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, m.prefix+"/challenge/"):
		m.handleChallengeMetadata(w, r)
	case r.Method == http.MethodPost && r.URL.Path == m.prefix+"/challenge/verify":
		m.handleChallengeVerify(w, r)
	case r.Method == http.MethodPost && r.URL.Path == m.prefix+"/challenge/redeem":
		m.handleChallengeRedeem(w, r)
	case r.Method == http.MethodPost && r.URL.Path == m.prefix+"/challenge/fallback":
		m.handleChallengeFallback(w, r)
	default:
		writeAdapterError(w, http.StatusNotFound, "palisade_adapter_route_not_found")
	}
	return true
}

func (m *Middleware) handleChallengeMetadata(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, m.prefix+"/challenge/")
	if !validChallengeID(id) || strings.Contains(id, "/") {
		writeAdapterError(w, http.StatusNotFound, "challenge_not_found")
		return
	}
	cookie, ok := m.challengeCookie(w, r)
	if !ok {
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, m.endpoint("/v1/challenge/"+id), nil)
	if err != nil {
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
		return
	}
	request.AddCookie(&cookie)
	response, err := m.client.Do(request)
	if err != nil {
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = readBounded(response.Body, maxServiceBody)
		writeChallengeRelayError(w, response.StatusCode)
		return
	}
	var metadata challengeMetadata
	if decodeBounded(response.Body, &metadata) != nil || metadata.ChallengeID != id || !validChallengeMetadata(metadata, m.now().UTC()) {
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_invalid_response")
		return
	}
	writeLocalJSON(w, http.StatusOK, metadata)
}

func (m *Middleware) handleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	var payload challengeVerifyRequest
	if decodeClientJSON(w, r, &payload) != nil || !validChallengeID(payload.ChallengeID) || !stableToken(payload.VerificationToken, 43) {
		writeAdapterError(w, http.StatusBadRequest, "challenge_invalid")
		return
	}
	cookie, ok := m.challengeCookie(w, r)
	if !ok {
		return
	}
	var verification challengeVerification
	status, err := m.postJSON(r.Context(), "/v1/challenge/verify", payload, &cookie, false, &verification)
	if err != nil {
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
		return
	}
	if status != http.StatusOK {
		writeChallengeRelayError(w, status)
		return
	}
	now := m.now().UTC()
	if verification.ChallengeID != payload.ChallengeID || !stableToken(verification.RedemptionToken, 43) ||
		!verification.ExpiresAt.After(now) || verification.ExpiresAt.After(now.Add(time.Minute)) {
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_invalid_response")
		return
	}
	writeLocalJSON(w, http.StatusOK, verification)
}

func (m *Middleware) handleChallengeRedeem(w http.ResponseWriter, r *http.Request) {
	var payload challengeRedeemRequest
	if decodeClientJSON(w, r, &payload) != nil || !validChallengeID(payload.ChallengeID) || !stableToken(payload.RedemptionToken, 43) ||
		!validClassification(Classification{Action: payload.Action, EndpointClass: payload.EndpointClass}) {
		writeAdapterError(w, http.StatusBadRequest, "challenge_invalid")
		return
	}
	cookie, ok := m.challengeCookie(w, r)
	if !ok {
		return
	}
	pending, err := r.Cookie(PendingCookieName)
	if err != nil || pending.Value == "" || len(pending.Value) > 4096 {
		writeAdapterError(w, http.StatusConflict, "challenge_retry_not_bound")
		return
	}
	grant, redemptionBinding, err := m.state.reserveGrant(pending.Value, payload.ChallengeID, cookie.Value, payload.Action, payload.EndpointClass, m.now().UTC())
	if err != nil {
		if errors.Is(err, ErrInvalidPending) {
			writeAdapterError(w, http.StatusConflict, "challenge_retry_not_bound")
			return
		}
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
		return
	}
	servicePayload := challengeServiceRedeemRequest{
		ChallengeID: payload.ChallengeID, RedemptionToken: payload.RedemptionToken, RedemptionBinding: redemptionBinding,
		Action: payload.Action, EndpointClass: payload.EndpointClass,
	}
	status, err := m.postJSON(r.Context(), "/v1/challenge/redeem", servicePayload, &cookie, false, nil)
	if err != nil {
		m.state.releaseGrant(grant.Value, pending.Value)
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
		return
	}
	if status != http.StatusNoContent {
		m.state.releaseGrant(grant.Value, pending.Value)
		writeChallengeRelayError(w, status)
		return
	}
	m.state.commitPending(pending.Value)
	clearPendingCookie(w)
	http.SetCookie(w, &grant)
	w.Header().Set("X-Palisade-Challenge", "redeemed")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Middleware) handleChallengeFallback(w http.ResponseWriter, r *http.Request) {
	var payload challengeFallbackRequest
	if decodeClientJSON(w, r, &payload) != nil || !validChallengeID(payload.ChallengeID) {
		writeAdapterError(w, http.StatusBadRequest, "challenge_invalid")
		return
	}
	cookie, ok := m.challengeCookie(w, r)
	if !ok {
		return
	}
	status, err := m.postJSON(r.Context(), "/v1/challenge/fallback", payload, &cookie, false, nil)
	if err != nil {
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
		return
	}
	if status != http.StatusNoContent {
		writeChallengeRelayError(w, status)
		return
	}
	if pending, err := r.Cookie(PendingCookieName); err == nil && len(pending.Value) <= 4096 &&
		m.state.closePending(pending.Value, payload.ChallengeID, cookie.Value, m.now().UTC()) {
		clearPendingCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Middleware) challengeCookie(w http.ResponseWriter, r *http.Request) (http.Cookie, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 4096 {
		writeAdapterError(w, http.StatusUnauthorized, "invalid_session")
		return http.Cookie{}, false
	}
	return *cookie, true
}

func (m *Middleware) writeChallengePage(w http.ResponseWriter, r *http.Request, challengeID, sessionValue string, classification Classification, challengeBinding [32]byte) {
	var body bytes.Buffer
	if err := challengePage.Execute(&body, struct {
		Prefix, ChallengeID, Action, EndpointClass, FallbackPath string
	}{m.prefix, challengeID, classification.Action, classification.EndpointClass, m.fallbackPath}); err != nil {
		writeAdapterError(w, http.StatusInternalServerError, "palisade_challenge_page_failed")
		return
	}
	pending, err := m.state.issuePending(r, classification, challengeID, sessionValue, challengeBinding, m.now().UTC())
	if err != nil {
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
		return
	}
	writeChallengeSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Palisade-Action", "challenge")
	w.Header().Set("X-Palisade-Challenge-ID", challengeID)
	w.Header().Set("Location", m.prefix+"/challenge/"+challengeID)
	http.SetCookie(w, &pending)
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body.Bytes()); err != nil {
		m.state.revokePending(pending.Value)
	}
}

func writeChallengeSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func decodeClientJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidResponse
	}
	return nil
}

func validChallengeMetadata(metadata challengeMetadata, now time.Time) bool {
	return validChallengeID(metadata.ChallengeID) && metadata.Family == "timed_confirmation_v2" && metadata.ReadyAt.Before(metadata.ExpiresAt) &&
		metadata.ExpiresAt.After(now) && !metadata.ExpiresAt.After(now.Add(DefaultPendingTTL)) && metadata.AttemptsRemaining >= 0 && metadata.AttemptsRemaining <= 20 && stableToken(metadata.VerificationToken, 43) &&
		metadata.Accessibility.NonVisual && metadata.Accessibility.KeyboardOnly && metadata.Accessibility.FallbackOffered
}

func stableToken(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func writeChallengeRelayError(w http.ResponseWriter, status int) {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusGone,
		http.StatusTooEarly, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		writeAdapterError(w, status, "challenge_rejected")
	default:
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_invalid_response")
	}
}

func writeLocalJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
