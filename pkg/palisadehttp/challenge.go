package palisadehttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
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
  <link rel="stylesheet" href="{{.Prefix}}/challenge.css">
  <script src="{{.Prefix}}/challenge.js" defer></script>
</head>
<body>
  <main id="palisade-challenge" aria-labelledby="palisade-title" aria-describedby="palisade-description" data-prefix="{{.Prefix}}" data-challenge-id="{{.ChallengeID}}" data-action="{{.Action}}" data-endpoint-class="{{.EndpointClass}}" data-fallback-path="{{.FallbackPath}}">
    <section class="challenge-shell">
      <p class="eyebrow">Request protection</p>
      <h1 id="palisade-title">Verify this request</h1>
      <p id="palisade-description">This short confirmation protects the service from abusive automation. It does not identify you.</p>
      <p id="palisade-status" class="status" role="status" aria-live="polite" aria-atomic="true">Loading verification…</p>
      <div class="actions">
        <button id="palisade-continue" class="primary" type="button" aria-describedby="palisade-status" disabled>Continue</button>
        <form id="palisade-fallback-form" method="post" action="{{.Prefix}}/challenge/fallback" autocomplete="off">
          <input type="hidden" name="challenge_id" value="{{.ChallengeID}}">
          <button id="palisade-fallback" class="secondary" type="submit">Use another verification method</button>
        </form>
      </div>
      <noscript><p class="notice" role="note">JavaScript verification is unavailable. The alternative verification button above works without JavaScript.</p></noscript>
    </section>
  </main>
</body>
</html>
`))

var fallbackResultPage = template.Must(template.New("fallback-result").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{.Title}}</title>
  <link rel="stylesheet" href="{{.Prefix}}/challenge.css">
</head>
<body>
  <main aria-labelledby="palisade-result-title">
    <section class="challenge-shell">
      <p class="eyebrow">Request protection</p>
      <h1 id="palisade-result-title">{{.Title}}</h1>
      <p class="status" role="status">{{.Message}}</p>
    </section>
  </main>
</body>
</html>
`))

const challengeStyles = `:root {
  color-scheme: light dark;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 100%;
  line-height: 1.5;
}
* { box-sizing: border-box; }
body {
  min-height: 100vh;
  margin: 0;
  display: grid;
  place-items: center;
  background: #f3f6fb;
  color: #172033;
}
main { width: 100%; padding: 1rem; }
.challenge-shell {
  width: min(100%, 42rem);
  margin: 0 auto;
  padding: clamp(1.5rem, 5vw, 3rem);
  border: 1px solid #b8c3d6;
  border-radius: 1rem;
  background: #ffffff;
  box-shadow: 0 1rem 3rem rgba(27, 43, 72, 0.12);
}
.eyebrow {
  margin: 0 0 0.5rem;
  color: #36547d;
  font-size: 0.875rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
h1 { margin: 0 0 1rem; font-size: clamp(1.75rem, 5vw, 2.5rem); line-height: 1.15; }
p { max-width: 65ch; }
.status {
  margin: 1.5rem 0;
  padding: 1rem;
  border-left: 0.3rem solid #245a9b;
  background: #eaf2fc;
  color: #132c4d;
  font-weight: 600;
}
.actions { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: stretch; }
.actions form { display: flex; margin: 0; }
button {
  min-width: 10rem;
  min-height: 2.75rem;
  padding: 0.7rem 1rem;
  border: 2px solid transparent;
  border-radius: 0.55rem;
  font: inherit;
  font-weight: 700;
  cursor: pointer;
}
button.primary { background: #174f91; color: #ffffff; }
button.secondary { border-color: #415a77; background: #ffffff; color: #223a57; }
button:disabled { cursor: not-allowed; opacity: 0.6; }
button:focus-visible {
  outline: 3px solid #b94d00;
  outline-offset: 3px;
}
.notice { margin: 1.25rem 0 0; padding-top: 1rem; border-top: 1px solid #b8c3d6; }
@media (max-width: 32rem) {
  .actions, .actions form, button { width: 100%; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    scroll-behavior: auto !important;
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
@media (prefers-color-scheme: dark) {
  body { background: #101722; color: #f5f7fb; }
  .challenge-shell { border-color: #66758b; background: #182231; box-shadow: none; }
  .eyebrow { color: #b9d4fb; }
  .status { border-left-color: #8fc0ff; background: #233852; color: #ffffff; }
  button.primary { background: #9ac7ff; color: #08182b; }
  button.secondary { border-color: #c5d5e9; background: #182231; color: #ffffff; }
  button:focus-visible { outline-color: #ffd08a; }
  .notice { border-top-color: #66758b; }
}
@media (forced-colors: active) {
  .challenge-shell, .status, button { border: 2px solid CanvasText; }
  button:focus-visible { outline: 3px solid Highlight; }
}
`

const challengeScript = `(() => {
  "use strict";
  const root = document.getElementById("palisade-challenge");
  const status = document.getElementById("palisade-status");
  const proceed = document.getElementById("palisade-continue");
  const fallbackForm = document.getElementById("palisade-fallback-form");
  const fallback = document.getElementById("palisade-fallback");
  if (!root || !status || !proceed || !fallbackForm || !fallback) return;
  const prefix = root.dataset.prefix;
  const challengeId = root.dataset.challengeId;
  const action = root.dataset.action;
  const endpointClass = root.dataset.endpointClass;
  const fallbackPath = root.dataset.fallbackPath;
  let verificationToken = "";
  let timer = 0;
  root.setAttribute("aria-busy", "true");

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
      root.setAttribute("aria-busy", "false");
    } catch (_) {
      status.textContent = "Verification is unavailable. Try again or use the fallback.";
      root.setAttribute("aria-busy", "false");
    }
  };

  proceed.addEventListener("click", async () => {
    proceed.disabled = true;
    root.setAttribute("aria-busy", "true");
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
      root.setAttribute("aria-busy", "false");
      window.location.reload();
    } catch (_) {
      status.textContent = "Verification failed. Try again or use the fallback.";
      root.setAttribute("aria-busy", "false");
      proceed.disabled = false;
    }
  });

  fallbackForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    fallback.disabled = true;
    root.setAttribute("aria-busy", "true");
    status.textContent = "Requesting another verification method…";
    try {
      const response = await jsonRequest("/challenge/fallback", {challenge_id: challengeId});
      if (!response.ok) throw new Error("fallback");
      if (fallbackPath) { window.location.assign(fallbackPath); return; }
      status.textContent = "Use the site's support channel for another verification method.";
      root.setAttribute("aria-busy", "false");
    } catch (_) {
      status.textContent = "The fallback is unavailable. Contact site support.";
      root.setAttribute("aria-busy", "false");
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
	case r.Method == http.MethodGet && r.URL.Path == m.prefix+"/challenge.css":
		writeChallengeSecurityHeaders(w)
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write([]byte(challengeStyles))
	case r.Method == http.MethodGet && r.URL.Path == m.prefix+"/challenge.js":
		writeChallengeSecurityHeaders(w)
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write([]byte(challengeScript))
	case r.Method == http.MethodGet && r.URL.Path == m.prefix+"/challenge/fallback":
		m.writeFallbackResult(w, http.StatusOK, "Alternative verification requested", "Your choice was recorded. Continue with the site's support or account-verification process.")
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
	payload, formRequest, err := decodeChallengeFallback(w, r)
	if err != nil || !validChallengeID(payload.ChallengeID) {
		if formRequest {
			m.writeFallbackResult(w, http.StatusBadRequest, "Alternative verification unavailable", "The request was invalid. Return to the protected page and try again.")
			return
		}
		writeAdapterError(w, http.StatusBadRequest, "challenge_invalid")
		return
	}
	cookie, cookieErr := r.Cookie(SessionCookieName)
	if cookieErr != nil || cookie.Value == "" || len(cookie.Value) > 4096 {
		if formRequest {
			m.writeFallbackResult(w, http.StatusUnauthorized, "Verification session unavailable", "Return to the protected page to start a new verification session.")
			return
		}
		writeAdapterError(w, http.StatusUnauthorized, "invalid_session")
		return
	}
	status, err := m.postJSON(r.Context(), "/v1/challenge/fallback", payload, cookie, false, nil)
	if err != nil {
		if formRequest {
			m.writeFallbackResult(w, http.StatusServiceUnavailable, "Alternative verification unavailable", "The verification service is unavailable. Try again later.")
			return
		}
		writeAdapterError(w, http.StatusServiceUnavailable, "palisade_unavailable")
		return
	}
	if status != http.StatusNoContent {
		if formRequest {
			m.writeFallbackResult(w, safeChallengeRelayStatus(status), "Alternative verification unavailable", "The verification request could not be completed. Return to the protected page and try again.")
			return
		}
		writeChallengeRelayError(w, status)
		return
	}
	if pending, err := r.Cookie(PendingCookieName); err == nil && len(pending.Value) <= 4096 &&
		m.state.closePending(pending.Value, payload.ChallengeID, cookie.Value, m.now().UTC()) {
		clearPendingCookie(w)
	}
	if !formRequest {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeChallengeSecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	if m.fallbackPath != "" {
		http.Redirect(w, r, m.fallbackPath, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, m.prefix+"/challenge/fallback", http.StatusSeeOther)
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
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

func decodeChallengeFallback(w http.ResponseWriter, r *http.Request) (challengeFallbackRequest, bool, error) {
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil && r.Header.Get("Content-Type") != "" {
		return challengeFallbackRequest{}, false, mediaErr
	}
	if mediaType == "" || mediaType == "application/json" {
		var payload challengeFallbackRequest
		err := decodeClientJSON(w, r, &payload)
		return payload, false, err
	}
	if mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return challengeFallbackRequest{}, mediaType == "application/x-www-form-urlencoded", ErrInvalidResponse
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return challengeFallbackRequest{}, true, err
	}
	values, err := url.ParseQuery(string(body))
	challengeIDs := values["challenge_id"]
	if err != nil || len(values) != 1 || len(challengeIDs) != 1 {
		return challengeFallbackRequest{}, true, ErrInvalidResponse
	}
	return challengeFallbackRequest{ChallengeID: challengeIDs[0]}, true, nil
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
	writeAdapterError(w, safeChallengeRelayStatus(status), "challenge_rejected")
}

func safeChallengeRelayStatus(status int) int {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusGone,
		http.StatusTooEarly, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return status
	default:
		return http.StatusServiceUnavailable
	}
}

func (m *Middleware) writeFallbackResult(w http.ResponseWriter, status int, title, message string) {
	var body bytes.Buffer
	if err := fallbackResultPage.Execute(&body, struct{ Prefix, Title, Message string }{m.prefix, title, message}); err != nil {
		writeAdapterError(w, http.StatusInternalServerError, "palisade_challenge_page_failed")
		return
	}
	writeChallengeSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

func writeLocalJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
