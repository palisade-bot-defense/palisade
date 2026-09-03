// Command human-liveness-demo runs the assurance surface on loopback so a
// person can walk the interactive liveness challenge themselves and see the
// assertion it produces.
//
// This is a functional check, not a measurement. One person completing the
// challenge shows the path works end to end with a real human in it, which no
// automated test can show: every existing test drives the service with code.
// It produces no confirmed-human false-positive interval — that needs a
// representative cohort, and one person is not one.
//
// Everything is synthetic and loopback-only. No key here is a deployment key.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"encoding/base64"
	"sync"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/deviceattest"
	"github.com/palisade-human-trust/palisade/internal/httpapi"
	"github.com/palisade-human-trust/palisade/internal/liveness"
	"github.com/palisade-human-trust/palisade/internal/token"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

const (
	address      = "localhost:8099"
	origin       = "http://localhost:8099"
	relyingParty = "localhost"
	audience     = "demo.local"
)

// demoEngine returns a decision carrying the one evidence code that raises a
// level today: a browser sequence PALISADE verified against its own event
// store. The demo asserts it directly so the liveness path is what is being
// exercised, not the sensor.
type demoEngine struct{}

func (demoEngine) Decide(context.Context, core.DecisionRequest) (core.Decision, error) {
	return core.Decision{
		DecisionID: "demo",
		Action:     core.ActionAllow,
		Evidence: []core.Evidence{{
			Code: "BROWSER_SEQUENCE_PRESENT", Detector: "demo",
			Dimension: core.DimensionContinuity, Direction: core.DirectionBenign,
			Strength: .24, Confidence: .64,
		}},
		PolicyVersion: "demo-v1", ModelVersion: "demo-v1",
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}, nil
}

// demoRegistry stands in for the store a deployment's own registration ceremony
// writes to. PALISADE registers nothing itself; this exists so the demo has
// something to read. It keeps credentials in memory only.
type demoRegistry struct {
	mu          sync.Mutex
	credentials map[string]deviceattest.Credential
}

func (r *demoRegistry) Credential(credentialID, _ string) (deviceattest.Credential, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	credential, registered := r.credentials[credentialID]
	return credential, registered
}

func (r *demoRegistry) RecordSignCount(credentialID string, signCount uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	credential, registered := r.credentials[credentialID]
	if !registered {
		return
	}
	// Say out loud whether clone detection is running. A ceremony that succeeds
	// with a counter of zero looks identical to one protected by a counter, and
	// an operator who cannot tell them apart will credit a check that never
	// executed. Platform authenticators behind synced passkeys report zero.
	if signCount == 0 && credential.SignCount == 0 {
		fmt.Printf("  signature counter: none — clone detection is inert for this credential\n")
	} else {
		fmt.Printf("  signature counter: %d -> %d\n", credential.SignCount, signCount)
	}
	credential.SignCount = signCount
	r.credentials[credentialID] = credential
}

// register accepts a public key the browser just created. A real deployment
// runs its own registration ceremony here and applies whatever
// attestation-statement policy it wants; this one accepts what it is given and
// says so, because the demo is exercising verification, not enrolment.
func (r *demoRegistry) register(w http.ResponseWriter, request *http.Request) {
	var body struct {
		CredentialID string `json:"credential_id"`
		PublicKey    string `json:"public_key"`
		Algorithm    string `json:"algorithm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, request.Body, 8<<10)).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
	if err != nil || body.CredentialID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	algorithm := deviceattest.ES256
	if body.Algorithm == "eddsa" {
		algorithm = deviceattest.EdDSA
	}
	r.mu.Lock()
	r.credentials[body.CredentialID] = deviceattest.Credential{
		ID: body.CredentialID, Algorithm: algorithm, PublicKey: raw,
	}
	r.mu.Unlock()
	fmt.Printf("  device credential registered (%s)\n", algorithm)
	writeJSON(w, map[string]string{"status": "registered"})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func run() error {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	tokens, err := token.NewService([]byte("demo-proof-secret-0123456789abcdef"), token.NewMemoryNonceStore())
	if err != nil {
		return err
	}
	live, err := liveness.New(liveness.Config{Secret: []byte("demo-liveness-secret-0123456789ab")})
	if err != nil {
		return err
	}

	registry := &demoRegistry{credentials: map[string]deviceattest.Credential{}}
	devices, err := deviceattest.NewService(deviceattest.Config{
		Secret:   []byte("demo-device-secret-0123456789abcd"),
		Registry: registry,
		Policy:   deviceattest.Policy{RelyingPartyID: relyingParty, Origin: origin},
	})
	if err != nil {
		return err
	}

	server := httpapi.New(demoEngine{}, tokens, "demo-key", slog.New(slog.DiscardHandler)).
		WithAssurance(httpapi.AssuranceConfig{
			SigningKey:       private,
			BindingSecret:    []byte("demo-binding-secret-0123456789abc"),
			AllowedAudiences: []string{audience},
		}).
		WithLiveness(live).
		WithDeviceAttestation(devices)

	// A demo that shows nothing cannot confirm anything. This records the shape
	// of each attempt — never a session identifier, an option or an answer, so
	// watching the log tells an operator that a run happened and how it ended,
	// and nothing about who made it.
	surface := server.Handler()
	mux := http.NewServeMux()
	mux.Handle("/v1/", observe(surface))
	mux.HandleFunc("GET /{$}", page)
	// The demo page verifies the assertion itself, so it needs the public key.
	// A relying party gets exactly this and nothing more.
	mux.HandleFunc("POST /demo/register", registry.register)
	mux.HandleFunc("GET /public-key", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"public_key_hex": fmt.Sprintf("%x", public),
			"key_id":         palisadeassurance.KeyID(public),
			"audience":       audience,
		})
	})

	// Append rather than truncate, and stamp each run. A restart during someone
	// else's session used to erase what they had just done, which is the one
	// thing an observation log must not do.
	fmt.Printf("=== run started %s ===\n", time.Now().Format(time.RFC3339))
	fmt.Printf("PALISADE liveness demo on http://%s\n", address)
	fmt.Println("Open it, answer the rounds, and watch the assertion change.")
	fmt.Println("Ctrl-C to stop. Everything is synthetic and loopback-only.")
	return (&http.Server{
		Addr: address, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second,
	}).ListenAndServe()
}

// recorder captures the status so the observer can report an outcome without
// reading or retaining the body.
type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// observe reports the shape of each attempt. It deliberately prints no
// duration: the only interval this layer can measure is its own handler time,
// which is sub-millisecond and says nothing about how long a person took. An
// operator reading "0s" next to a human answer would draw the wrong conclusion,
// and the interval that matters — reveal to response — is enforced inside the
// service, not observable here.
func observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		switch {
		case r.URL.Path == "/v1/assurance/liveness" && wrapped.status == http.StatusOK:
			fmt.Printf("  liveness attempt opened\n")
		case r.URL.Path == "/v1/assurance/liveness/answer" && wrapped.status == http.StatusOK:
			fmt.Printf("  round answered\n")
		case r.URL.Path == "/v1/assurance/liveness/answer":
			fmt.Printf("  attempt ended — wrong option, faster than the floor, or past the deadline\n")
		case r.URL.Path == "/v1/assurance/device/challenge" && wrapped.status == http.StatusOK:
			fmt.Printf("  device challenge issued\n")
		case r.URL.Path == "/v1/assurance/device/complete" && wrapped.status == http.StatusOK:
			fmt.Printf("  device ceremony completed\n")
		case r.URL.Path == "/v1/assurance/device/complete":
			fmt.Printf("  device ceremony failed — the server does not say which constraint\n")
		case r.URL.Path == "/v1/assurance/content" && wrapped.status == http.StatusOK:
			fmt.Printf("  content assertion minted\n")
		case r.URL.Path == "/v1/assurance/channel" && wrapped.status == http.StatusOK:
			fmt.Printf("  channel assertion minted\n")
		case r.URL.Path == "/v1/assurance" && wrapped.status == http.StatusOK:
			fmt.Printf("  assertion minted\n")
		}
	})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(demoPage))
}
