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

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/internal/httpapi"
	"github.com/palisade-human-trust/palisade/internal/liveness"
	"github.com/palisade-human-trust/palisade/internal/token"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

const (
	address  = "127.0.0.1:8099"
	audience = "demo.local"
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

	server := httpapi.New(demoEngine{}, tokens, "demo-key", slog.New(slog.DiscardHandler)).
		WithAssurance(httpapi.AssuranceConfig{
			SigningKey:       private,
			BindingSecret:    []byte("demo-binding-secret-0123456789abc"),
			AllowedAudiences: []string{audience},
		}).
		WithLiveness(live)

	mux := http.NewServeMux()
	mux.Handle("/v1/", server.Handler())
	mux.HandleFunc("GET /{$}", page)
	// The demo page verifies the assertion itself, so it needs the public key.
	// A relying party gets exactly this and nothing more.
	mux.HandleFunc("GET /public-key", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"public_key_hex": fmt.Sprintf("%x", public),
			"key_id":         palisadeassurance.KeyID(public),
			"audience":       audience,
		})
	})

	fmt.Printf("PALISADE liveness demo on http://%s\n", address)
	fmt.Println("Open it, answer the rounds, and watch the assertion change.")
	fmt.Println("Ctrl-C to stop. Everything is synthetic and loopback-only.")
	return (&http.Server{
		Addr: address, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second,
	}).ListenAndServe()
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(demoPage))
}
