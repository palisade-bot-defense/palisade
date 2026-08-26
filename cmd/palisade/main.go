package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/detector"
	decisionengine "github.com/palisade-bot-defense/palisade/internal/engine"
	"github.com/palisade-bot-defense/palisade/internal/events"
	"github.com/palisade-bot-defense/palisade/internal/httpapi"
	"github.com/palisade-bot-defense/palisade/internal/policy"
	"github.com/palisade-bot-defense/palisade/internal/replay"
	"github.com/palisade-bot-defense/palisade/internal/session"
	"github.com/palisade-bot-defense/palisade/internal/token"
)

var version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: palisade <serve|doctor|replay|version>")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "doctor":
		return doctor()
	case "replay":
		return runReplay(args[1:])
	case "version":
		fmt.Printf("palisade %s go=%s os=%s arch=%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dev := flags.Bool("dev", false, "allow ephemeral local secrets and proof-free decisions")
	if err := flags.Parse(args); err != nil {
		return err
	}
	secret, apiKey, err := secrets(*dev)
	if err != nil {
		return err
	}
	engine, tokenService, err := buildEngine(secret, !*dev)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	eventStore := events.NewStore(5 * time.Minute)
	api := httpapi.New(engine, tokenService, apiKey, logger).WithEventStore(eventStore).RequireEventProof(!*dev)
	server := &http.Server{
		Addr:              *listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Info("PALISADE starting", "version", version, "listen", *listen, "dev", *dev)
	if *dev {
		logger.Warn("development mode active; proof tokens are not required")
	}
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func doctor() error {
	_, keyPresent := os.LookupEnv("PALISADE_HMAC_KEY")
	_, apiKeyPresent := os.LookupEnv("PALISADE_API_KEY")
	fmt.Printf("PALISADE doctor\nversion: %s\ngo: %s\nhmac_key: %t\napi_key: %t\n", version, runtime.Version(), keyPresent, apiKeyPresent)
	if !keyPresent || !apiKeyPresent {
		return errors.New("production secrets are missing; use serve --dev only for local development")
	}
	return nil
}

func runReplay(args []string) error {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	filePath := flags.String("file", "examples/replay/synthetic.jsonl", "JSONL replay file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	file, err := os.Open(*filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	engine, _, err := buildEngine(secret, false)
	if err != nil {
		return err
	}
	return replay.Run(context.Background(), file, os.Stdout, engine)
}

func buildEngine(secret []byte, requireProof bool) (*decisionengine.Engine, *token.Service, error) {
	tokenService, err := token.NewService(secret, token.NewMemoryNonceStore())
	if err != nil {
		return nil, nil, err
	}
	policyEngine, err := policy.NewDefault()
	if err != nil {
		return nil, nil, err
	}
	registry := detector.NewRegistry(detector.ProtocolConsistency{}, detector.SequenceVelocity{}, detector.ExternalVerdicts{})
	sessionStore := session.NewMemoryStore(5*time.Minute, 100_000)
	return decisionengine.New(sessionStore, registry, policyEngine, tokenService, requireProof), tokenService, nil
}

func secrets(dev bool) ([]byte, string, error) {
	encoded := os.Getenv("PALISADE_HMAC_KEY")
	apiKey := os.Getenv("PALISADE_API_KEY")
	if encoded != "" && apiKey != "" {
		secret, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(secret) < 32 {
			return nil, "", errors.New("PALISADE_HMAC_KEY must be base64url without padding and decode to at least 32 bytes")
		}
		return secret, apiKey, nil
	}
	if !dev {
		return nil, "", errors.New("PALISADE_HMAC_KEY and PALISADE_API_KEY are required outside development mode")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", err
	}
	return secret, "development-only", nil
}
