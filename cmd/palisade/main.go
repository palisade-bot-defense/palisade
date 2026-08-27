package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

	"github.com/palisade-bot-defense/palisade/internal/challenge"
	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/detector"
	decisionengine "github.com/palisade-bot-defense/palisade/internal/engine"
	"github.com/palisade-bot-defense/palisade/internal/events"
	"github.com/palisade-bot-defense/palisade/internal/httpapi"
	"github.com/palisade-bot-defense/palisade/internal/offlineimport"
	"github.com/palisade-bot-defense/palisade/internal/policy"
	"github.com/palisade-bot-defense/palisade/internal/replay"
	"github.com/palisade-bot-defense/palisade/internal/rollout"
	"github.com/palisade-bot-defense/palisade/internal/session"
	"github.com/palisade-bot-defense/palisade/internal/sessioncookie"
	"github.com/palisade-bot-defense/palisade/internal/shadowanalysis"
	"github.com/palisade-bot-defense/palisade/internal/shadowlog"
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
		return errors.New("usage: palisade <serve|doctor|replay|import-offline|verify-shadow-log|analyze-shadow-log|rollout-keygen|prepare-rollout|verify-rollout|version>")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "doctor":
		return doctor()
	case "replay":
		return runReplay(args[1:])
	case "import-offline":
		return runOfflineImport(args[1:])
	case "verify-shadow-log":
		return verifyShadowLog(args[1:])
	case "analyze-shadow-log":
		return analyzeShadowLog(args[1:])
	case "rollout-keygen":
		return rolloutKeygen(args[1:])
	case "prepare-rollout":
		return prepareRollout(args[1:])
	case "verify-rollout":
		return verifyRollout(args[1:])
	case "version":
		fmt.Printf("palisade %s go=%s os=%s arch=%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func analyzeShadowLog(args []string) error {
	flags := flag.NewFlagSet("analyze-shadow-log", flag.ContinueOnError)
	directory := flags.String("dir", "", "private shadow log directory outside every Git worktree")
	keyFile := flags.String("key-file", "", "owner-only shadow log encryption key file")
	maxFiles := flags.Uint64("max-files", shadowlog.DefaultScanMaxFiles, "hard managed-file scan budget")
	maxRecords := flags.Uint64("max-records", shadowlog.DefaultScanMaxRecords, "hard decrypted-record scan budget")
	maxEncryptedBytes := flags.Int64("max-encrypted-bytes", shadowlog.DefaultScanMaxEncryptedBytes, "hard encrypted input byte budget")
	outputPath := flags.String("output", "", "new owner-only aggregate report outside every Git worktree; defaults to stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *directory == "" || *keyFile == "" {
		return errors.New("analyze-shadow-log requires --dir and --key-file and accepts no positional arguments")
	}
	report, err := shadowanalysis.AnalyzeDirectory(*directory, *keyFile, shadowanalysis.Config{ScanLimits: shadowlog.ScanLimits{
		MaxFiles: *maxFiles, MaxRecords: *maxRecords, MaxEncryptedBytes: *maxEncryptedBytes,
	}})
	if err != nil {
		return err
	}
	if *outputPath != "" {
		if err := rollout.WriteAnalysisReport(*outputPath, report); err != nil {
			return err
		}
		fmt.Println("shadow analysis report written")
		return nil
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func verifyShadowLog(args []string) error {
	flags := flag.NewFlagSet("verify-shadow-log", flag.ContinueOnError)
	directory := flags.String("dir", "", "private shadow log directory outside every Git worktree")
	keyFile := flags.String("key-file", "", "owner-only shadow log encryption key file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *directory == "" || *keyFile == "" {
		return errors.New("verify-shadow-log requires --dir and --key-file and accepts no positional arguments")
	}
	verified, err := shadowlog.VerifyDirectory(*directory, *keyFile)
	if err != nil {
		return err
	}
	fmt.Printf("shadow log verified: files=%d records=%d decisions=%d outcomes=%d first=%s last=%s\n", verified.Files, verified.Records, verified.Decisions, verified.Outcomes, verified.FirstAt, verified.LastAt)
	return nil
}

func runOfflineImport(args []string) error {
	flags := flag.NewFlagSet("import-offline", flag.ContinueOnError)
	inputDir := flags.String("input-dir", "", "directory containing the exact offline Shield export files")
	outputDir := flags.String("output-dir", "", "new output directory outside every Git worktree")
	keyFile := flags.String("pseudonym-key-file", "", "0600 file containing at least 32 bytes")
	datasetID := flags.String("dataset-id", "", "non-secret stable identifier for this source dataset")
	pilotID := flags.String("pilot-id", "", "non-secret stable identifier for this deployment or pilot")
	provenance := flags.String("provenance", offlineimport.ProvenanceOffline, "input provenance (offline_export only)")
	anubisPeerSource := flags.String("anubis-peer-source", offlineimport.AnubisPeerDirect, "Anubis peer field: direct_peer_only or trusted_x_real_ip")
	shardSize := flags.Int("shard-size", offlineimport.DefaultShardSize, "normalized events per shard")
	maxLineBytes := flags.Int("max-line-bytes", offlineimport.DefaultMaxLineSize, "maximum decompressed line size")
	sortChunkSize := flags.Int("sort-chunk-size", offlineimport.DefaultSortChunkSize, "events retained in memory per external-sort run")
	maxDecompressedBytes := flags.Int64("max-decompressed-bytes", offlineimport.DefaultMaxDecompressedBytes, "hard total decompressed input byte budget")
	maxInputRecords := flags.Uint64("max-input-records", offlineimport.DefaultMaxInputRecords, "hard total input record budget")
	maxEvents := flags.Uint64("max-events", offlineimport.DefaultMaxEvents, "hard normalized event budget")
	maxShards := flags.Int("max-shards", offlineimport.DefaultMaxShards, "hard output shard budget")
	maxOutputBytes := flags.Int64("max-output-bytes", offlineimport.DefaultMaxOutputBytes, "hard final output byte budget")
	maxWorkingBytes := flags.Int64("max-working-bytes", offlineimport.DefaultMaxWorkingBytes, "hard temporary sort byte budget")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("import-offline does not accept positional arguments")
	}
	result, err := offlineimport.Run(offlineimport.Config{
		InputDir:             *inputDir,
		OutputDir:            *outputDir,
		PseudonymKeyFile:     *keyFile,
		DatasetID:            *datasetID,
		PilotID:              *pilotID,
		Provenance:           *provenance,
		AnubisPeerSource:     *anubisPeerSource,
		ShardSize:            *shardSize,
		MaxLineBytes:         *maxLineBytes,
		SortChunkSize:        *sortChunkSize,
		MaxDecompressedBytes: *maxDecompressedBytes,
		MaxInputRecords:      *maxInputRecords,
		MaxEvents:            *maxEvents,
		MaxShards:            *maxShards,
		MaxOutputBytes:       *maxOutputBytes,
		MaxWorkingBytes:      *maxWorkingBytes,
	})
	if err != nil {
		return err
	}
	fmt.Printf("offline import complete: events=%d invalid=%d skipped=%d\nmanifest: %s\n", result.Events, result.Invalid, result.Skipped, result.ManifestPath)
	return nil
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dev := flags.Bool("dev", false, "allow ephemeral local secrets and proof-free decisions")
	modeName := flags.String("mode", string(core.RuntimeModeShadow), "runtime mode: serve requires shadow; signed plans enable canary/enforce")
	rolloutPlanPath := flags.String("rollout-plan", "", "owner-only signed rollout plan outside every Git worktree")
	rolloutPublicKeyPath := flags.String("rollout-public-key", "", "owner-only rollout verification public key outside every Git worktree")
	requireSessionCookie := flags.Bool("require-session-cookie", false, "require a valid server-issued session cookie on token, event and decision requests")
	shadowLogDir := flags.String("shadow-log-dir", "", "private encrypted append-only shadow log directory")
	shadowLogKeyFile := flags.String("shadow-log-key-file", "", "owner-only file containing 32-4096 encryption key bytes")
	shadowLogMaxBytes := flags.Int64("shadow-log-max-bytes", shadowlog.DefaultMaxFileBytes, "rotate shadow logs after this many encrypted bytes")
	shadowLogMaxAge := flags.Duration("shadow-log-max-age", shadowlog.DefaultMaxFileAge, "rotate shadow logs after this duration")
	shadowLogRetention := flags.Duration("shadow-log-retention", shadowlog.DefaultRetention, "delete managed shadow logs older than this duration")
	shadowLogQueue := flags.Int("shadow-log-queue", shadowlog.DefaultQueueSize, "bounded asynchronous shadow record queue")
	if err := flags.Parse(args); err != nil {
		return err
	}
	mode, err := parseRuntimeMode(*modeName)
	if err != nil {
		return err
	}
	if mode != core.RuntimeModeShadow {
		return errors.New("serve enforcement requires a signed rollout plan; --mode enforce is supported only by deterministic replay")
	}
	if (*rolloutPlanPath == "") != (*rolloutPublicKeyPath == "") {
		return errors.New("--rollout-plan and --rollout-public-key must be configured together")
	}
	if (*shadowLogDir == "") != (*shadowLogKeyFile == "") {
		return errors.New("--shadow-log-dir and --shadow-log-key-file must be configured together")
	}
	if *dev && (*rolloutPlanPath != "" || *rolloutPublicKeyPath != "") {
		return errors.New("signed rollout plans require stable production secrets and cannot run with --dev")
	}
	if *rolloutPlanPath != "" && !*requireSessionCookie {
		return errors.New("signed rollout plans require --require-session-cookie for stable cohort binding")
	}
	if *rolloutPlanPath != "" && *shadowLogDir == "" {
		return errors.New("signed rollout plans require the encrypted shadow log for measurement and rollback evidence")
	}
	secret, apiKey, err := secrets(*dev)
	if err != nil {
		return err
	}
	rolloutController, err := loadRollout(*rolloutPlanPath, *rolloutPublicKeyPath, secret, time.Now().UTC())
	if err != nil {
		return err
	}
	var engineOptions []decisionengine.Option
	if rolloutController != nil {
		engineOptions = append(engineOptions, decisionengine.WithRollout(rolloutController))
		mode = rolloutController.Plan().Stage
	}
	engine, tokenService, err := buildEngine(secret, !*dev, core.RuntimeModeShadow, engineOptions...)
	if err != nil {
		return err
	}
	sessionCookies, err := sessioncookie.New(secret, sessioncookie.DefaultTTL)
	if err != nil {
		return err
	}
	challengeService, err := challenge.New(challenge.Config{Secret: secret})
	if err != nil {
		return err
	}
	var shadowSink *shadowlog.Sink
	if *shadowLogDir != "" {
		shadowSink, err = shadowlog.New(shadowlog.Config{
			Directory: *shadowLogDir, KeyFile: *shadowLogKeyFile, MaxFileBytes: *shadowLogMaxBytes,
			MaxFileAge: *shadowLogMaxAge, Retention: *shadowLogRetention, QueueSize: *shadowLogQueue,
		})
		if err != nil {
			return err
		}
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	eventStore := events.NewStore(5 * time.Minute)
	api := httpapi.New(engine, tokenService, apiKey, logger).
		WithEventStore(eventStore).
		RequireEventProof(!*dev).
		WithSessionCookies(sessionCookies, *requireSessionCookie).
		WithChallenges(challengeService)
	if shadowSink != nil {
		api.WithShadowRecorder(shadowSink)
	}
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
	challengeSweeperDone := make(chan struct{})
	go func() {
		defer close(challengeSweeperDone)
		challengeService.RunSweeper(ctx, time.Minute)
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	rolloutID := ""
	if rolloutController != nil {
		rolloutID = rolloutController.Plan().RolloutID
	}
	logger.Info("PALISADE starting", "version", version, "listen", *listen, "dev", *dev, "mode", mode, "rollout_id", rolloutID, "require_session_cookie", *requireSessionCookie, "shadow_log", shadowSink != nil)
	if *dev {
		logger.Warn("development mode active; proof tokens are not required")
	}
	err = server.ListenAndServe()
	stop()
	<-challengeSweeperDone
	var shadowCloseErr error
	if shadowSink != nil {
		shadowCloseErr = shadowSink.Close()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return shadowCloseErr
	}
	return errors.Join(err, shadowCloseErr)
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
	modeName := flags.String("mode", string(core.RuntimeModeShadow), "runtime mode: shadow or enforce")
	if err := flags.Parse(args); err != nil {
		return err
	}
	mode, err := parseRuntimeMode(*modeName)
	if err != nil {
		return err
	}
	file, err := os.Open(*filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	engine, _, err := buildReplayEngine(mode)
	if err != nil {
		return err
	}
	return replay.Run(context.Background(), file, os.Stdout, engine)
}

func buildEngine(secret []byte, requireProof bool, mode core.RuntimeMode, options ...decisionengine.Option) (*decisionengine.Engine, *token.Service, error) {
	tokenService, err := token.NewService(secret, token.NewMemoryNonceStore())
	if err != nil {
		return nil, nil, err
	}
	policyEngine, err := policy.NewDefault()
	if err != nil {
		return nil, nil, err
	}
	registry := detector.NewRegistry(detector.ProtocolConsistency{}, detector.SequenceVelocity{}, detector.CampaignSurface{}, detector.ExternalVerdicts{})
	if err := registry.Err(); err != nil {
		return nil, nil, err
	}
	sessionStore := session.NewMemoryStore(5*time.Minute, 100_000)
	return decisionengine.New(sessionStore, registry, policyEngine, tokenService, requireProof, mode, options...), tokenService, nil
}

func buildReplayEngine(mode core.RuntimeMode) (*decisionengine.Engine, *token.Service, error) {
	// Replay never verifies proofs. Record timestamps provide its clock, while a
	// fixed local-only key and sequential IDs preserve deterministic output
	// without changing the cryptographic randomness used by serve.
	secret := make([]byte, 32)
	nextID := 0
	return buildEngine(
		secret,
		false,
		mode,
		decisionengine.WithDecisionIDGenerator(func() string {
			nextID++
			return fmt.Sprintf("replay-%06d", nextID)
		}),
	)
}

func parseRuntimeMode(value string) (core.RuntimeMode, error) {
	switch core.RuntimeMode(value) {
	case core.RuntimeModeShadow:
		return core.RuntimeModeShadow, nil
	case core.RuntimeModeEnforce:
		return core.RuntimeModeEnforce, nil
	default:
		return "", fmt.Errorf("invalid runtime mode %q: expected shadow or enforce", value)
	}
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
