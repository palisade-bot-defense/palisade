package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/analysisfeed"
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
		return errors.New("usage: palisade <serve|doctor|replay|import-offline|verify-shadow-log|analyze-shadow-log|crawler-registry-keygen|crawler-registry-sign|crawler-registry-inspect|rollout-keygen|prepare-review|prepare-rollout|verify-rollout|version>")
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
	case "crawler-registry-keygen":
		return crawlerRegistryKeygen(args[1:])
	case "crawler-registry-sign":
		return crawlerRegistrySign(args[1:])
	case "crawler-registry-inspect":
		return crawlerRegistryInspect(args[1:])
	case "rollout-keygen":
		return rolloutKeygen(args[1:])
	case "prepare-review":
		return prepareReview(args[1:])
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
	maxDecisionLinks := flags.Int("max-decision-links", shadowanalysis.DefaultMaxDecisionLinks, "hard in-memory decision/outcome linkage budget")
	outputPath := flags.String("output", "", "new owner-only aggregate report outside every Git worktree; defaults to stdout")
	watchInterval := flags.Duration("watch-interval", 0, "repeat local analysis and atomically replace --output at this interval")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *directory == "" || *keyFile == "" {
		return errors.New("analyze-shadow-log requires --dir and --key-file and accepts no positional arguments")
	}
	config := shadowanalysis.Config{ScanLimits: shadowlog.ScanLimits{
		MaxFiles: *maxFiles, MaxRecords: *maxRecords, MaxEncryptedBytes: *maxEncryptedBytes,
	}, MaxDecisionLinks: *maxDecisionLinks}
	if *watchInterval != 0 {
		if *outputPath == "" || *watchInterval < 10*time.Second || *watchInterval > 24*time.Hour {
			return errors.New("--watch-interval requires --output and must be between 10s and 24h")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runShadowAnalysisWatch(ctx, *watchInterval, func() (shadowanalysis.Report, error) {
			return shadowanalysis.AnalyzeDirectory(*directory, *keyFile, config)
		}, func(report shadowanalysis.Report) error {
			return rollout.ReplaceAnalysisReport(*outputPath, report)
		}, os.Stdout, os.Stderr)
	}
	report, err := shadowanalysis.AnalyzeDirectory(*directory, *keyFile, config)
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

func runShadowAnalysisWatch(ctx context.Context, interval time.Duration, analyze func() (shadowanalysis.Report, error), publish func(shadowanalysis.Report) error, stdout, stderr io.Writer) error {
	update := func() error {
		report, err := analyze()
		if err != nil {
			return err
		}
		if err := publish(report); err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "shadow analysis updated: decisions=%d outcomes=%d readiness=%s\n", report.Decisions.Total, report.Outcomes.Total, report.Readiness.State)
		return err
	}
	if err := update(); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := update(); err != nil {
				_, _ = fmt.Fprintln(stderr, "shadow analysis update failed; last valid aggregate report retained")
			}
		}
	}
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
	listen := flags.String("listen", "127.0.0.1:8080", "public decision API listen address")
	adminListen := flags.String("admin-listen", "127.0.0.1:8081", "loopback-only operator console listen address")
	adminAnalysisReport := flags.String("admin-analysis-report", "", "owner-only aggregate analysis report outside every Git worktree")
	adminAnalysisRefresh := flags.Duration("admin-analysis-refresh", 30*time.Second, "poll interval for an atomically replaced aggregate analysis report")
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
	eventShadowAction := flags.String("event-shadow-action", "", "server-trusted action for one shadow decision after each accepted event batch")
	eventShadowEndpoint := flags.String("event-shadow-endpoint-class", "", "server-trusted endpoint class for event-triggered shadow decisions")
	eventShadowFromProof := flags.Bool("event-shadow-from-proof", false, "derive each event shadow action and endpoint class from its backend-issued signed proof")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve does not accept positional arguments")
	}
	if err := validateAdminListen(*adminListen); err != nil {
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
	if (*eventShadowAction == "") != (*eventShadowEndpoint == "") {
		return errors.New("--event-shadow-action and --event-shadow-endpoint-class must be configured together")
	}
	if *eventShadowFromProof && *eventShadowAction != "" {
		return errors.New("--event-shadow-from-proof is mutually exclusive with the static event shadow profile")
	}
	eventShadowEnabled := *eventShadowAction != "" || *eventShadowFromProof
	if eventShadowEnabled && *shadowLogDir == "" {
		return errors.New("event shadow evaluation requires the encrypted shadow log")
	}
	if eventShadowEnabled && !*requireSessionCookie {
		return errors.New("event shadow evaluation requires --require-session-cookie")
	}
	if eventShadowEnabled && *rolloutPlanPath != "" {
		return errors.New("event shadow evaluation is shadow-only and cannot run with a signed rollout plan")
	}
	if *eventShadowFromProof && *dev {
		return errors.New("--event-shadow-from-proof requires production one-time event proofs and cannot run with --dev")
	}
	var eventShadowProfile httpapi.EventShadowProfile
	if *eventShadowFromProof {
		eventShadowProfile = httpapi.NewEventShadowProofProfile()
	} else if eventShadowEnabled {
		eventShadowProfile, err = httpapi.NewEventShadowProfile(*eventShadowAction, *eventShadowEndpoint)
		if err != nil {
			return err
		}
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
	adminKey, err := adminSecret(*dev, apiKey)
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
	var analysisFeed *analysisfeed.Feed
	if *adminAnalysisReport != "" {
		analysisFeed, err = analysisfeed.New(*adminAnalysisReport, *adminAnalysisRefresh, logger)
		if err != nil {
			return err
		}
	}
	eventStore := events.NewStore(5 * time.Minute)
	api := httpapi.New(engine, tokenService, apiKey, logger).
		WithEventStore(eventStore).
		RequireEventProof(!*dev).
		WithSessionCookies(sessionCookies, *requireSessionCookie).
		WithChallenges(challengeService)
	if shadowSink != nil {
		api.WithShadowRecorder(shadowSink)
	}
	if eventShadowEnabled {
		api.WithEventShadowEvaluation(eventShadowProfile)
	}
	rolloutID := ""
	if rolloutController != nil {
		rolloutID = rolloutController.Plan().RolloutID
	}
	api.WithAdmin(httpapi.AdminConfig{
		Key: adminKey, StartedAt: time.Now().UTC(), Mode: mode, RolloutID: rolloutID,
		PolicyVersion: policy.DefaultVersion, ModelVersion: decisionengine.ModelVersion,
		ShadowLogEnabled: shadowSink != nil, EventShadowEnabled: eventShadowEnabled,
		EventShadowFromProof: *eventShadowFromProof, AnalysisFeed: analysisFeed,
	})
	server := &http.Server{
		Addr:              *listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	adminServer := &http.Server{
		Addr:              *adminListen,
		Handler:           api.AdminHandler(),
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
	analysisFeedDone := make(chan struct{})
	if analysisFeed == nil {
		close(analysisFeedDone)
	} else {
		go func() {
			defer close(analysisFeedDone)
			analysisFeed.Run(ctx)
		}()
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = adminServer.Shutdown(shutdownCtx)
	}()
	logger.Info("PALISADE starting", "version", version, "listen", *listen, "admin_listen", *adminListen, "dev", *dev, "mode", mode, "rollout_id", rolloutID, "require_session_cookie", *requireSessionCookie, "shadow_log", shadowSink != nil, "event_shadow_evaluation", eventShadowEnabled, "event_shadow_from_proof", *eventShadowFromProof, "analysis_report", analysisFeed != nil)
	if *dev {
		logger.Warn("development mode active; proof tokens are not required")
	}
	serverErrors := make(chan error, 2)
	go func() { serverErrors <- server.ListenAndServe() }()
	go func() { serverErrors <- adminServer.ListenAndServe() }()
	err = <-serverErrors
	stop()
	secondServerErr := <-serverErrors
	<-challengeSweeperDone
	<-analysisFeedDone
	var shadowCloseErr error
	if shadowSink != nil {
		shadowCloseErr = shadowSink.Close()
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	if errors.Is(secondServerErr, http.ErrServerClosed) {
		secondServerErr = nil
	}
	return errors.Join(err, secondServerErr, shadowCloseErr)
}

func doctor() error {
	_, keyPresent := os.LookupEnv("PALISADE_HMAC_KEY")
	_, apiKeyPresent := os.LookupEnv("PALISADE_API_KEY")
	_, adminKeyPresent := os.LookupEnv("PALISADE_ADMIN_KEY")
	fmt.Printf("PALISADE doctor\nversion: %s\ngo: %s\nhmac_key: %t\napi_key: %t\nadmin_key: %t\n", version, runtime.Version(), keyPresent, apiKeyPresent, adminKeyPresent)
	if !keyPresent || !apiKeyPresent || !adminKeyPresent {
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
	registry := detector.NewDefaultRegistry()
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

func adminSecret(dev bool, apiKey string) (string, error) {
	adminKey := os.Getenv("PALISADE_ADMIN_KEY")
	if adminKey == "" && dev {
		return "development-only-admin", nil
	}
	if len(adminKey) < 32 {
		return "", errors.New("PALISADE_ADMIN_KEY must contain at least 32 bytes when configured")
	}
	if len(adminKey) == len(apiKey) && subtle.ConstantTimeCompare([]byte(adminKey), []byte(apiKey)) == 1 {
		return "", errors.New("PALISADE_ADMIN_KEY must be distinct from PALISADE_API_KEY")
	}
	return adminKey, nil
}

func validateAdminListen(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("--admin-listen must be a loopback IP and port")
	}
	ip := net.ParseIP(host)
	portNumber, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("--admin-listen must be a loopback IP and port")
	}
	return nil
}
