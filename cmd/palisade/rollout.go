package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/core"
	"github.com/palisade-bot-defense/palisade/internal/engine"
	"github.com/palisade-bot-defense/palisade/internal/policy"
	"github.com/palisade-bot-defense/palisade/internal/rollout"
)

func rolloutKeygen(args []string) error {
	flags := flag.NewFlagSet("rollout-keygen", flag.ContinueOnError)
	privatePath := flags.String("private-key", "", "new owner-only Ed25519 approval private key outside every Git worktree")
	publicPath := flags.String("public-key", "", "new owner-only Ed25519 verification public key outside every Git worktree")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *privatePath == "" || *publicPath == "" {
		return errors.New("rollout-keygen requires --private-key and --public-key")
	}
	if err := rollout.GenerateKeyPair(*privatePath, *publicPath); err != nil {
		return err
	}
	fmt.Println("rollout approval key pair created")
	return nil
}

func prepareRollout(args []string) error {
	flags := flag.NewFlagSet("prepare-rollout", flag.ContinueOnError)
	analysisPath := flags.String("analysis", "", "owner-only aggregate shadow analysis report")
	privateKeyPath := flags.String("private-key", "", "owner-only Ed25519 approval private key")
	outputPath := flags.String("output", "", "new owner-only signed rollout plan")
	rolloutID := flags.String("rollout-id", "", "stable non-secret rollout identifier")
	approvalID := flags.String("approval-id", "", "stable operator review or change-ticket identifier")
	predecessorRolloutID := flags.String("predecessor-rollout-id", "", "required canary rollout identifier when stage=enforce")
	stageName := flags.String("stage", "canary", "rollout stage: canary or enforce")
	endpointNames := flags.String("endpoints", "", "comma-separated public endpoint classes")
	maxActionName := flags.String("max-action", "challenge", "maximum enforced action: throttle, challenge or block")
	canaryBasisPoints := flags.Uint("canary-basis-points", 0, "selected canary share in basis points; 1-1000, enforce uses 10000")
	expiresIn := flags.String("expires-in", "24h", "plan lifetime, for example 24h")
	throttleSeconds := flags.Int("throttle-seconds", rollout.DefaultThrottleSeconds, "origin Retry-After for throttle")
	challengeTTLSeconds := flags.Int("challenge-ttl-seconds", rollout.DefaultChallengeTTLSeconds, "challenge directive lifetime")
	blockSeconds := flags.Int("block-seconds", rollout.DefaultBlockSeconds, "temporary block lifetime")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *analysisPath == "" || *privateKeyPath == "" || *outputPath == "" || *rolloutID == "" || *approvalID == "" || *endpointNames == "" {
		return errors.New("prepare-rollout requires --analysis, --private-key, --output, --rollout-id, --approval-id and --endpoints")
	}
	stage, err := parseRolloutStage(*stageName)
	if err != nil {
		return err
	}
	if stage == core.RuntimeModeEnforce && *predecessorRolloutID == "" {
		return errors.New("prepare-rollout stage=enforce requires --predecessor-rollout-id")
	}
	maxAction, err := parseRolloutAction(*maxActionName)
	if err != nil {
		return err
	}
	basisPoints := uint32(*canaryBasisPoints)
	if basisPoints == 0 {
		if stage == core.RuntimeModeCanary {
			basisPoints = 100
		} else {
			basisPoints = rollout.FullRolloutBasisPoints
		}
	}
	now := time.Now().UTC()
	expiresAt, err := rollout.ParseDurationFromNow(*expiresIn, now)
	if err != nil {
		return err
	}
	reportBytes, report, err := rollout.ReadAnalysisReport(*analysisPath)
	if err != nil {
		return err
	}
	privateKey, err := rollout.ReadPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	signed, err := rollout.Prepare(report, reportBytes, rollout.PrepareOptions{
		RolloutID: *rolloutID, ApprovalID: *approvalID, PredecessorRolloutID: *predecessorRolloutID, Stage: stage,
		EndpointClasses: splitEndpoints(*endpointNames), MaxAction: maxAction, CanaryBasisPoints: basisPoints,
		ThrottleSeconds: *throttleSeconds, ChallengeTTLSeconds: *challengeTTLSeconds, BlockSeconds: *blockSeconds,
		CreatedAt: now, ExpiresAt: expiresAt,
	}, privateKey)
	if err != nil {
		return err
	}
	if err := rollout.WriteSignedPlan(*outputPath, signed); err != nil {
		return err
	}
	fmt.Printf("signed rollout plan created: rollout=%s stage=%s endpoints=%d expires_at=%s\n", signed.Plan.RolloutID, signed.Plan.Stage, len(signed.Plan.EndpointClasses), signed.Plan.ExpiresAt)
	return nil
}

func verifyRollout(args []string) error {
	flags := flag.NewFlagSet("verify-rollout", flag.ContinueOnError)
	planPath := flags.String("plan", "", "owner-only signed rollout plan")
	publicKeyPath := flags.String("public-key", "", "owner-only Ed25519 verification public key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *planPath == "" || *publicKeyPath == "" {
		return errors.New("verify-rollout requires --plan and --public-key")
	}
	signed, err := rollout.ReadSignedPlan(*planPath)
	if err != nil {
		return err
	}
	publicKey, err := rollout.ReadPublicKey(*publicKeyPath)
	if err != nil {
		return err
	}
	if err := rollout.Verify(signed, publicKey, time.Now().UTC()); err != nil {
		return err
	}
	fmt.Printf("rollout plan verified: rollout=%s stage=%s max_action=%s expires_at=%s\n", signed.Plan.RolloutID, signed.Plan.Stage, signed.Plan.MaxAction, signed.Plan.ExpiresAt)
	return nil
}

func loadRollout(planPath, publicKeyPath string, cohortKey []byte, now time.Time) (*rollout.Controller, error) {
	if (planPath == "") != (publicKeyPath == "") {
		return nil, errors.New("--rollout-plan and --rollout-public-key must be configured together")
	}
	if planPath == "" {
		return nil, nil
	}
	signed, err := rollout.ReadSignedPlan(planPath)
	if err != nil {
		return nil, err
	}
	publicKey, err := rollout.ReadPublicKey(publicKeyPath)
	if err != nil {
		return nil, err
	}
	return rollout.NewController(signed, publicKey, cohortKey, policy.DefaultVersion, engine.ModelVersion, now)
}

func parseRolloutStage(value string) (core.RuntimeMode, error) {
	switch core.RuntimeMode(value) {
	case core.RuntimeModeCanary:
		return core.RuntimeModeCanary, nil
	case core.RuntimeModeEnforce:
		return core.RuntimeModeEnforce, nil
	default:
		return "", fmt.Errorf("invalid rollout stage %q: expected canary or enforce", value)
	}
}

func parseRolloutAction(value string) (core.Action, error) {
	switch core.Action(value) {
	case core.ActionThrottle, core.ActionChallenge, core.ActionBlock:
		return core.Action(value), nil
	default:
		return "", fmt.Errorf("invalid rollout max action %q", value)
	}
}

func splitEndpoints(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		result = append(result, strings.TrimSpace(part))
	}
	return result
}
