package main

import (
	"errors"
	"flag"
	"fmt"
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
	reviewPath := flags.String("review", "", "owner-only deterministic rollout review proposal")
	privateKeyPath := flags.String("private-key", "", "owner-only Ed25519 approval private key")
	outputPath := flags.String("output", "", "new owner-only signed rollout plan")
	rolloutID := flags.String("rollout-id", "", "stable non-secret rollout identifier")
	approvalID := flags.String("approval-id", "", "stable operator review or change-ticket identifier")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *analysisPath == "" || *reviewPath == "" || *privateKeyPath == "" || *outputPath == "" || *rolloutID == "" || *approvalID == "" {
		return errors.New("prepare-rollout requires --analysis, --review, --private-key, --output, --rollout-id and --approval-id")
	}
	reportBytes, report, err := rollout.ReadAnalysisReport(*analysisPath)
	if err != nil {
		return err
	}
	proposal, err := rollout.ReadReviewProposal(*reviewPath)
	if err != nil {
		return err
	}
	privateKey, err := rollout.ReadPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	signed, err := rollout.PrepareFromReview(report, reportBytes, proposal, *rolloutID, *approvalID, time.Now().UTC(), privateKey)
	if err != nil {
		return err
	}
	if err := rollout.WriteSignedPlan(*outputPath, signed); err != nil {
		return err
	}
	fmt.Printf("signed rollout plan created: rollout=%s stage=%s endpoints=%d expires_at=%s\n", signed.Plan.RolloutID, signed.Plan.Stage, len(signed.Plan.EndpointClasses), signed.Plan.ExpiresAt)
	return nil
}

func prepareReview(args []string) error {
	flags := flag.NewFlagSet("prepare-review", flag.ContinueOnError)
	analysisPath := flags.String("analysis", "", "owner-only aggregate shadow analysis report")
	outputPath := flags.String("output", "", "new owner-only deterministic review proposal")
	stageName := flags.String("stage", "canary", "reviewed rollout stage: canary or enforce")
	predecessorRolloutID := flags.String("predecessor-rollout-id", "", "required exact predecessor canary identifier for enforce review")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *analysisPath == "" || *outputPath == "" {
		return errors.New("prepare-review requires --analysis and --output")
	}
	stage, err := parseRolloutStage(*stageName)
	if err != nil {
		return err
	}
	if stage == core.RuntimeModeEnforce && *predecessorRolloutID == "" {
		return errors.New("prepare-review stage=enforce requires --predecessor-rollout-id")
	}
	if stage == core.RuntimeModeCanary && *predecessorRolloutID != "" {
		return errors.New("prepare-review stage=canary does not accept --predecessor-rollout-id")
	}
	reportBytes, report, err := rollout.ReadAnalysisReport(*analysisPath)
	if err != nil {
		return err
	}
	proposal, err := rollout.BuildReviewProposal(report, reportBytes, rollout.ReviewOptions{Stage: stage, PredecessorRolloutID: *predecessorRolloutID})
	if err != nil {
		return err
	}
	if err := rollout.WriteReviewProposal(*outputPath, proposal); err != nil {
		return err
	}
	endpoints := 0
	if proposal.RecommendedScope != nil {
		endpoints = len(proposal.RecommendedScope.EndpointClasses)
	}
	fmt.Printf("rollout review proposal created: state=%s stage=%s endpoints=%d automatic_activation=false\n", proposal.State, proposal.RequestedStage, endpoints)
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
