package policy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"cel.dev/cel-go/cel"
	"github.com/palisade-bot-defense/palisade/internal/core"
)

const DefaultVersion = "default-v3"

type Input struct {
	Scores        core.Scores
	EndpointClass string
	HoneypotHits  int
	PolicyAlert   bool
	VerifiedBot   bool
}

type Result struct {
	Action core.Action
	Reason string
}

type rule struct {
	reason  string
	action  core.Action
	program cel.Program
}

type Engine struct {
	rules   []rule
	version string
}

type ruleSpec struct {
	expression string
	reason     string
	action     core.Action
}

func defaultRuleSpecs() []ruleSpec {
	return []ruleSpec{
		{"policy_alert && honeypot_hits >= 1", "MULTI_SOURCE_ABUSE", core.ActionBlock},
		{"endpoint_class == 'public_content' && (intent_risk >= 0.90 || (!verified_bot && automation_risk >= 0.88))", "PUBLIC_CONTENT_HIGH_RISK", core.ActionThrottle},
		{"intent_risk >= 0.90 || (!verified_bot && automation_risk >= 0.88)", "HIGH_RISK", core.ActionBlock},
		{"policy_alert || honeypot_hits >= 1 || intent_risk >= 0.68 || account_continuity < 0.20 || (!verified_bot && automation_risk >= 0.68)", "STEP_UP_REQUIRED", core.ActionChallenge},
		{"intent_risk >= 0.52 || (!verified_bot && automation_risk >= 0.52)", "ELEVATED_RISK", core.ActionObserve},
		{"verified_bot && !policy_alert && honeypot_hits == 0", "VERIFIED_AUTOMATION_ALLOWED", core.ActionAllow},
	}
}

// DefaultSource renders the checked-in CEL documentation from the same rule
// specifications that are compiled for runtime evaluation.
func DefaultSource() string {
	var source strings.Builder
	source.WriteString("// Generated documentation form of the computed default-v3 policy.\n")
	source.WriteString("// internal/policy/engine_test.go rejects drift from the runtime rules.\n")
	for _, spec := range defaultRuleSpecs() {
		fmt.Fprintf(&source, "%s ? %s :\n", spec.expression, strconv.Quote(string(spec.action)))
	}
	source.WriteString(strconv.Quote(string(core.ActionAllow)))
	source.WriteByte('\n')
	return source.String()
}

func NewDefault() (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("automation_risk", cel.DoubleType),
		cel.Variable("intent_risk", cel.DoubleType),
		cel.Variable("account_continuity", cel.DoubleType),
		cel.Variable("endpoint_class", cel.StringType),
		cel.Variable("honeypot_hits", cel.IntType),
		cel.Variable("policy_alert", cel.BoolType),
		cel.Variable("verified_bot", cel.BoolType),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	engine := &Engine{version: DefaultVersion}
	for _, spec := range defaultRuleSpecs() {
		ast, issues := env.Compile(spec.expression)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compile policy %s: %w", spec.reason, issues.Err())
		}
		program, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("build policy %s: %w", spec.reason, err)
		}
		engine.rules = append(engine.rules, rule{reason: spec.reason, action: spec.action, program: program})
	}
	return engine, nil
}

func (e *Engine) Version() string { return e.version }

func (e *Engine) Evaluate(input Input) (Result, error) {
	activation := map[string]any{
		"automation_risk":    input.Scores.AutomationRisk,
		"intent_risk":        input.Scores.AbuseIntentRisk,
		"account_continuity": input.Scores.AccountContinuity,
		"endpoint_class":     input.EndpointClass,
		"honeypot_hits":      int64(input.HoneypotHits),
		"policy_alert":       input.PolicyAlert,
		"verified_bot":       input.VerifiedBot,
	}
	for _, current := range e.rules {
		value, _, err := current.program.Eval(activation)
		if err != nil {
			return Result{}, fmt.Errorf("evaluate policy %s: %w", current.reason, err)
		}
		matched, ok := value.Value().(bool)
		if !ok {
			return Result{}, errors.New("policy expression did not return boolean")
		}
		if matched {
			return Result{Action: current.action, Reason: current.reason}, nil
		}
	}
	return Result{Action: core.ActionAllow, Reason: "BASELINE_LOW_RISK"}, nil
}
