package policy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"cel.dev/cel-go/cel"
	"github.com/palisade-human-trust/palisade/internal/core"
)

const DefaultVersion = "default-v5"

const DefaultProfile = "transparent-progressive-v1"

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
	return ruleSpecs(DefaultBundle())
}

func ruleSpecs(bundle Bundle) []ruleSpec {
	automationHigh := strconv.FormatFloat(bundle.AutomationHigh, 'f', 2, 64)
	automationStepUp := strconv.FormatFloat(bundle.AutomationStepUp, 'f', 2, 64)
	automationElevated := strconv.FormatFloat(bundle.AutomationElevated, 'f', 2, 64)
	intentHigh := strconv.FormatFloat(bundle.IntentHigh, 'f', 2, 64)
	intentStepUp := strconv.FormatFloat(bundle.IntentStepUp, 'f', 2, 64)
	intentElevated := strconv.FormatFloat(bundle.IntentElevated, 'f', 2, 64)
	continuityStepUpBelow := strconv.FormatFloat(bundle.ContinuityStepUpBelow, 'f', 2, 64)
	return []ruleSpec{
		{"policy_alert && honeypot_hits >= 1", "MULTI_SOURCE_ABUSE", core.ActionBlock},
		{"endpoint_class == 'public_content' && (intent_risk >= " + intentHigh + " || (!verified_public_crawler && automation_risk >= " + automationHigh + "))", "PUBLIC_CONTENT_HIGH_RISK", core.ActionThrottle},
		{"intent_risk >= " + intentHigh + " || (!verified_public_crawler && automation_risk >= " + automationHigh + ")", "HIGH_RISK", core.ActionBlock},
		{"policy_alert || honeypot_hits >= 1 || intent_risk >= " + intentStepUp + " || account_continuity < " + continuityStepUpBelow + " || (!verified_public_crawler && automation_risk >= " + automationStepUp + ")", "STEP_UP_REQUIRED", core.ActionChallenge},
		{"intent_risk >= " + intentElevated + " || (!verified_public_crawler && automation_risk >= " + automationElevated + ")", "ELEVATED_RISK", core.ActionDelay},
		{"verified_public_crawler && !policy_alert && honeypot_hits == 0", "VERIFIED_PUBLIC_CRAWLER_ALLOWED", core.ActionAllow},
	}
}

// DefaultSource renders the checked-in CEL documentation from the same rule
// specifications that are compiled for runtime evaluation.
func DefaultSource() string {
	var source strings.Builder
	source.WriteString("// Generated documentation form of the computed default-v5 policy.\n")
	source.WriteString("// internal/policy/engine_test.go rejects drift from the runtime rules.\n")
	for _, spec := range defaultRuleSpecs() {
		fmt.Fprintf(&source, "%s ? %s :\n", spec.expression, strconv.Quote(string(spec.action)))
	}
	source.WriteString(strconv.Quote(string(core.ActionAllow)))
	source.WriteByte('\n')
	return source.String()
}

func NewDefault() (*Engine, error) {
	return newEngine(DefaultBundle())
}

func newEngine(bundle Bundle) (*Engine, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	env, err := cel.NewEnv(
		cel.Variable("automation_risk", cel.DoubleType),
		cel.Variable("intent_risk", cel.DoubleType),
		cel.Variable("account_continuity", cel.DoubleType),
		cel.Variable("endpoint_class", cel.StringType),
		cel.Variable("honeypot_hits", cel.IntType),
		cel.Variable("policy_alert", cel.BoolType),
		cel.Variable("verified_public_crawler", cel.BoolType),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	engine := &Engine{version: bundle.PolicyVersion}
	for _, spec := range ruleSpecs(bundle) {
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
		"automation_risk":         input.Scores.AutomationRisk,
		"intent_risk":             input.Scores.AbuseIntentRisk,
		"account_continuity":      input.Scores.AccountContinuity,
		"endpoint_class":          input.EndpointClass,
		"honeypot_hits":           int64(input.HoneypotHits),
		"policy_alert":            input.PolicyAlert,
		"verified_public_crawler": input.VerifiedBot && publicCrawlerEndpoint(input.EndpointClass),
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

func publicCrawlerEndpoint(value string) bool {
	switch value {
	case "public_content", "compare_index", "other_public":
		return true
	default:
		return false
	}
}
