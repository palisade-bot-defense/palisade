// Package palisadecontract defines the closed normalized values shared by the
// PALISADE HTTP service, protobuf contract and origin adapters. Raw request,
// network, fingerprint and vendor values are deliberately outside this API.
package palisadecontract

const (
	Version          = "palisade.normalized-signal-contract.v1"
	EventProofAction = "events"
)

var (
	requestActions = []string{
		"read", "write", "create", "update", "delete", "search", "compare",
		"login", "logout", "register", "checkout", "purchase", "other",
	}
	proofActions = []string{
		"read", "write", "create", "update", "delete", "search", "compare",
		"login", "logout", "register", "checkout", "purchase", "events", "other",
	}
	endpointClasses = []string{
		"public_content", "compare_index", "compare_noindex", "challenge_worker",
		"other_public", "account", "login", "checkout", "other",
	}
	evaluationCohorts = []string{
		"standard", "reduced_motion", "keyboard_only", "fallback_path", "sensor_missing", "unknown",
	}
	challengeVerdicts = []string{"suspicious", "failed", "blocked", "allowed", "passed", "unknown"}
	crawlerClasses    = []string{
		"unknown", "search_indexer", "answer_engine", "training_crawler",
		"user_triggered_agent", "preview", "monitoring", "other",
	}
	crawlerVerifications   = []string{"unknown", "ip_ua_registry", "fcrdns_ua", "http_signature"}
	transportProtocols     = []string{"http1", "http2", "http3", "unknown"}
	transportSecurities    = []string{"direct_tls", "trusted_proxy_tls", "plaintext", "unknown"}
	clientAddressSources   = []string{"direct", "trusted_proxy", "invalid_trusted_proxy", "unknown"}
	edgeFingerprintClasses = []string{
		"unknown", "browser_consistent", "automation_consistent", "anomalous",
	}
	edgeFingerprintMethods = []string{"unknown", "tls", "http2", "tls_http2"}
	networkReputations     = []string{"unknown", "low_risk", "elevated_risk", "high_risk"}
	networkTypes           = []string{"unknown", "residential", "mobile", "hosting", "enterprise", "education", "anonymizer"}
	decisionActions        = []string{"allow", "observe", "delay", "throttle", "challenge", "block"}
	runtimeModes           = []string{"shadow", "canary", "enforce"}
	enforcementHandlings   = []string{"pass", "delay", "throttle", "challenge", "block"}
)

func RequestActions() []string         { return clone(requestActions) }
func ProofActions() []string           { return clone(proofActions) }
func EndpointClasses() []string        { return clone(endpointClasses) }
func EvaluationCohorts() []string      { return clone(evaluationCohorts) }
func ChallengeVerdicts() []string      { return clone(challengeVerdicts) }
func CrawlerClasses() []string         { return clone(crawlerClasses) }
func CrawlerVerifications() []string   { return clone(crawlerVerifications) }
func TransportProtocols() []string     { return clone(transportProtocols) }
func TransportSecurities() []string    { return clone(transportSecurities) }
func ClientAddressSources() []string   { return clone(clientAddressSources) }
func EdgeFingerprintClasses() []string { return clone(edgeFingerprintClasses) }
func EdgeFingerprintMethods() []string { return clone(edgeFingerprintMethods) }
func NetworkReputations() []string     { return clone(networkReputations) }
func NetworkTypes() []string           { return clone(networkTypes) }
func DecisionActions() []string        { return clone(decisionActions) }
func RuntimeModes() []string           { return clone(runtimeModes) }
func EnforcementHandlings() []string   { return clone(enforcementHandlings) }

func ValidRequestAction(value string) bool        { return contains(requestActions, value) }
func ValidEndpointClass(value string) bool        { return contains(endpointClasses, value) }
func ValidEvaluationCohort(value string) bool     { return contains(evaluationCohorts, value) }
func ValidChallengeVerdict(value string) bool     { return contains(challengeVerdicts, value) }
func ValidCrawlerClass(value string) bool         { return contains(crawlerClasses, value) }
func ValidCrawlerVerification(value string) bool  { return contains(crawlerVerifications, value) }
func ValidTransportProtocol(value string) bool    { return contains(transportProtocols, value) }
func ValidTransportSecurity(value string) bool    { return contains(transportSecurities, value) }
func ValidClientAddressSource(value string) bool  { return contains(clientAddressSources, value) }
func ValidEdgeFingerprintClass(value string) bool { return contains(edgeFingerprintClasses, value) }
func ValidEdgeFingerprintMethod(value string) bool {
	return contains(edgeFingerprintMethods, value)
}
func ValidNetworkReputation(value string) bool   { return contains(networkReputations, value) }
func ValidNetworkType(value string) bool         { return contains(networkTypes, value) }
func ValidDecisionAction(value string) bool      { return contains(decisionActions, value) }
func ValidRuntimeMode(value string) bool         { return contains(runtimeModes, value) }
func ValidEnforcementHandling(value string) bool { return contains(enforcementHandlings, value) }

// ValidProofAction distinguishes the special browser-event proof from closed
// request actions. The events value must never be used as a DecisionRequest action.
func ValidProofAction(value string) bool {
	return contains(proofActions, value)
}

// ValidOptionalUnknownClass accepts omission at the JSON boundary. Every
// omitted class is normalized to unknown before evidence evaluation.
func ValidOptionalUnknownClass(value string, validator func(string) bool) bool {
	return value == "" || validator(value)
}

// ValidCrawlerIdentity rejects a positive identity flag without both a closed
// non-unknown purpose and a closed non-unknown verification method.
func ValidCrawlerIdentity(verified bool, class, verification string) bool {
	if !ValidOptionalUnknownClass(class, ValidCrawlerClass) ||
		!ValidOptionalUnknownClass(verification, ValidCrawlerVerification) {
		return false
	}
	if !verified {
		return true
	}
	return class != "" && class != "unknown" && verification != "" && verification != "unknown"
}

// ValidEdgeIntelligence requires the fingerprint class and its measurement
// method together. Reputation and network type remain independent context and
// no benign class establishes that a client is human.
func ValidEdgeIntelligence(class, method, reputation, networkType string) bool {
	if !ValidOptionalUnknownClass(class, ValidEdgeFingerprintClass) ||
		!ValidOptionalUnknownClass(method, ValidEdgeFingerprintMethod) ||
		!ValidOptionalUnknownClass(reputation, ValidNetworkReputation) ||
		!ValidOptionalUnknownClass(networkType, ValidNetworkType) {
		return false
	}
	classKnown := class != "" && class != "unknown"
	methodKnown := method != "" && method != "unknown"
	return classKnown == methodKnown
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func clone(values []string) []string { return append([]string(nil), values...) }
