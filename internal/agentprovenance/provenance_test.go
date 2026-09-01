package agentprovenance

import (
	"reflect"
	"testing"

	"github.com/palisade-human-trust/palisade/internal/core"
	"github.com/palisade-human-trust/palisade/pkg/palisadeassurance"
)

func observations(verified bool, class core.CrawlerClass, method string) core.Observations {
	return core.Observations{
		VerifiedBot:         verified,
		CrawlerClass:        class,
		CrawlerVerification: core.CrawlerVerification(method),
	}
}

func TestOrdinaryTrafficHasNoAgentIdentity(t *testing.T) {
	result := Derive(core.Observations{}, "public_content")
	if result.Provenance != None || result.Purpose != "" {
		t.Fatalf("ordinary traffic was given an agent identity: %+v", result)
	}
	if len(result.ReasonCodes) != 0 {
		t.Fatalf("ordinary traffic produced reason codes: %v", result.ReasonCodes)
	}
	if result.Verified() {
		t.Fatal("ordinary traffic reported as verified")
	}
}

func TestCompleteTrustChainVerifiesForItsPurpose(t *testing.T) {
	result := Derive(observations(true, core.CrawlerClassSearchIndexer, "ip_ua_registry"), "public_content")
	if result.Provenance != VerifiedPurpose || !result.Verified() {
		t.Fatalf("a complete trust chain did not verify: %+v", result)
	}
	if result.Purpose != string(core.CrawlerClassSearchIndexer) {
		t.Fatalf("the declared purpose was lost: %+v", result)
	}
	if !reflect.DeepEqual(result.ReasonCodes, []string{ReasonVerifiedPurpose}) {
		t.Fatalf("unexpected reason codes: %v", result.ReasonCodes)
	}
}

func TestAClaimAloneNeverVerifies(t *testing.T) {
	// Every one of these is spoofable or incomplete. None may reach
	// verified_purpose, because a user-agent token is not an identity.
	cases := map[string]struct {
		observations  core.Observations
		endpointClass string
	}{
		"claimed class with no verification": {
			observations(false, core.CrawlerClassSearchIndexer, ""), "public_content"},
		"verified bot with unknown method": {
			observations(true, core.CrawlerClassSearchIndexer, "unknown"), "public_content"},
		"verified bot with no purpose class": {
			observations(true, core.CrawlerClassUnknown, "ip_ua_registry"), "public_content"},
		"training crawler is policy controlled": {
			observations(true, core.CrawlerClassTrainingCrawler, "ip_ua_registry"), "public_content"},
		"monitoring is policy controlled": {
			observations(true, core.CrawlerClassMonitoring, "ip_ua_registry"), "public_content"},
	}
	for name, testCase := range cases {
		result := Derive(testCase.observations, testCase.endpointClass)
		if result.Verified() {
			t.Fatalf("%s verified: %+v", name, result)
		}
	}
}

func TestPurposeDoesNotTravelToEveryEndpoint(t *testing.T) {
	// The same identity that verifies on public content must not verify on a
	// login, account or checkout surface. Identity is not authorization.
	for _, endpointClass := range []string{"login", "account", "checkout", "compare_noindex", "challenge_worker"} {
		result := Derive(observations(true, core.CrawlerClassSearchIndexer, "ip_ua_registry"), endpointClass)
		if result.Verified() {
			t.Fatalf("a crawler verified on %s: %+v", endpointClass, result)
		}
		if !contains(result.ReasonCodes, ReasonPurposeNotPermittedHere) {
			t.Fatalf("the scope mismatch on %s was not explained: %v", endpointClass, result.ReasonCodes)
		}
	}

	// The same request on a public endpoint does verify, so the difference is
	// the endpoint and nothing else.
	if !Derive(observations(true, core.CrawlerClassSearchIndexer, "ip_ua_registry"), "public_content").Verified() {
		t.Fatal("the control case did not verify")
	}
}

func TestAuthorizedProvenanceIsUnreachable(t *testing.T) {
	// An authorized agent must present proof that a verified human authorized
	// it. That requires an assurance level above the supported ceiling, so no
	// input may produce this value today.
	classes := []core.CrawlerClass{
		core.CrawlerClassUnknown, core.CrawlerClassSearchIndexer, core.CrawlerClassAnswerEngine,
		core.CrawlerClassTrainingCrawler, core.CrawlerClassUserTriggeredAgent,
		core.CrawlerClassPreview, core.CrawlerClassMonitoring,
	}
	methods := []string{"", "unknown", "ip_ua_registry", "fcrdns_ua", "http_signature"}
	endpoints := []string{
		"public_content", "compare_index", "compare_noindex", "challenge_worker",
		"other_public", "account", "login", "checkout", "other",
	}
	for _, class := range classes {
		for _, method := range methods {
			for _, endpoint := range endpoints {
				for _, verified := range []bool{false, true} {
					result := Derive(observations(verified, class, method), endpoint)
					if result.Provenance == Authorized {
						t.Fatalf("authorized provenance was reached: class %v method %q endpoint %q",
							class, method, endpoint)
					}
					if !validProvenance(result.Provenance) {
						t.Fatalf("unknown provenance %q", result.Provenance)
					}
				}
			}
		}
	}
	if palisadeassurance.MaximumSupportedLevel >= palisadeassurance.LevelAttestedDevice {
		t.Fatal("the assurance ceiling rose; revisit whether an agent grant can now be verified")
	}
}

func TestVocabularyMatchesTheAssertionContract(t *testing.T) {
	// The assertion carries this value, so both vocabularies must be the same.
	want := map[string]struct{}{}
	for _, value := range palisadeassurance.AgentProvenances() {
		want[value] = struct{}{}
	}
	for _, value := range []string{None, Declared, Authorized, VerifiedPurpose} {
		if _, known := want[value]; !known {
			t.Fatalf("%q is not part of the published assertion vocabulary", value)
		}
		delete(want, value)
	}
	if len(want) != 0 {
		t.Fatalf("the assertion vocabulary has values this package cannot produce: %v", want)
	}
}

func validProvenance(value string) bool {
	switch value {
	case None, Declared, Authorized, VerifiedPurpose:
		return true
	default:
		return false
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
