package palisadecontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type normalizedCatalog struct {
	SchemaVersion          string                `json:"schema_version"`
	Scope                  string                `json:"scope"`
	Closed                 bool                  `json:"closed"`
	RawValuesAllowed       bool                  `json:"raw_values_allowed"`
	RequestActions         []string              `json:"request_actions"`
	ProofActions           []string              `json:"proof_actions"`
	EndpointClasses        []string              `json:"endpoint_classes"`
	EvaluationCohorts      []string              `json:"evaluation_cohorts"`
	ChallengeVerdicts      []string              `json:"challenge_verdicts"`
	CrawlerClasses         []string              `json:"crawler_classes"`
	CrawlerVerifications   []string              `json:"crawler_verifications"`
	TransportProtocols     []string              `json:"transport_protocols"`
	TransportSecurities    []string              `json:"transport_securities"`
	ClientAddressSources   []string              `json:"client_address_sources"`
	EdgeFingerprintClasses []string              `json:"edge_fingerprint_classes"`
	EdgeFingerprintMethods []string              `json:"edge_fingerprint_methods"`
	NetworkReputations     []string              `json:"network_reputations"`
	NetworkTypes           []string              `json:"network_types"`
	DecisionActions        []string              `json:"decision_actions"`
	RuntimeModes           []string              `json:"runtime_modes"`
	EnforcementHandlings   []string              `json:"enforcement_handlings"`
	NumericBounds          map[string]valueRange `json:"numeric_bounds"`
	Invariants             map[string]string     `json:"invariants"`
	ForbiddenRawClasses    []string              `json:"forbidden_raw_classes"`
}

type valueRange struct {
	Minimum float64 `json:"minimum"`
	Maximum float64 `json:"maximum"`
}

func TestPublishedCatalogMatchesGoContractExactly(t *testing.T) {
	root := contractRepositoryRoot(t)
	catalog := readNormalizedCatalog(t, filepath.Join(root, "api/contracts/normalized-signal-v1.json"))
	if catalog.SchemaVersion != Version || catalog.Scope != "decision_and_origin_adapter" || !catalog.Closed || catalog.RawValuesAllowed {
		t.Fatalf("unsafe normalized contract header: %+v", catalog)
	}
	want := map[string][]string{
		"request_actions": RequestActions(), "proof_actions": ProofActions(), "endpoint_classes": EndpointClasses(),
		"evaluation_cohorts": EvaluationCohorts(), "challenge_verdicts": ChallengeVerdicts(), "crawler_classes": CrawlerClasses(),
		"crawler_verifications": CrawlerVerifications(), "transport_protocols": TransportProtocols(), "transport_securities": TransportSecurities(),
		"client_address_sources": ClientAddressSources(), "edge_fingerprint_classes": EdgeFingerprintClasses(),
		"edge_fingerprint_methods": EdgeFingerprintMethods(), "network_reputations": NetworkReputations(), "network_types": NetworkTypes(),
		"decision_actions": DecisionActions(), "runtime_modes": RuntimeModes(), "enforcement_handlings": EnforcementHandlings(),
	}
	got := map[string][]string{
		"request_actions": catalog.RequestActions, "proof_actions": catalog.ProofActions, "endpoint_classes": catalog.EndpointClasses,
		"evaluation_cohorts": catalog.EvaluationCohorts, "challenge_verdicts": catalog.ChallengeVerdicts, "crawler_classes": catalog.CrawlerClasses,
		"crawler_verifications": catalog.CrawlerVerifications, "transport_protocols": catalog.TransportProtocols, "transport_securities": catalog.TransportSecurities,
		"client_address_sources": catalog.ClientAddressSources, "edge_fingerprint_classes": catalog.EdgeFingerprintClasses,
		"edge_fingerprint_methods": catalog.EdgeFingerprintMethods, "network_reputations": catalog.NetworkReputations, "network_types": catalog.NetworkTypes,
		"decision_actions": catalog.DecisionActions, "runtime_modes": catalog.RuntimeModes, "enforcement_handlings": catalog.EnforcementHandlings,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog drift:\ngot  %#v\nwant %#v", got, want)
	}
	wantBounds := map[string]valueRange{
		"browser_event_count": {Minimum: 0, Maximum: 10_000},
		"honeypot_hits":       {Minimum: 0, Maximum: 100},
		"external_risk_score": {Minimum: 0, Maximum: 1},
	}
	if !reflect.DeepEqual(catalog.NumericBounds, wantBounds) {
		t.Fatalf("numeric bounds = %#v, want %#v", catalog.NumericBounds, wantBounds)
	}
	wantInvariants := map[string]string{
		"omitted_optional_class": "unknown", "edge_fingerprint_pairing": "class_and_method_known_together",
		"verified_crawler_pairing": "non_unknown_class_and_verification_required", "browser_event_claim": "neutral_until_server_verified",
		"challenge_passed": "outcome_not_human_identity",
	}
	if !reflect.DeepEqual(catalog.Invariants, wantInvariants) {
		t.Fatalf("invariants = %#v, want %#v", catalog.Invariants, wantInvariants)
	}
	wantForbidden := []string{"request_url", "query_string", "request_body", "user_agent", "ip_address", "asn", "tls_fingerprint", "http2_fingerprint", "vendor_label", "vendor_score"}
	if !reflect.DeepEqual(catalog.ForbiddenRawClasses, wantForbidden) {
		t.Fatalf("forbidden raw classes = %#v, want %#v", catalog.ForbiddenRawClasses, wantForbidden)
	}
}

func TestOpenAPIAndProtobufMatchPublishedClosedValues(t *testing.T) {
	root := contractRepositoryRoot(t)
	catalog := readNormalizedCatalog(t, filepath.Join(root, "api/contracts/normalized-signal-v1.json"))
	openAPI := readContractFile(t, filepath.Join(root, "api/openapi.yaml"))
	for _, marker := range []string{
		"x-palisade-adapter-contract: palisade.origin-adapter.v1",
		"x-palisade-normalized-signal-contract: palisade.normalized-signal-contract.v1",
	} {
		if !bytes.Contains(openAPI, []byte(marker)) {
			t.Fatalf("OpenAPI lost contract marker %q", marker)
		}
	}
	for name, values := range map[string][]string{
		"proof actions": catalog.ProofActions, "request actions": catalog.RequestActions, "endpoint classes": catalog.EndpointClasses,
		"evaluation cohorts": catalog.EvaluationCohorts, "challenge verdicts": catalog.ChallengeVerdicts,
		"crawler classes": catalog.CrawlerClasses, "crawler verifications": catalog.CrawlerVerifications,
		"transport protocols": catalog.TransportProtocols, "transport securities": catalog.TransportSecurities,
		"client address sources": catalog.ClientAddressSources, "edge fingerprint classes": catalog.EdgeFingerprintClasses,
		"edge fingerprint methods": catalog.EdgeFingerprintMethods, "network reputations": catalog.NetworkReputations,
		"network types": catalog.NetworkTypes, "decision actions": catalog.DecisionActions,
		"runtime modes": catalog.RuntimeModes, "enforcement handlings": catalog.EnforcementHandlings,
	} {
		literal := "enum: [" + strings.Join(values, ", ") + "]"
		if !bytes.Contains(openAPI, []byte(literal)) {
			t.Errorf("OpenAPI missing exact %s enum %q", name, literal)
		}
	}
	if bytes.Contains(openAPI, []byte("action: { type: string, minLength: 1, maxLength: 80 }")) {
		t.Fatal("OpenAPI still exposes a free-form action field")
	}
	for _, invariant := range []string{
		"required: [crawler_class, crawler_verification]",
		"required: [edge_fingerprint_method]",
		"required: [edge_fingerprint_class]",
	} {
		if !bytes.Contains(openAPI, []byte(invariant)) {
			t.Errorf("OpenAPI missing cross-field invariant %q", invariant)
		}
	}

	decisionProto := string(readContractFile(t, filepath.Join(root, "api/proto/palisade/v1/decision.proto")))
	commonProto := string(readContractFile(t, filepath.Join(root, "api/proto/palisade/v1/common.proto")))
	protoEnums := []struct {
		name, prefix string
		values       []string
		contents     string
	}{
		{"RequestAction", "REQUEST_ACTION_", catalog.RequestActions, decisionProto},
		{"EndpointClass", "ENDPOINT_CLASS_", catalog.EndpointClasses, decisionProto},
		{"EvaluationCohort", "EVALUATION_COHORT_", catalog.EvaluationCohorts, decisionProto},
		{"ChallengeVerdict", "CHALLENGE_VERDICT_", catalog.ChallengeVerdicts, decisionProto},
		{"CrawlerClass", "CRAWLER_CLASS_", catalog.CrawlerClasses, decisionProto},
		{"CrawlerVerification", "CRAWLER_VERIFICATION_", catalog.CrawlerVerifications, decisionProto},
		{"TransportProtocol", "TRANSPORT_PROTOCOL_", catalog.TransportProtocols, decisionProto},
		{"TransportSecurity", "TRANSPORT_SECURITY_", catalog.TransportSecurities, decisionProto},
		{"ClientAddressSource", "CLIENT_ADDRESS_SOURCE_", catalog.ClientAddressSources, decisionProto},
		{"EdgeFingerprintClass", "EDGE_FINGERPRINT_CLASS_", catalog.EdgeFingerprintClasses, decisionProto},
		{"EdgeFingerprintMethod", "EDGE_FINGERPRINT_METHOD_", catalog.EdgeFingerprintMethods, decisionProto},
		{"NetworkReputation", "NETWORK_REPUTATION_", catalog.NetworkReputations, decisionProto},
		{"NetworkType", "NETWORK_TYPE_", catalog.NetworkTypes, decisionProto},
		{"Action", "ACTION_", catalog.DecisionActions, commonProto},
		{"RuntimeMode", "RUNTIME_MODE_", catalog.RuntimeModes, commonProto},
		{"EnforcementHandling", "ENFORCEMENT_HANDLING_", catalog.EnforcementHandlings, commonProto},
	}
	for _, enum := range protoEnums {
		got := parseProtoEnum(t, enum.contents, enum.name, enum.prefix)
		want := append([]string(nil), enum.values...)
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("protobuf enum %s = %v, want %v", enum.name, got, want)
		}
	}
	for _, declaration := range []string{
		"RequestAction action = 2;", "EndpointClass endpoint_class = 3;", "EvaluationCohort evaluation_cohort = 7;",
		"ChallengeVerdict challenge_verdict = 4;", "TransportProtocol transport_protocol = 8;",
		"CrawlerClass crawler_class = 11;", "EdgeFingerprintClass edge_fingerprint_class = 13;",
		"NetworkReputation network_reputation = 15;", "EnforcementHandling handling = 1;",
	} {
		if !strings.Contains(decisionProto+commonProto, declaration) {
			t.Errorf("protobuf contract missing typed declaration %q", declaration)
		}
	}
}

func TestCatalogDecoderRejectsUnknownAndTrailingJSON(t *testing.T) {
	root := contractRepositoryRoot(t)
	contents := readContractFile(t, filepath.Join(root, "api/contracts/normalized-signal-v1.json"))
	for name, mutated := range map[string][]byte{
		"unknown field":     bytes.Replace(contents, []byte(`{`), []byte(`{"unknown":true,`), 1),
		"trailing document": append(append([]byte(nil), contents...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeNormalizedCatalog(mutated); err == nil {
				t.Fatal("poisoned normalized catalog was accepted")
			}
		})
	}
}

func TestProtobufContractsHaveBalancedBlocksAndUniqueNumbers(t *testing.T) {
	root := contractRepositoryRoot(t)
	for _, relative := range []string{
		"api/proto/palisade/v1/common.proto",
		"api/proto/palisade/v1/decision.proto",
	} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			contents := string(readContractFile(t, filepath.Join(root, relative)))
			if !strings.Contains(contents, `syntax = "proto3";`) || strings.Count(contents, "{") != strings.Count(contents, "}") {
				t.Fatalf("unbalanced or non-proto3 contract %s", relative)
			}
			blockPattern := regexp.MustCompile(`(?s)(message|enum)\s+([A-Za-z][A-Za-z0-9_]*)\s*\{(.*?)\}`)
			blocks := blockPattern.FindAllStringSubmatch(contents, -1)
			if len(blocks) == 0 {
				t.Fatalf("no message or enum blocks in %s", relative)
			}
			numberPattern := regexp.MustCompile(`=\s*([0-9]+)\s*;`)
			for _, block := range blocks {
				seen := map[int]bool{}
				numbers := numberPattern.FindAllStringSubmatch(block[3], -1)
				if len(numbers) == 0 {
					t.Errorf("%s %s has no numbered values", block[1], block[2])
				}
				for _, match := range numbers {
					number, err := strconv.Atoi(match[1])
					if err != nil || seen[number] {
						t.Errorf("%s %s has invalid or duplicate number %q", block[1], block[2], match[1])
					}
					seen[number] = true
				}
				if block[1] == "enum" && !seen[0] {
					t.Errorf("enum %s has no zero value", block[2])
				}
			}
		})
	}
}

func readNormalizedCatalog(t *testing.T, path string) normalizedCatalog {
	t.Helper()
	catalog, err := decodeNormalizedCatalog(readContractFile(t, path))
	if err != nil {
		t.Fatalf("decode normalized catalog: %v", err)
	}
	return catalog
}

func decodeNormalizedCatalog(contents []byte) (normalizedCatalog, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var catalog normalizedCatalog
	if err := decoder.Decode(&catalog); err != nil {
		return normalizedCatalog{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return normalizedCatalog{}, fmt.Errorf("trailing JSON")
		}
		return normalizedCatalog{}, fmt.Errorf("trailing JSON: %w", err)
	}
	return catalog, nil
}

func parseProtoEnum(t *testing.T, contents, name, prefix string) []string {
	t.Helper()
	blockPattern := regexp.MustCompile(`(?s)enum\s+` + regexp.QuoteMeta(name) + `\s*\{(.*?)\}`)
	block := blockPattern.FindStringSubmatch(contents)
	if len(block) != 2 {
		t.Fatalf("protobuf enum %s not found", name)
	}
	valuePattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(prefix) + `([A-Z0-9_]+)\s*=\s*([0-9]+);`)
	matches := valuePattern.FindAllStringSubmatch(block[1], -1)
	values := make([]string, 0, len(matches))
	seenNumbers := map[int]bool{}
	for _, match := range matches {
		number, err := strconv.Atoi(match[2])
		if err != nil || seenNumbers[number] {
			t.Fatalf("protobuf enum %s has invalid or duplicate number %q", name, match[2])
		}
		seenNumbers[number] = true
		if match[1] == "UNSPECIFIED" {
			continue
		}
		values = append(values, strings.ToLower(match[1]))
	}
	if len(values) == 0 {
		t.Fatalf("protobuf enum %s has no values", name)
	}
	return values
}

func readContractFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func contractRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract package path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
