package palisadeassurance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testAudience = "relying.example"

var testSecret = []byte("palisade-assurance-binding-secret-32b")

func testKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for index := range raw {
		raw[index] = seed
	}
	private := ed25519.NewKeyFromSeed(raw)
	return private.Public().(ed25519.PublicKey), private
}

func testPayload(t *testing.T, level int, sources []string) Payload {
	t.Helper()
	binding, err := SessionBinding(testSecret, "session-identifier-value", testAudience)
	if err != nil {
		t.Fatalf("derive session binding: %v", err)
	}
	return Payload{
		AssuranceLevel:   level,
		AssuranceSources: sources,
		ReasonCodes:      []string{"verified_browser_events"},
		UniquenessScope:  "none",
		AgentProvenance:  "none",
		Binding: Binding{
			SessionBinding: binding,
			RequestAction:  "login",
			EndpointClass:  "login",
			Audience:       testAudience,
		},
		PolicyVersion: "default-v5",
		ModelVersion:  "transparent-baseline-v13",
	}
}

func TestBehavioralAssertionRoundTripsAndCarriesNoIdentity(t *testing.T) {
	public, private := testKey(t, 1)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	encoded, err := Sign(testPayload(t, LevelBehavioral, []string{"behavioral"}), time.Minute, now, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifier, err := NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verified, err := verifier.Verify(encoded, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Payload.AssuranceLevel != LevelBehavioral || verified.Payload.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected verified payload: %+v", verified.Payload)
	}
	if !verified.Satisfies(LevelBehavioral, false) || verified.Satisfies(LevelBehavioral, true) {
		t.Fatal("assurance minimum evaluated incorrectly")
	}
	if strings.Contains(string(encoded), "session-identifier-value") {
		t.Fatal("assertion leaked the raw session identifier")
	}
}

func TestSessionBindingIsUnlinkableAcrossAudiences(t *testing.T) {
	first, err := SessionBinding(testSecret, "session-identifier-value", "one.example")
	if err != nil {
		t.Fatalf("derive first binding: %v", err)
	}
	second, err := SessionBinding(testSecret, "session-identifier-value", "two.example")
	if err != nil {
		t.Fatalf("derive second binding: %v", err)
	}
	if first == second {
		t.Fatal("the same session produced a linkable binding across audiences")
	}
	repeated, err := SessionBinding(testSecret, "session-identifier-value", "one.example")
	if err != nil || repeated != first {
		t.Fatalf("session binding is not deterministic: %v %q", err, repeated)
	}
	if _, err := SessionBinding(testSecret[:8], "session-identifier-value", "one.example"); err == nil {
		t.Fatal("a short binding secret was accepted")
	}
}

func TestUnsupportedLevelsAreRefusedOnBothSides(t *testing.T) {
	public, private := testKey(t, 2)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	for level, sources := range map[int][]string{
		LevelInteractive:    {"behavioral", "challenge"},
		LevelAttestedDevice: {"behavioral", "challenge", "device"},
		LevelIssuerVerified: {"behavioral", "challenge", "device", "issuer"},
		LevelIssuerUnique:   {"behavioral", "challenge", "device", "issuer"},
	} {
		payload := testPayload(t, level, sources)
		if _, err := Sign(payload, time.Minute, now, private); err != ErrUnsupportedLevel {
			t.Fatalf("level %d was signable: %v", level, err)
		}
		// A deployment that raises the ceiling in its own build must still be
		// refused by an unmodified verifier.
		if _, err := verifier.Verify(forceSign(t, payload, time.Minute, now, private), now); err != ErrUnsupportedLevel {
			t.Fatalf("level %d was verifiable: %v", level, err)
		}
	}
}

func TestSupportedCeilingMatchesImplementedEvidence(t *testing.T) {
	// The ceiling is a claim about mechanisms, not a tunable. Raising it
	// requires a verifier for the added evidence class.
	if MaximumSupportedLevel != LevelBehavioral {
		t.Fatal("the supported ceiling changed without an implemented evidence class")
	}
	if MaximumSpecifiedLevel != LevelIssuerUnique {
		t.Fatal("the specified ladder no longer matches the protocol document")
	}
}

func TestVerifierRejectsTamperingBindingAndForeignSignatures(t *testing.T) {
	public, private := testKey(t, 3)
	_, otherPrivate := testKey(t, 4)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	valid, err := Sign(testPayload(t, LevelBehavioral, []string{"behavioral"}), time.Minute, now, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	for name, mutate := range map[string]func() []byte{
		"raised level after signing": func() []byte {
			return mutateDocument(t, valid, func(document map[string]any) {
				document["payload"].(map[string]any)["assurance_level"] = float64(LevelBehavioral)
				document["payload"].(map[string]any)["reason_codes"] = []any{"tampered_code"}
			})
		},
		"unknown field": func() []byte {
			return mutateDocument(t, valid, func(document map[string]any) { document["extra"] = true })
		},
		"unknown payload field": func() []byte {
			return mutateDocument(t, valid, func(document map[string]any) {
				document["payload"].(map[string]any)["subject"] = "person"
			})
		},
		"foreign signing key": func() []byte {
			return forceSign(t, testPayload(t, LevelBehavioral, []string{"behavioral"}), time.Minute, now, otherPrivate)
		},
		"foreign signature domain": func() []byte {
			return signWithDomain(t, testPayload(t, LevelBehavioral, []string{"behavioral"}), time.Minute, now, private,
				"PALISADE\x00LOCAL-ARTIFACT\x00V1\x00")
		},
		"truncated document": func() []byte { return valid[:len(valid)/2] },
		"empty document":     func() []byte { return nil },
	} {
		if _, err := verifier.Verify(mutate(), now); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	foreign, err := NewVerifier(public, "other.example")
	if err != nil {
		t.Fatalf("new foreign verifier: %v", err)
	}
	if _, err := foreign.Verify(valid, now); err != ErrInvalid {
		t.Fatalf("an assertion for another audience was accepted: %v", err)
	}
}

func TestValidityWindowFailsClosed(t *testing.T) {
	public, private := testKey(t, 5)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	encoded, err := Sign(testPayload(t, LevelBehavioral, []string{"behavioral"}), time.Minute, now, private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := verifier.Verify(encoded, now.Add(2*time.Minute)); err != ErrExpired {
		t.Fatalf("an expired assertion was accepted: %v", err)
	}
	if _, err := verifier.Verify(encoded, now.Add(-time.Hour)); err != ErrInvalid {
		t.Fatalf("an assertion from the future was accepted: %v", err)
	}
	if _, err := Sign(testPayload(t, LevelBehavioral, []string{"behavioral"}), MaximumLifetime+time.Second, now, private); err == nil {
		t.Fatal("an over-long lifetime was accepted")
	}
	if _, err := Sign(testPayload(t, LevelBehavioral, []string{"behavioral"}), 0, now, private); err == nil {
		t.Fatal("a zero lifetime was accepted")
	}
}

func TestMalformedPayloadsAreRejected(t *testing.T) {
	_, private := testKey(t, 6)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	missingSource := testPayload(t, LevelBehavioral, nil)
	if _, err := Sign(missingSource, time.Minute, now, private); err != ErrInvalid {
		t.Fatalf("a level without its required evidence class was signed: %v", err)
	}

	uniqueWithoutIssuer := testPayload(t, LevelBehavioral, []string{"behavioral"})
	uniqueWithoutIssuer.UniquenessScope = "issuer"
	if _, err := Sign(uniqueWithoutIssuer, time.Minute, now, private); err != ErrInvalid {
		t.Fatalf("uniqueness without an issuer evidence class was signed: %v", err)
	}

	uniqueWithoutDevice := testPayload(t, LevelBehavioral, []string{"behavioral"})
	uniqueWithoutDevice.UniquenessScope = "device"
	if _, err := Sign(uniqueWithoutDevice, time.Minute, now, private); err != ErrInvalid {
		t.Fatalf("device uniqueness without a device evidence class was signed: %v", err)
	}

	duplicateSource := testPayload(t, LevelBehavioral, []string{"behavioral", "behavioral"})
	if _, err := Sign(duplicateSource, time.Minute, now, private); err != ErrInvalid {
		t.Fatalf("a duplicated evidence class was signed: %v", err)
	}

	freeText := testPayload(t, LevelBehavioral, []string{"behavioral"})
	freeText.ReasonCodes = []string{"Not A Reason Code"}
	if _, err := Sign(freeText, time.Minute, now, private); err != ErrInvalid {
		t.Fatalf("free text passed as a reason code: %v", err)
	}

	badBinding := testPayload(t, LevelBehavioral, []string{"behavioral"})
	badBinding.Binding.SessionBinding = "short"
	if _, err := Sign(badBinding, time.Minute, now, private); err != ErrInvalid {
		t.Fatalf("a malformed session binding was signed: %v", err)
	}

	rawAction := testPayload(t, LevelBehavioral, []string{"behavioral"})
	rawAction.Binding.RequestAction = "GET /account?token=secret"
	if _, err := Sign(rawAction, time.Minute, now, private); err != ErrInvalid {
		t.Fatalf("a raw request value was accepted as an action class: %v", err)
	}
}

func TestConformanceSuiteMatchesImplementation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "conformance", "human-assurance-assertion-v1.json"))
	if err != nil {
		t.Fatalf("read conformance suite: %v", err)
	}
	var suite struct {
		SchemaVersion         string `json:"schema_version"`
		Contract              string `json:"contract"`
		SyntheticOnly         bool   `json:"synthetic_only"`
		SupportedLevelCeiling int    `json:"supported_level_ceiling"`
		SpecifiedLevelCeiling int    `json:"specified_level_ceiling"`
		Scenarios             []struct {
			ID       string   `json:"id"`
			Mutation string   `json:"mutation"`
			Level    int      `json:"level"`
			Sources  []string `json:"sources"`
			Expected string   `json:"expected"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("decode conformance suite: %v", err)
	}
	if suite.Contract != SchemaVersion || !suite.SyntheticOnly {
		t.Fatalf("conformance suite does not describe this contract: %+v", suite.Contract)
	}
	if suite.SupportedLevelCeiling != MaximumSupportedLevel || suite.SpecifiedLevelCeiling != MaximumSpecifiedLevel {
		t.Fatal("conformance suite ceilings disagree with the implementation")
	}
	if len(suite.Scenarios) == 0 {
		t.Fatal("conformance suite has no scenarios")
	}

	public, private := testKey(t, 7)
	_, otherPrivate := testKey(t, 8)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(public, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	for _, scenario := range suite.Scenarios {
		payload := testPayload(t, scenario.Level, scenario.Sources)
		evaluateAt := now.Add(time.Second)
		switch scenario.Mutation {
		case "none":
		case "drop_required_source":
			payload.AssuranceSources = nil
		case "uniqueness_without_source":
			payload.UniquenessScope = "issuer"
		case "other_audience":
			payload.Binding.Audience = "other.example"
		case "evaluate_after_expiry":
			evaluateAt = now.Add(2 * MaximumLifetime)
		case "evaluate_before_issue":
			evaluateAt = now.Add(-time.Hour)
		case "raise_level_after_signing", "other_signing_key", "foreign_domain_signature", "unknown_field":
		default:
			t.Fatalf("scenario %s uses an unknown mutation %q", scenario.ID, scenario.Mutation)
		}

		var encoded []byte
		switch scenario.Mutation {
		case "other_signing_key":
			encoded = forceSign(t, payload, time.Minute, now, otherPrivate)
		case "foreign_domain_signature":
			encoded = signWithDomain(t, payload, time.Minute, now, private, "PALISADE\x00LOCAL-ARTIFACT\x00V1\x00")
		case "raise_level_after_signing":
			encoded = mutateDocument(t, forceSign(t, payload, time.Minute, now, private), func(document map[string]any) {
				document["payload"].(map[string]any)["assurance_level"] = float64(LevelIssuerUnique)
			})
		case "unknown_field":
			encoded = mutateDocument(t, forceSign(t, payload, time.Minute, now, private), func(document map[string]any) {
				document["subject_identifier"] = "person"
			})
		default:
			encoded = forceSign(t, payload, time.Minute, now, private)
		}

		_, err := verifier.Verify(encoded, evaluateAt)
		got := "accepted"
		switch err {
		case nil:
		case ErrExpired:
			got = "expired"
		case ErrUnsupportedLevel:
			got = "unsupported_level"
		default:
			got = "invalid"
		}
		if got != scenario.Expected {
			t.Fatalf("scenario %s: expected %s, got %s (%v)", scenario.ID, scenario.Expected, got, err)
		}
	}
}

// forceSign produces a document without the emitter-side level ceiling so the
// verifier can be exercised against assertions a modified deployment might mint.
func forceSign(t *testing.T, payload Payload, ttl time.Duration, now time.Time, private ed25519.PrivateKey) []byte {
	t.Helper()
	return signWithDomain(t, payload, ttl, now, private, domainSeparator)
}

func signWithDomain(t *testing.T, payload Payload, ttl time.Duration, now time.Time, private ed25519.PrivateKey, domain string) []byte {
	t.Helper()
	issuedAt := now.UTC().Truncate(time.Second)
	payload.SchemaVersion = SchemaVersion
	payload.IssuedAt = issuedAt.Format(time.RFC3339)
	payload.ExpiresAt = issuedAt.Add(ttl).Format(time.RFC3339)
	if payload.Nonce == "" {
		payload.Nonce = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	message := append([]byte(domain), canonical...)
	document := Assertion{
		Payload:   payload,
		KeyID:     KeyID(private.Public().(ed25519.PublicKey)),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message)),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return encoded
}

func mutateDocument(t *testing.T, encoded []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	mutate(document)
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode mutated document: %v", err)
	}
	return mutated
}
