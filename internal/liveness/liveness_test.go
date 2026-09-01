package liveness

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

var start = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

const (
	testSession  = "session-12345678"
	testAction   = "login"
	testEndpoint = "login"
)

// deterministicReader makes prompts and identifiers reproducible so tests
// assert behaviour rather than luck.
type deterministicReader struct{ value byte }

func (r *deterministicReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		r.value++
		buffer[index] = r.value
	}
	return len(buffer), nil
}

func newService(t *testing.T, rounds int) *Service {
	t.Helper()
	service, err := New(Config{
		Secret: []byte("liveness-attestation-secret-32-bytes"),
		Rounds: rounds,
		Random: &deterministicReader{},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

// solve answers every round at a plausible human pace and returns the
// attestation from the final round.
func solve(t *testing.T, service *Service, pace time.Duration) string {
	t.Helper()
	id, prompt, err := service.Begin(testSession, testAction, testEndpoint, start)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	now := start
	for {
		now = now.Add(pace)
		progress, err := service.Answer(id, testSession, prompt.Target, prompt.Round, now)
		if err != nil {
			t.Fatalf("round %d: %v", prompt.Round, err)
		}
		if progress.Completed {
			return progress.Attestation
		}
		prompt = *progress.Next
	}
}

func TestCompletedAttemptProducesABoundAttestation(t *testing.T) {
	service := newService(t, DefaultRounds)
	attestation := solve(t, service, time.Second)
	if attestation == "" {
		t.Fatal("a completed attempt produced no attestation")
	}
	if err := service.VerifyAttestation(attestation, testSession, testAction, testEndpoint, start.Add(5*time.Second)); err != nil {
		t.Fatalf("the attestation did not verify: %v", err)
	}
	// The attempt is consumed on completion, so it cannot be replayed.
	if service.Open() != 0 {
		t.Fatalf("a completed attempt was left open: %d", service.Open())
	}
}

func TestAttestationIsBoundToItsSessionActionAndEndpoint(t *testing.T) {
	service := newService(t, DefaultRounds)
	attestation := solve(t, service, time.Second)
	at := start.Add(5 * time.Second)

	for name, args := range map[string][3]string{
		"another session":  {"session-87654321", testAction, testEndpoint},
		"another action":   {testSession, "checkout", testEndpoint},
		"another endpoint": {testSession, testAction, "checkout"},
	} {
		if err := service.VerifyAttestation(attestation, args[0], args[1], args[2], at); err != ErrAttestation {
			t.Fatalf("%s accepted the attestation: %v", name, err)
		}
	}
}

func TestAttestationExpiresAndCannotBeForged(t *testing.T) {
	service := newService(t, DefaultRounds)
	attestation := solve(t, service, time.Second)

	if err := service.VerifyAttestation(attestation, testSession, testAction, testEndpoint,
		start.Add(AttestationTTL+time.Minute)); err != ErrAttestation {
		t.Fatal("an expired attestation was accepted")
	}
	for name, forged := range map[string]string{
		"empty":       "",
		"not base64":  "!!!!",
		"truncated":   attestation[:len(attestation)-6],
		"flipped bit": strings.Replace(attestation, string(attestation[0]), "Z", 1),
	} {
		if err := service.VerifyAttestation(forged, testSession, testAction, testEndpoint, start.Add(time.Second)); err != ErrAttestation {
			t.Fatalf("%s attestation was accepted", name)
		}
	}

	// A different deployment secret must not verify another's attestation.
	other, err := New(Config{
		Secret: []byte("a-different-deployment-secret-32bytes"),
		Random: &deterministicReader{},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if err := other.VerifyAttestation(attestation, testSession, testAction, testEndpoint, start.Add(time.Second)); err != ErrAttestation {
		t.Fatal("an attestation verified under another deployment secret")
	}
}

func TestPromptsAreRevealedOneAtATime(t *testing.T) {
	service := newService(t, DefaultRounds)
	id, first, err := service.Begin(testSession, testAction, testEndpoint, start)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Answering a later round before its prompt exists must fail: an attempt
	// cannot be solved ahead of time.
	if _, err := service.Answer(id, testSession, first.Target, 1, start.Add(time.Second)); err != ErrRoundOutOfOrder {
		t.Fatalf("an out-of-order round was accepted: %v", err)
	}
}

func TestATooFastAnswerIsRefused(t *testing.T) {
	service := newService(t, DefaultRounds)
	id, prompt, err := service.Begin(testSession, testAction, testEndpoint, start)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// A response that precedes the human reaction floor did not react to a
	// prompt that was only just revealed.
	if _, err := service.Answer(id, testSession, prompt.Target, 0, start.Add(MinimumResponse/2)); err != ErrTooFast {
		t.Fatalf("an instant answer was accepted: %v", err)
	}
}

func TestUnhurriedAnswersAreAccepted(t *testing.T) {
	// Assistive technology, a screen reader announcing options, and simply
	// thinking all take time. A slow but in-window pace must pass, or the
	// challenge excludes the people it is meant to serve.
	service := newService(t, DefaultRounds)
	if attestation := solve(t, service, MaximumResponse-time.Second); attestation == "" {
		t.Fatal("an unhurried but in-window attempt did not complete")
	}
}

func TestALateAnswerEndsTheAttempt(t *testing.T) {
	service := newService(t, DefaultRounds)
	id, prompt, err := service.Begin(testSession, testAction, testEndpoint, start)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := service.Answer(id, testSession, prompt.Target, 0, start.Add(MaximumResponse+time.Second)); err != ErrExpired {
		t.Fatalf("a late answer was accepted: %v", err)
	}
	if _, err := service.Answer(id, testSession, prompt.Target, 0, start.Add(time.Second)); err != ErrNotOpen {
		t.Fatalf("a failed attempt stayed open: %v", err)
	}
}

func TestAWrongAnswerEndsTheAttemptWithoutRetry(t *testing.T) {
	// Retrying inside one attempt would let a client search the option space,
	// so a wrong answer must end it rather than cost one of several tries.
	service := newService(t, DefaultRounds)
	id, prompt, err := service.Begin(testSession, testAction, testEndpoint, start)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	wrong := ""
	for _, option := range prompt.Options {
		if option != prompt.Target {
			wrong = option
			break
		}
	}
	if _, err := service.Answer(id, testSession, wrong, 0, start.Add(time.Second)); err != ErrWrongAnswer {
		t.Fatalf("a wrong answer was accepted: %v", err)
	}
	if _, err := service.Answer(id, testSession, prompt.Target, 0, start.Add(2*time.Second)); err != ErrNotOpen {
		t.Fatalf("the attempt allowed a retry: %v", err)
	}
}

func TestAnotherSessionCannotAnswerOrRelay(t *testing.T) {
	service := newService(t, DefaultRounds)
	id, prompt, err := service.Begin(testSession, testAction, testEndpoint, start)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := service.Answer(id, "session-87654321", prompt.Target, 0, start.Add(time.Second)); err != ErrInvalid {
		t.Fatalf("another session answered the attempt: %v", err)
	}
}

func TestExpiredAttemptsAreSweptAndCapacityIsBounded(t *testing.T) {
	service := newService(t, DefaultRounds)
	if _, _, err := service.Begin(testSession, testAction, testEndpoint, start); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if service.Open() != 1 {
		t.Fatalf("open attempts = %d", service.Open())
	}
	if removed := service.Sweep(start.Add(MaximumTotal + time.Second)); removed != 1 {
		t.Fatalf("swept %d attempts", removed)
	}
	if service.Open() != 0 {
		t.Fatal("an expired attempt survived the sweep")
	}

	bounded, err := New(Config{
		Secret: []byte("liveness-attestation-secret-32-bytes"), MaxEntries: 1, Random: &deterministicReader{}})
	if err != nil {
		t.Fatalf("new bounded service: %v", err)
	}
	if _, _, err := bounded.Begin(testSession, testAction, testEndpoint, start); err != nil {
		t.Fatalf("first begin: %v", err)
	}
	if _, _, err := bounded.Begin("session-87654321", testAction, testEndpoint, start); err != ErrCapacity {
		t.Fatalf("the capacity bound was not enforced: %v", err)
	}
}

func TestGuessingCostGrowsWithRounds(t *testing.T) {
	// A single round is a one-in-Options guess. The point of several rounds is
	// that the cost compounds, and that each one must be answered live.
	service := newService(t, DefaultRounds)
	id, prompt, err := service.Begin(testSession, testAction, testEndpoint, start)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if len(prompt.Options) != Options {
		t.Fatalf("prompt offered %d options", len(prompt.Options))
	}
	seen := map[string]struct{}{}
	for _, option := range prompt.Options {
		if _, duplicate := seen[option]; duplicate {
			t.Fatal("a prompt repeated an option, which shrinks the option space")
		}
		seen[option] = struct{}{}
	}
	if _, present := seen[prompt.Target]; !present {
		t.Fatal("the target is not among the offered options")
	}
	_ = id
}

func TestConfigurationIsValidated(t *testing.T) {
	for name, config := range map[string]Config{
		"no secret":    {},
		"short secret": {Secret: []byte("short")},
		"too many rounds": {
			Secret: []byte("liveness-attestation-secret-32-bytes"), Rounds: 9},
	} {
		if _, err := New(config); err != ErrInvalid {
			t.Fatalf("%s was accepted", name)
		}
	}
	service, err := New(Config{Secret: []byte("liveness-attestation-secret-32-bytes")})
	if err != nil {
		t.Fatalf("default configuration: %v", err)
	}
	if _, _, err := service.Begin("short", testAction, testEndpoint, start); err != ErrInvalid {
		t.Fatalf("a short session was accepted: %v", err)
	}
}

func TestPromptCarriesNoSubjectData(t *testing.T) {
	service := newService(t, DefaultRounds)
	_, prompt, err := service.Begin(testSession, testAction, testEndpoint, start)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for _, option := range append(prompt.Options, prompt.Target) {
		if bytes.Contains([]byte(option), []byte(testSession)) {
			t.Fatal("a prompt option embedded the session identifier")
		}
	}
}
