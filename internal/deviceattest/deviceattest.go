// Package deviceattest verifies that a registered, device-bound credential
// signed a fresh challenge PALISADE issued for this session.
//
// # What this verifies, and what it deliberately does not
//
// It verifies a WebAuthn authentication assertion: that the holder of a
// registered credential produced a signature over a challenge this deployment
// issued, for this relying party and origin, with the user-presence flag set.
// That is evidence the private key lives on hardware the person has, and that
// it was exercised now rather than replayed.
//
// It does not verify an attestation statement. Deciding which vendor made an
// authenticator means parsing packed, TPM, Android-key and Apple attestation
// formats and maintaining vendor root certificates, and a partial
// implementation of that is worse than none: it would report a provenance it
// had not actually checked. Registration, including any attestation-statement
// validation a deployment wants, happens outside PALISADE. PALISADE receives
// only the resulting credential — an identifier and a public key — through a
// signed local artifact, in the same verify-never-issue shape as the issuer
// trust list.
//
// So a successful verification means "a credential this deployment registered
// was used, live, here". It does not mean "a genuine YubiKey" and it does not
// mean "a human": possession of a device is not presence of a person, which is
// why device evidence sits above interaction evidence in the ladder rather than
// replacing it.
//
// Nor does it always mean one device. A synced passkey — what most people
// actually have — lives on every device signed into that account, and the
// backup-eligible flag in the assertion says so. Result reports it, and a
// deployment that reads "device-bound" literally can require otherwise through
// the policy. Left off, which is the default, the ceremony evidences possession
// of an account's credential rather than of one particular device. That
// distinction stayed invisible until a real platform authenticator was put
// through this path.
package deviceattest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"time"
)

const (
	// authenticatorDataMinimum is the fixed prefix every assertion carries:
	// a 32-byte relying-party hash, one flags byte and a four-byte counter.
	authenticatorDataMinimum = 37

	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	// flagBackupEligible marks a credential the authenticator may copy off this
	// device — a synced passkey. Such a credential is not device-bound, whatever
	// the ceremony proves about possession right now.
	flagBackupEligible = 0x08
	// flagBackedUp marks a credential that currently exists somewhere else too.
	flagBackedUp = 0x10

	// MaximumClientDataBytes bounds the JSON the client controls.
	MaximumClientDataBytes = 8 << 10
	// MaximumAssertionBytes bounds each binary field.
	MaximumAssertionBytes = 8 << 10

	expectedType = "webauthn.get"
)

var (
	// ErrInvalid covers every structural and vocabulary failure.
	ErrInvalid = errors.New("invalid device assertion")
	// ErrSignature reports a signature that did not verify.
	ErrSignature = errors.New("device assertion signature did not verify")
	// ErrChallenge reports a challenge that was not the one issued, or a
	// relying party or origin the deployment does not accept.
	ErrChallenge = errors.New("device assertion answered the wrong challenge")
	// ErrPresence reports an assertion the authenticator produced without the
	// user actually touching it.
	ErrPresence = errors.New("device assertion lacks user presence")
	// ErrReplay reports a signature counter that did not advance.
	ErrReplay = errors.New("device assertion counter did not advance")
	// ErrNotDeviceBound reports a credential the authenticator may sync to other
	// devices, presented where the deployment requires a device-bound one.
	ErrNotDeviceBound = errors.New("device credential is not bound to one device")
)

// Algorithm names the signature algorithms this package verifies. Both are
// modern and unambiguous; older RSA suites are deliberately absent rather than
// half-supported.
type Algorithm string

const (
	// ES256 is ECDSA over P-256 with SHA-256, the WebAuthn default.
	ES256 Algorithm = "es256"
	// EdDSA is Ed25519.
	EdDSA Algorithm = "eddsa"
)

// Credential is a registered device-bound credential. PALISADE never creates
// one: a deployment registers it elsewhere and supplies it, so the public key
// here has already been through whatever attestation policy that deployment
// chose to apply.
type Credential struct {
	// ID is the credential identifier, base64url encoded.
	ID string
	// Algorithm is the signature algorithm the public key uses.
	Algorithm Algorithm
	// PublicKey is the raw public key: an uncompressed P-256 point for ES256,
	// or a 32-byte Ed25519 key.
	PublicKey []byte
	// SignCount is the last counter value seen, or zero when the authenticator
	// does not keep one.
	SignCount uint32
}

// Policy is what a deployment requires of an assertion.
type Policy struct {
	// RelyingPartyID is the registrable domain the credential is scoped to.
	RelyingPartyID string
	// Origin is the exact origin the ceremony must have run on.
	Origin string
	// RequireUserVerification demands that the authenticator verified the
	// person, not merely their presence. It is off by default: requiring a PIN
	// or biometric raises assurance but excludes authenticators that cannot do
	// it, which is an accessibility budget rather than a free improvement.
	RequireUserVerification bool
	// RequireDeviceBound refuses a credential the authenticator may sync to
	// other devices. It is off by default because synced passkeys are what most
	// people actually have and refusing them excludes almost everyone; but a
	// deployment that reads "device-bound" literally must turn it on, because
	// without it the ceremony proves possession of an account's credential
	// rather than of one device.
	RequireDeviceBound bool
}

// Assertion is what the client returns from an authentication ceremony.
type Assertion struct {
	CredentialID      string
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// Result reports a verified assertion.
type Result struct {
	CredentialID string
	// UserVerified reports whether the authenticator verified the person rather
	// than only their presence.
	UserVerified bool
	// BackupEligible reports that the authenticator may copy this credential to
	// other devices. When it is true the credential is not device-bound: the
	// ceremony shows someone holds the account's credential, which may live on
	// several devices at once.
	BackupEligible bool
	// BackedUp reports that the credential currently exists elsewhere as well.
	BackedUp bool
	// SignCount is the counter this assertion carried, for the caller to store.
	SignCount uint32
	// VerifiedAt is the time the verification was performed.
	VerifiedAt time.Time
}

// clientData is the subset of the ceremony's client data this package reads.
// Unknown fields are tolerated because the browser owns this structure, but
// every field that matters is checked.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// Verify checks one assertion against a registered credential, a deployment
// policy and the exact challenge PALISADE issued.
//
// The challenge must be the one this deployment minted for this session,
// action and endpoint class. Verifying a signature over an attacker-chosen
// challenge would prove only that a key exists somewhere, not that it was used
// here and now.
func Verify(
	assertion Assertion,
	credential Credential,
	policy Policy,
	issuedChallenge []byte,
	now time.Time,
) (Result, error) {
	if policy.RelyingPartyID == "" || policy.Origin == "" || len(issuedChallenge) < 16 {
		return Result{}, ErrInvalid
	}
	if len(assertion.AuthenticatorData) < authenticatorDataMinimum ||
		len(assertion.AuthenticatorData) > MaximumAssertionBytes ||
		len(assertion.ClientDataJSON) == 0 || len(assertion.ClientDataJSON) > MaximumClientDataBytes ||
		len(assertion.Signature) == 0 || len(assertion.Signature) > MaximumAssertionBytes {
		return Result{}, ErrInvalid
	}
	if subtle.ConstantTimeCompare([]byte(assertion.CredentialID), []byte(credential.ID)) != 1 {
		return Result{}, ErrInvalid
	}

	var data clientData
	if err := json.Unmarshal(assertion.ClientDataJSON, &data); err != nil {
		return Result{}, ErrInvalid
	}
	if data.Type != expectedType {
		// A registration ceremony's client data must never be accepted as an
		// authentication: the two prove different things.
		return Result{}, ErrChallenge
	}
	challenge, err := base64.RawURLEncoding.DecodeString(data.Challenge)
	if err != nil || subtle.ConstantTimeCompare(challenge, issuedChallenge) != 1 {
		return Result{}, ErrChallenge
	}
	if subtle.ConstantTimeCompare([]byte(data.Origin), []byte(policy.Origin)) != 1 {
		return Result{}, ErrChallenge
	}

	relyingPartyHash := sha256.Sum256([]byte(policy.RelyingPartyID))
	if subtle.ConstantTimeCompare(assertion.AuthenticatorData[:32], relyingPartyHash[:]) != 1 {
		return Result{}, ErrChallenge
	}
	flags := assertion.AuthenticatorData[32]
	if flags&flagUserPresent == 0 {
		return Result{}, ErrPresence
	}
	userVerified := flags&flagUserVerified != 0
	if policy.RequireUserVerification && !userVerified {
		return Result{}, ErrPresence
	}
	backupEligible := flags&flagBackupEligible != 0
	if policy.RequireDeviceBound && backupEligible {
		return Result{}, ErrNotDeviceBound
	}

	signCount := uint32(assertion.AuthenticatorData[33])<<24 |
		uint32(assertion.AuthenticatorData[34])<<16 |
		uint32(assertion.AuthenticatorData[35])<<8 |
		uint32(assertion.AuthenticatorData[36])
	// A counter that goes backwards means the credential was cloned. A counter
	// that stays at zero means the authenticator keeps none, which is allowed.
	if signCount != 0 && signCount <= credential.SignCount {
		return Result{}, ErrReplay
	}

	clientDataHash := sha256.Sum256(assertion.ClientDataJSON)
	signed := make([]byte, 0, len(assertion.AuthenticatorData)+len(clientDataHash))
	signed = append(signed, assertion.AuthenticatorData...)
	signed = append(signed, clientDataHash[:]...)

	if err := verifySignature(credential, signed, assertion.Signature); err != nil {
		return Result{}, err
	}
	return Result{
		CredentialID:   credential.ID,
		UserVerified:   userVerified,
		BackupEligible: backupEligible,
		BackedUp:       flags&flagBackedUp != 0,
		SignCount:      signCount,
		VerifiedAt:     now.UTC(),
	}, nil
}

func verifySignature(credential Credential, signed, signature []byte) error {
	switch credential.Algorithm {
	case ES256:
		key, err := parseP256(credential.PublicKey)
		if err != nil {
			return err
		}
		var parsed struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil ||
			parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
			return ErrSignature
		}
		digest := sha256.Sum256(signed)
		if !ecdsa.Verify(key, digest[:], parsed.R, parsed.S) {
			return ErrSignature
		}
		return nil
	case EdDSA:
		if len(credential.PublicKey) != ed25519.PublicKeySize {
			return ErrInvalid
		}
		if !ed25519.Verify(ed25519.PublicKey(credential.PublicKey), signed, signature) {
			return ErrSignature
		}
		return nil
	default:
		// An unknown algorithm is refused rather than skipped. Falling through
		// to "no signature check" is how a verifier becomes decoration.
		return ErrInvalid
	}
}

func parseP256(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 65 || raw[0] != 4 {
		return nil, ErrInvalid
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:])
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		// A point off the curve is not a key. Accepting one invites invalid
		// curve attacks against the verification itself.
		return nil, ErrInvalid
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
