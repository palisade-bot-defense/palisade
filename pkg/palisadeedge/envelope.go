// Package palisadeedge verifies vendor-neutral, locally signed upstream signal
// envelopes. The envelope contains only PALISADE's closed normalized classes;
// raw addresses, fingerprints, headers and provider payloads are outside this
// package's wire contract.
package palisadeedge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/palisade-human-trust/palisade/pkg/palisadecontract"
)

const (
	Version         = "palisade.edge-signals.v1"
	PayloadHeader   = "X-Palisade-Edge-Signals"
	SignatureHeader = "X-Palisade-Edge-Signature"

	DefaultMaxAge     = 30 * time.Second
	DefaultFutureSkew = 5 * time.Second
	DefaultMaxNonces  = 100_000
	maximumPayload    = 2048
	maximumCIDRs      = 64
)

var (
	ErrInvalidConfig   = errors.New("invalid PALISADE edge-signal configuration")
	ErrInvalidEnvelope = errors.New("invalid PALISADE edge-signal envelope")
	ErrReplay          = errors.New("replayed PALISADE edge-signal envelope")
)

// Signals contains only request-time upstream context. Delayed ground-truth
// outcomes remain linked through POST /v1/outcome rather than this envelope.
type Signals struct {
	ChallengeVerdict      string  `json:"challenge_verdict,omitempty"`
	ExternalRiskScore     float64 `json:"external_risk_score,omitempty"`
	PolicyAlert           bool    `json:"policy_alert,omitempty"`
	EdgeFingerprintClass  string  `json:"edge_fingerprint_class,omitempty"`
	EdgeFingerprintMethod string  `json:"edge_fingerprint_method,omitempty"`
	NetworkReputation     string  `json:"network_reputation,omitempty"`
	NetworkType           string  `json:"network_type,omitempty"`
}

type envelope struct {
	Version  string  `json:"version"`
	IssuedAt int64   `json:"issued_at"`
	Nonce    string  `json:"nonce"`
	Signals  Signals `json:"signals"`
}

type VerifierConfig struct {
	Key              []byte
	TrustedPeerCIDRs []string
	MaxAge           time.Duration
	FutureSkew       time.Duration
	MaxNonces        int
}

type nonceEntry struct{ expires time.Time }

type Verifier struct {
	key        []byte
	peers      []netip.Prefix
	maxAge     time.Duration
	futureSkew time.Duration
	maxNonces  int
	now        func() time.Time
	mu         sync.Mutex
	nonces     map[[sha256.Size]byte]nonceEntry
}

func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if !validKey(config.Key) || len(config.TrustedPeerCIDRs) == 0 || len(config.TrustedPeerCIDRs) > maximumCIDRs {
		return nil, ErrInvalidConfig
	}
	if config.MaxAge == 0 {
		config.MaxAge = DefaultMaxAge
	}
	if config.FutureSkew == 0 {
		config.FutureSkew = DefaultFutureSkew
	}
	if config.MaxNonces == 0 {
		config.MaxNonces = DefaultMaxNonces
	}
	if config.MaxAge < time.Second || config.MaxAge > 5*time.Minute || config.FutureSkew < time.Second || config.FutureSkew > time.Minute ||
		config.MaxNonces < 1 || config.MaxNonces > 1_000_000 {
		return nil, ErrInvalidConfig
	}
	verifier := &Verifier{
		key: append([]byte(nil), config.Key...), maxAge: config.MaxAge, futureSkew: config.FutureSkew,
		maxNonces: config.MaxNonces, now: time.Now, nonces: make(map[[sha256.Size]byte]nonceEntry),
	}
	for _, raw := range config.TrustedPeerCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !validPrefix(prefix) || prefix != prefix.Masked() {
			return nil, ErrInvalidConfig
		}
		for _, existing := range verifier.peers {
			if existing.Contains(prefix.Addr()) || prefix.Contains(existing.Addr()) {
				return nil, ErrInvalidConfig
			}
		}
		verifier.peers = append(verifier.peers, prefix)
	}
	return verifier, nil
}

// Verify ignores spoofed headers from an untrusted direct peer. Once the peer
// is trusted, a missing envelope remains neutral while partial or invalid
// envelope data is a fail-closed integration error.
func (v *Verifier) Verify(request *http.Request) (Signals, bool, error) {
	if request == nil {
		return Signals{}, false, ErrInvalidEnvelope
	}
	payloadValues := request.Header.Values(PayloadHeader)
	signatureValues := request.Header.Values(SignatureHeader)
	peer, peerOK := parsePeer(request.RemoteAddr)
	if !peerOK || !v.trusted(peer) {
		return Signals{}, false, nil
	}
	if len(payloadValues) == 0 && len(signatureValues) == 0 {
		return Signals{}, false, nil
	}
	if len(payloadValues) != 1 || len(signatureValues) != 1 || len(signatureValues[0]) != base64.RawURLEncoding.EncodedLen(sha256.Size) || strings.ContainsAny(payloadValues[0], "\r\n, ") ||
		strings.ContainsAny(signatureValues[0], "\r\n, ") || len(payloadValues[0]) > base64.RawURLEncoding.EncodedLen(maximumPayload) {
		return Signals{}, false, ErrInvalidEnvelope
	}
	raw, err := base64.RawURLEncoding.DecodeString(payloadValues[0])
	if err != nil || len(raw) == 0 || len(raw) > maximumPayload {
		return Signals{}, false, ErrInvalidEnvelope
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureValues[0])
	if err != nil || len(signature) != sha256.Size || !hmac.Equal(signature, signatureFor(v.key, raw)) {
		return Signals{}, false, ErrInvalidEnvelope
	}
	parsed, err := decodeEnvelope(raw)
	if err != nil {
		return Signals{}, false, err
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return Signals{}, false, ErrInvalidEnvelope
	}
	now := v.now().UTC()
	issuedAt := time.Unix(parsed.IssuedAt, 0).UTC()
	if parsed.Version != Version || parsed.IssuedAt < 0 || issuedAt.After(now.Add(v.futureSkew)) || now.Sub(issuedAt) > v.maxAge {
		return Signals{}, false, ErrInvalidEnvelope
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parsed.Nonce)
	if err != nil || len(nonce) != 16 || !validSignals(parsed.Signals) {
		return Signals{}, false, ErrInvalidEnvelope
	}
	if err := v.consumeNonce(nonce, now, issuedAt.Add(v.maxAge+v.futureSkew)); err != nil {
		return Signals{}, false, err
	}
	return parsed.Signals, true, nil
}

// Sign creates the two exact header values for a normalized per-request
// envelope. Nonce must contain 16 cryptographically random bytes and must not
// be reused with the same verifier population.
func Sign(key []byte, issuedAt time.Time, nonce [16]byte, signals Signals) (payload, signature string, err error) {
	if !validKey(key) || issuedAt.IsZero() || issuedAt.Unix() < 0 || issuedAt.Nanosecond() != 0 || !validSignals(signals) {
		return "", "", ErrInvalidEnvelope
	}
	value := envelope{
		Version: Version, IssuedAt: issuedAt.UTC().Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), Signals: signals,
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maximumPayload {
		return "", "", ErrInvalidEnvelope
	}
	return base64.RawURLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(signatureFor(key, raw)), nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return ErrInvalidEnvelope
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return ErrInvalidEnvelope
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return ErrInvalidEnvelope
			}
		default:
			return ErrInvalidEnvelope
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidEnvelope
	}
	return nil
}

func decodeEnvelope(raw []byte) (envelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value envelope
	if err := decoder.Decode(&value); err != nil {
		return envelope{}, ErrInvalidEnvelope
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return envelope{}, ErrInvalidEnvelope
	}
	return value, nil
}

func validSignals(value Signals) bool {
	if math.IsNaN(value.ExternalRiskScore) || math.IsInf(value.ExternalRiskScore, 0) || value.ExternalRiskScore < 0 || value.ExternalRiskScore > 1 ||
		!palisadecontract.ValidOptionalUnknownClass(value.ChallengeVerdict, palisadecontract.ValidChallengeVerdict) ||
		!palisadecontract.ValidEdgeIntelligence(value.EdgeFingerprintClass, value.EdgeFingerprintMethod, value.NetworkReputation, value.NetworkType) {
		return false
	}
	known := func(value string) bool { return value != "" && value != "unknown" }
	return value.PolicyAlert || value.ExternalRiskScore > 0 || known(value.ChallengeVerdict) || known(value.EdgeFingerprintClass) ||
		known(value.NetworkReputation) || known(value.NetworkType)
}

func validKey(key []byte) bool {
	return len(key) >= 32 && len(key) <= 4096
}

func signatureFor(key, raw []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("palisade:edge-signals:v1\x00"))
	_, _ = mac.Write(raw)
	return mac.Sum(nil)
}

func validPrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	if !prefix.IsValid() || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if address.Is4() {
		return prefix.Bits() >= 8
	}
	return address.Is6() && prefix.Bits() >= 16
}

func parsePeer(value string) (netip.Addr, bool) {
	if address, err := netip.ParseAddrPort(value); err == nil {
		return address.Addr().Unmap(), address.Addr().Zone() == ""
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func (v *Verifier) trusted(address netip.Addr) bool {
	for _, prefix := range v.peers {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (v *Verifier) consumeNonce(nonce []byte, now, expires time.Time) error {
	digest := sha256.Sum256(nonce)
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.nonces) >= v.maxNonces {
		for key, entry := range v.nonces {
			if !entry.expires.After(now) {
				delete(v.nonces, key)
			}
		}
	}
	if _, exists := v.nonces[digest]; exists {
		return ErrReplay
	}
	if len(v.nonces) >= v.maxNonces {
		return fmt.Errorf("%w: nonce capacity exceeded", ErrInvalidEnvelope)
	}
	v.nonces[digest] = nonceEntry{expires: expires}
	return nil
}
