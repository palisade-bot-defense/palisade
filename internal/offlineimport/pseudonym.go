package offlineimport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

type pseudonymizer struct {
	domainKey []byte
	domainID  string
}

func newPseudonymizer(key []byte, datasetID, pilotID string) *pseudonymizer {
	mac := hmac.New(sha256.New, key)
	writeKDFField(mac, "palisade:offline:v2:domain")
	writeKDFField(mac, datasetID)
	writeKDFField(mac, pilotID)
	domainKey := mac.Sum(nil)
	digest := sha256.Sum256(domainKey)
	return &pseudonymizer{domainKey: domainKey, domainID: base64.RawURLEncoding.EncodeToString(digest[:12])}
}

func (p *pseudonymizer) Wipe() { wipe(p.domainKey) }

func validPseudonym(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func (p *pseudonymizer) pseudonym(kind string, observedAt time.Time, subject, userAgent string) string {
	day := observedAt.UTC().Format("2006-01-02")
	derive := hmac.New(sha256.New, p.domainKey)
	writeKDFField(derive, "palisade:offline:v2:day")
	writeKDFField(derive, day)
	dayKey := derive.Sum(nil)
	defer wipe(dayKey)

	mac := hmac.New(sha256.New, dayKey)
	writeKDFField(mac, kind)
	writeKDFField(mac, subject)
	if kind == "session" {
		writeKDFField(mac, userAgent)
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func writeKDFField(mac interface{ Write([]byte) (int, error) }, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write([]byte(value))
}
