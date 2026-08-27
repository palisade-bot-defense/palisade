package shadowlog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func deriveKey(master []byte, domain string) []byte {
	mac := hmac.New(sha256.New, master)
	_, _ = mac.Write([]byte(domain))
	return mac.Sum(nil)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func keyIdentifier(key []byte) [8]byte {
	digest := sha256.Sum256(key)
	var identifier [8]byte
	copy(identifier[:], digest[:8])
	return identifier
}

func sessionKey(indexKey []byte, sessionID string) string {
	mac := hmac.New(sha256.New, indexKey)
	_, _ = mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
