package offlineimport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const classifierVersion = "closed-v2"

func endpointClass(target string) string {
	if cut := strings.IndexAny(target, "?#"); cut >= 0 {
		target = target[:cut]
	}
	if strings.HasPrefix(target, "/.within.website/") {
		return "anubis_worker"
	}
	parts := strings.Split(strings.Trim(target, "/"), "/")
	if len(parts) > 0 && parts[0] == "compare" {
		return "compare_index"
	}
	if len(parts) > 1 && parts[1] == "compare" {
		switch parts[0] {
		case "en", "de":
			return "compare_index"
		}
	}
	return "other_public"
}

func actionClass(method string) string {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return "read"
	case "POST", "PUT", "PATCH", "DELETE":
		return "write"
	default:
		return "other"
	}
}

func statusClass(status int) string {
	switch {
	case status >= 200 && status <= 299:
		return "success"
	case status >= 300 && status <= 399:
		return "redirect"
	case status >= 400 && status <= 499:
		return "client_error"
	case status >= 500 && status <= 599:
		return "server_error"
	default:
		return "unknown"
	}
}

func sizeBucket(size int64) int {
	switch {
	case size <= 0:
		return 0
	case size <= 1<<10:
		return 1
	case size <= 16<<10:
		return 2
	case size <= 256<<10:
		return 3
	default:
		return 4
	}
}

func weightBucket(weight float64) int {
	switch {
	case weight <= 0:
		return 0
	case weight < 0.25:
		return 1
	case weight < 0.5:
		return 2
	case weight < 0.75:
		return 3
	default:
		return 4
	}
}

func crowdSecReason(scenario string) string {
	switch strings.ToLower(strings.TrimSpace(scenario)) {
	case "crowdsecurity/http-bad-user-agent", "crowdsecurity/http-crawl-non_statics", "crowdsecurity/http-path-traversal-probing", "crowdsecurity/http-probing", "crowdsecurity/http-sensitive-files":
		return "crowdsec_http_abuse"
	case "crowdsecurity/http-generic-bf", "crowdsecurity/ssh-bf":
		return "crowdsec_credential_abuse"
	case "crowdsecurity/community-blocklist", "crowdsecurity/crowdsec-blacklists":
		return "crowdsec_reputation"
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

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

func normalizePeer(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return "", false
	}
	if peer, err := netip.ParseAddrPort(value); err == nil {
		address := peer.Addr()
		if address.Zone() != "" {
			return "", false
		}
		return address.Unmap().String(), true
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return "", false
	}
	return address.Unmap().String(), true
}

func parseStatus(value string) int {
	status, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return status
}
