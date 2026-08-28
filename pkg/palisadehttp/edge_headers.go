package palisadehttp

import (
	"net/http"
	"strings"
)

const (
	TrustedEdgeFingerprintClassHeader  = "X-Palisade-Edge-Fingerprint-Class"
	TrustedEdgeFingerprintMethodHeader = "X-Palisade-Edge-Fingerprint-Method"
	TrustedNetworkReputationHeader     = "X-Palisade-Network-Reputation"
	TrustedNetworkTypeHeader           = "X-Palisade-Network-Type"
	maxTrustedEdgeHeaderBytes          = 64
)

type edgeHeaderNormalizer struct {
	enabled   bool
	transport transportNormalizer
}

type normalizedEdgeHeaders struct {
	fingerprintClass  string
	fingerprintMethod string
	networkReputation string
	networkType       string
}

func newEdgeHeaderNormalizer(config Config, transport transportNormalizer) (edgeHeaderNormalizer, error) {
	if config.TrustedEdgeHeaders && len(transport.trustedProxies) == 0 {
		return edgeHeaderNormalizer{}, ErrInvalidConfig
	}
	return edgeHeaderNormalizer{enabled: config.TrustedEdgeHeaders, transport: transport}, nil
}

func (n edgeHeaderNormalizer) normalize(request *http.Request) (normalizedEdgeHeaders, error) {
	result := normalizedEdgeHeaders{
		fingerprintClass:  "unknown",
		fingerprintMethod: "unknown",
		networkReputation: "unknown",
		networkType:       "unknown",
	}
	if !n.enabled {
		return result, nil
	}
	peer, ok := parsePeer(request.RemoteAddr)
	if !ok || !n.transport.contains(peer) {
		return result, nil
	}

	var err error
	if result.fingerprintClass, err = closedEdgeHeader(request, TrustedEdgeFingerprintClassHeader,
		"unknown", "browser_consistent", "automation_consistent", "anomalous"); err != nil {
		return normalizedEdgeHeaders{}, err
	}
	if result.fingerprintMethod, err = closedEdgeHeader(request, TrustedEdgeFingerprintMethodHeader,
		"unknown", "tls", "http2", "tls_http2"); err != nil {
		return normalizedEdgeHeaders{}, err
	}
	if result.networkReputation, err = closedEdgeHeader(request, TrustedNetworkReputationHeader,
		"unknown", "low_risk", "elevated_risk", "high_risk"); err != nil {
		return normalizedEdgeHeaders{}, err
	}
	if result.networkType, err = closedEdgeHeader(request, TrustedNetworkTypeHeader,
		"unknown", "residential", "mobile", "hosting", "enterprise", "education", "anonymizer"); err != nil {
		return normalizedEdgeHeaders{}, err
	}
	classKnown := result.fingerprintClass != "unknown"
	methodKnown := result.fingerprintMethod != "unknown"
	if classKnown != methodKnown {
		return normalizedEdgeHeaders{}, ErrInvalidSignals
	}
	return result, nil
}

func closedEdgeHeader(request *http.Request, name string, allowed ...string) (string, error) {
	values := request.Header.Values(name)
	if len(values) == 0 {
		return "unknown", nil
	}
	if len(values) != 1 || len(values[0]) > maxTrustedEdgeHeaderBytes || strings.ContainsAny(values[0], ",\r\n\x00") {
		return "", ErrInvalidSignals
	}
	value := strings.ToLower(strings.TrimSpace(values[0]))
	if value == "" || !oneOf(value, allowed...) {
		return "", ErrInvalidSignals
	}
	return value, nil
}
