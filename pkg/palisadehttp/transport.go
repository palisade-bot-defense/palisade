package palisadehttp

import (
	"net/http"
	"net/netip"
	"strings"
)

const maxTrustedProxyCIDRs = 64

const (
	TransportProtocolHTTP1   = "http1"
	TransportProtocolHTTP2   = "http2"
	TransportProtocolHTTP3   = "http3"
	TransportProtocolUnknown = "unknown"

	TransportSecurityDirectTLS       = "direct_tls"
	TransportSecurityTrustedProxyTLS = "trusted_proxy_tls"
	TransportSecurityPlaintext       = "plaintext"
	TransportSecurityUnknown         = "unknown"

	ClientAddressSourceDirect              = "direct"
	ClientAddressSourceTrustedProxy        = "trusted_proxy"
	ClientAddressSourceInvalidTrustedProxy = "invalid_trusted_proxy"
	ClientAddressSourceUnknown             = "unknown"
)

type transportNormalizer struct {
	trustedProxies []netip.Prefix
	clientIPHeader string
	protoHeader    string
}

func newTransportNormalizer(config Config) (transportNormalizer, error) {
	if len(config.TrustedProxyCIDRs) > maxTrustedProxyCIDRs {
		return transportNormalizer{}, ErrInvalidConfig
	}
	clientHeader, ok := supportedClientIPHeader(config.TrustedClientIPHeader)
	if !ok {
		return transportNormalizer{}, ErrInvalidConfig
	}
	protoHeader, ok := supportedProtoHeader(config.TrustedProtoHeader)
	if !ok {
		return transportNormalizer{}, ErrInvalidConfig
	}
	if len(config.TrustedProxyCIDRs) == 0 && (clientHeader != "" || protoHeader != "") {
		return transportNormalizer{}, ErrInvalidConfig
	}
	normalizer := transportNormalizer{clientIPHeader: clientHeader, protoHeader: protoHeader}
	for _, raw := range config.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !validTrustedPrefix(prefix) {
			return transportNormalizer{}, ErrInvalidConfig
		}
		normalizer.trustedProxies = append(normalizer.trustedProxies, prefix.Masked())
	}
	return normalizer, nil
}

func validTrustedPrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	if !prefix.IsValid() || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if address.Is4() {
		return prefix.Bits() >= 8
	}
	return address.Is6() && prefix.Bits() >= 16
}

func supportedClientIPHeader(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", true
	case "cf-connecting-ip":
		return "CF-Connecting-IP", true
	case "x-real-ip":
		return "X-Real-IP", true
	default:
		return "", false
	}
}

func supportedProtoHeader(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", true
	case "x-forwarded-proto":
		return "X-Forwarded-Proto", true
	default:
		return "", false
	}
}

func (n transportNormalizer) normalize(request *http.Request) (protocol, security, addressSource string) {
	protocol = normalizeProtocol(request)
	peer, peerOK := parsePeer(request.RemoteAddr)
	trustedPeer := peerOK && n.contains(peer)
	addressSource = ClientAddressSourceUnknown
	if peerOK && !trustedPeer {
		addressSource = ClientAddressSourceDirect
	} else if trustedPeer && n.clientIPHeader == "" {
		addressSource = ClientAddressSourceUnknown
	} else if trustedPeer {
		if _, ok := singleAddressHeader(request.Header.Values(n.clientIPHeader)); ok {
			addressSource = ClientAddressSourceTrustedProxy
		} else {
			addressSource = ClientAddressSourceInvalidTrustedProxy
		}
	}

	if trustedPeer && n.protoHeader != "" {
		values := request.Header.Values(n.protoHeader)
		if len(values) != 1 || strings.Contains(values[0], ",") {
			security = TransportSecurityUnknown
		} else {
			switch strings.ToLower(strings.TrimSpace(values[0])) {
			case "https":
				security = TransportSecurityTrustedProxyTLS
			case "http":
				security = TransportSecurityPlaintext
			default:
				security = TransportSecurityUnknown
			}
		}
	} else if request.TLS != nil {
		security = TransportSecurityDirectTLS
	} else {
		security = TransportSecurityPlaintext
	}
	return protocol, security, addressSource
}

func normalizeProtocol(request *http.Request) string {
	switch request.ProtoMajor {
	case 1:
		return TransportProtocolHTTP1
	case 2:
		return TransportProtocolHTTP2
	case 3:
		return TransportProtocolHTTP3
	default:
		return TransportProtocolUnknown
	}
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

func singleAddressHeader(values []string) (netip.Addr, bool) {
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(strings.TrimSpace(values[0]))
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func (n transportNormalizer) contains(address netip.Addr) bool {
	for _, prefix := range n.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
