package palisadehttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportNormalizerTrustsHeadersOnlyFromConfiguredPeer(t *testing.T) {
	normalizer, err := newTransportNormalizer(Config{
		TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedClientIPHeader: "CF-Connecting-IP", TrustedProtoHeader: "X-Forwarded-Proto",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name                                  string
		remoteAddr, target, clientIP, forward string
		protocol, security, source            string
	}{
		{
			name: "trusted proxy", remoteAddr: "203.0.113.9:443", target: "http://origin.example/",
			clientIP: "198.51.100.7", forward: "https", protocol: TransportProtocolHTTP1,
			security: TransportSecurityTrustedProxyTLS, source: ClientAddressSourceTrustedProxy,
		},
		{
			name: "trusted edge plaintext overrides proxy hop tls", remoteAddr: "203.0.113.9:443", target: "https://origin.example/",
			clientIP: "198.51.100.7", forward: "http", protocol: TransportProtocolHTTP1,
			security: TransportSecurityPlaintext, source: ClientAddressSourceTrustedProxy,
		},
		{
			name: "direct spoof ignored", remoteAddr: "198.51.100.9:443", target: "http://origin.example/",
			clientIP: "192.0.2.99", forward: "https", protocol: TransportProtocolHTTP1,
			security: TransportSecurityPlaintext, source: ClientAddressSourceDirect,
		},
		{
			name: "direct tls", remoteAddr: "198.51.100.9:443", target: "https://origin.example/",
			clientIP: "192.0.2.99", forward: "http", protocol: TransportProtocolHTTP1,
			security: TransportSecurityDirectTLS, source: ClientAddressSourceDirect,
		},
		{
			name: "trusted malformed client address", remoteAddr: "203.0.113.9:443", target: "http://origin.example/",
			clientIP: "198.51.100.7, 192.0.2.9", forward: "https", protocol: TransportProtocolHTTP1,
			security: TransportSecurityTrustedProxyTLS, source: ClientAddressSourceInvalidTrustedProxy,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("CF-Connecting-IP", test.clientIP)
			request.Header.Set("X-Forwarded-Proto", test.forward)
			protocol, security, source := normalizer.normalize(request)
			if protocol != test.protocol || security != test.security || source != test.source {
				t.Fatalf("normalized = %s/%s/%s, want %s/%s/%s", protocol, security, source, test.protocol, test.security, test.source)
			}
		})
	}
}

func TestTransportNormalizerRejectsUnsafeConfiguration(t *testing.T) {
	tooMany := make([]string, maxTrustedProxyCIDRs+1)
	for index := range tooMany {
		tooMany[index] = "203.0.113.0/24"
	}
	tests := []Config{
		{TrustedClientIPHeader: "CF-Connecting-IP"},
		{TrustedProxyCIDRs: []string{"0.0.0.0/0"}, TrustedClientIPHeader: "CF-Connecting-IP"},
		{TrustedProxyCIDRs: []string{"128.0.0.0/1"}, TrustedClientIPHeader: "CF-Connecting-IP"},
		{TrustedProxyCIDRs: []string{"8000::/1"}, TrustedClientIPHeader: "CF-Connecting-IP"},
		{TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedClientIPHeader: "X-Forwarded-For"},
		{TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedProtoHeader: "Forwarded"},
		{TrustedProxyCIDRs: []string{"203.0.113.0/24"}},
		{TrustedProxyCIDRs: []string{"203.0.113.7/24"}, TrustedClientIPHeader: "CF-Connecting-IP"},
		{TrustedProxyCIDRs: []string{"203.0.113.0/24", "203.0.113.0/25"}, TrustedClientIPHeader: "CF-Connecting-IP"},
		{TrustedProxyCIDRs: []string{"203.0.113.0/24", "203.0.113.0/24"}, TrustedClientIPHeader: "CF-Connecting-IP"},
		{TrustedProxyCIDRs: []string{"not-a-prefix"}},
		{TrustedProxyCIDRs: tooMany},
	}
	for index, config := range tests {
		if _, err := newTransportNormalizer(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestTransportNormalizerAcceptsXRealIPAndIPv4MappedPeer(t *testing.T) {
	normalizer, err := newTransportNormalizer(Config{
		TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedClientIPHeader: "x-real-ip",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://origin.example/", nil)
	request.RemoteAddr = "[::ffff:203.0.113.5]:8080"
	request.Header.Set("X-Real-IP", "2001:db8::5")
	_, security, source := normalizer.normalize(request)
	if source != ClientAddressSourceTrustedProxy || security != TransportSecurityUnknown {
		t.Fatalf("security/source = %s/%s", security, source)
	}
}

func TestTransportNormalizerTreatsMissingTrustedEdgeProtoAsUnknown(t *testing.T) {
	normalizer, err := newTransportNormalizer(Config{
		TrustedProxyCIDRs: []string{"203.0.113.0/24"}, TrustedClientIPHeader: "CF-Connecting-IP",
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"plain proxy hop": "http://origin.example/", "tls proxy hop": "https://origin.example/"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			request.RemoteAddr = "203.0.113.9:443"
			request.Header.Set("CF-Connecting-IP", "198.51.100.7")
			_, security, source := normalizer.normalize(request)
			if security != TransportSecurityUnknown || source != ClientAddressSourceTrustedProxy {
				t.Fatalf("security/source = %s/%s", security, source)
			}
		})
	}
}
