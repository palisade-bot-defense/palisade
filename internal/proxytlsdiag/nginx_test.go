package proxytlsdiag

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/palisade-bot-defense/palisade/pkg/palisadehttp"
)

const (
	nginxFixtureRoleEnvironment = "PALISADE_NGINX_FIXTURE_ROLE"
	nginxRoleCertificate        = "certificate"
	nginxRoleOrigin             = "origin"
	nginxRoleVerifier           = "verifier"
	nginxAddress                = "192.0.2.10"
	originAddress               = "192.0.2.20"
	verifierAddress             = "192.0.2.30"
	spoofedAddress              = "198.51.100.77"
	nginxTrustedPrefix          = nginxAddress + "/32"
	nginxServerURL              = "https://nginx:8443"
	originServerURL             = "http://origin:8080"
	originAdminURL              = "http://origin:8082"
	fixtureCertificatePath      = "/certs/server.crt"
	fixturePrivateKeyPath       = "/certs/server.key"
	fixtureTimeout              = 90 * time.Second
)

func TestNginxFixtureOrigin(t *testing.T) {
	requireNginxFixtureRole(t, nginxRoleOrigin)
	runNginxOriginFixture(t)
}

func TestNginxFixtureVerifier(t *testing.T) {
	requireNginxFixtureRole(t, nginxRoleVerifier)
	runNginxVerifier(t)
}

func TestNginxFixtureCertificateAuthority(t *testing.T) {
	requireNginxFixtureRole(t, nginxRoleCertificate)
	if err := generateFixtureCertificate(fixtureCertificatePath, fixturePrivateKeyPath, time.Now().UTC()); err != nil {
		t.Fatal("fixture certificate generation failed")
	}
	if err := os.Chown(fixtureCertificatePath, 101, 101); err != nil {
		t.Fatal("fixture certificate ownership failed")
	}
	if err := os.Chown(fixturePrivateKeyPath, 101, 101); err != nil {
		t.Fatal("fixture key ownership failed")
	}
	server := newFixtureServer(t, "0.0.0.0:8084", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/ready" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	serverErrors := make(chan error, 1)
	server.start(serverErrors)
	select {
	case err := <-serverErrors:
		t.Fatalf("certificate fixture failed: %v", err)
	case <-time.After(fixtureTimeout):
		t.Fatal("certificate fixture timed out")
	}
}

func TestNginxFixtureCertificateProbe(t *testing.T) {
	requireNginxFixtureRole(t, nginxRoleCertificate)
	probeFixtureHealth(t, "http://127.0.0.1:8084/ready")
}

func TestNginxFixtureHealthProbe(t *testing.T) {
	requireNginxFixtureRole(t, nginxRoleOrigin)
	probeFixtureHealth(t, "http://127.0.0.1:8082/ready")
}

func probeFixtureHealth(t *testing.T, target string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Get(target)
	if err != nil {
		t.Fatal("fixture is not ready")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("fixture readiness contract failed")
	}
}

func TestGeneratedFixtureCertificateIsScoped(t *testing.T) {
	directory := t.TempDir()
	certificatePath := directory + "/server.crt"
	privateKeyPath := directory + "/server.key"
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	if err := generateFixtureCertificate(certificatePath, privateKeyPath, now); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("certificate PEM boundary failed")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateInfo, _ := os.Stat(certificatePath)
	keyInfo, _ := os.Stat(privateKeyPath)
	if certificate.Subject.CommonName != "nginx" || len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != "nginx" ||
		certificate.IsCA || certificate.NotBefore != now.Add(-time.Minute) || certificate.NotAfter != now.Add(time.Hour) ||
		certificateInfo == nil || certificateInfo.Mode().Perm() != 0o644 || keyInfo == nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatal("certificate scope or permissions changed")
	}
}

func TestNginxFixtureConstantsAreClosed(t *testing.T) {
	if nginxTrustedPrefix != "192.0.2.10/32" || originAddress != "192.0.2.20" || verifierAddress != "192.0.2.30" ||
		!strings.HasPrefix(nginxServerURL, "https://") || !strings.HasPrefix(originServerURL, "http://") {
		t.Fatal("nginx fixture constants changed without contract review")
	}
}

func requireNginxFixtureRole(t *testing.T, expected string) {
	t.Helper()
	if os.Getenv(nginxFixtureRoleEnvironment) != expected {
		t.Skip("nginx container fixture role is not active")
	}
}

type protectedFixture struct {
	trusted atomic.Int64
	direct  atomic.Int64
}

func (fixture *protectedFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	peer, ok := remotePeer(request.RemoteAddr)
	body, bodyErr := io.ReadAll(io.LimitReader(request.Body, MaximumResponseSize+1))
	cookie, cookieErr := request.Cookie("application_session")
	valid := ok && bodyErr == nil && len(body) <= MaximumResponseSize && request.Method == http.MethodPost &&
		request.URL.EscapedPath() == privatePath && request.URL.RawQuery == privateQuery && string(body) == privateBody &&
		request.UserAgent() == privateAgent && cookieErr == nil && cookie.Value == privateCookie
	if valid {
		switch peer {
		case nginxAddress:
			valid = request.Header.Get("X-Real-IP") == verifierAddress && request.Header.Get("X-Forwarded-Proto") == "https" &&
				request.Header.Get("CF-Connecting-IP") == "" && request.Header.Get("X-Forwarded-For") == "" && request.Header.Get("Forwarded") == ""
			if valid {
				fixture.trusted.Add(1)
			}
		case verifierAddress:
			valid = request.Header.Get("X-Real-IP") == spoofedAddress && request.Header.Get("X-Forwarded-Proto") == "https"
			if valid {
				fixture.direct.Add(1)
			}
		default:
			valid = false
		}
	}
	if !valid {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func runNginxOriginFixture(t *testing.T) {
	trustedBoundaries := &boundaryState{}
	directBoundaries := &boundaryState{}
	trustedService := &serviceFixture{
		expectedRequestTransport: serviceHTTP1Plaintext, expectedProtocol: "http1", expectedSecurity: "trusted_proxy_tls", expectedSource: "trusted_proxy", boundaries: trustedBoundaries,
	}
	directService := &serviceFixture{
		expectedRequestTransport: serviceHTTP1Plaintext, expectedProtocol: "http1", expectedSecurity: "plaintext", expectedSource: "direct", boundaries: directBoundaries,
	}
	protected := &protectedFixture{}

	trustedGuard := newNginxOriginGuard(t, "http://127.0.0.1:8081")
	directGuard := newNginxOriginGuard(t, "http://127.0.0.1:8083")
	trustedHandler := trustedGuard.Handler(protected)
	directHandler := directGuard.Handler(protected)
	originHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		peer, ok := remotePeer(request.RemoteAddr)
		if !ok {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch peer {
		case nginxAddress:
			trustedHandler.ServeHTTP(writer, request)
		case verifierAddress:
			directHandler.ServeHTTP(writer, request)
		default:
			writer.WriteHeader(http.StatusForbidden)
		}
	})

	adminHandler := http.NewServeMux()
	adminHandler.HandleFunc("GET /ready", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	adminHandler.HandleFunc("POST /complete", func(writer http.ResponseWriter, request *http.Request) {
		peer, ok := remotePeer(request.RemoteAddr)
		valid := ok && peer == verifierAddress && trustedService.decisions.Load() == 1 && directService.decisions.Load() == 1 &&
			trustedBoundaries.counts().Total() == 0 && directBoundaries.counts().Total() == 0 &&
			protected.trusted.Load() == 1 && protected.direct.Load() == 1
		if !valid {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})

	servers := []fixtureServer{
		newFixtureServer(t, "0.0.0.0:8081", trustedService),
		newFixtureServer(t, "0.0.0.0:8083", directService),
		newFixtureServer(t, "0.0.0.0:8080", originHandler),
		newFixtureServer(t, "0.0.0.0:8082", adminHandler),
	}
	serverErrors := make(chan error, len(servers))
	for index := range servers {
		servers[index].start(serverErrors)
	}

	select {
	case err := <-serverErrors:
		t.Fatalf("fixture server failed: %v", err)
	case <-time.After(fixtureTimeout):
		t.Fatal("fixture completion timed out")
	}
}

func newNginxOriginGuard(t *testing.T, baseURL string) *palisadehttp.Middleware {
	t.Helper()
	guard, err := palisadehttp.New(palisadehttp.Config{
		BaseURL: baseURL, APIKey: apiKey, FailureMode: palisadehttp.FailClosed,
		Classifier:            palisadehttp.StaticClassification("write", "account"),
		TrustedProxyCIDRs:     []string{nginxTrustedPrefix},
		TrustedClientIPHeader: "X-Real-IP",
		TrustedProtoHeader:    "X-Forwarded-Proto",
		Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

type fixtureServer struct {
	server   *http.Server
	listener net.Listener
}

func newFixtureServer(t *testing.T, address string, handler http.Handler) fixtureServer {
	t.Helper()
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal("fixture listener failed")
	}
	return fixtureServer{
		server: &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}, listener: listener,
	}
}

func (server fixtureServer) start(serverErrors chan<- error) {
	go func() {
		err := server.server.Serve(server.listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()
}

func generateFixtureCertificate(certificatePath, privateKeyPath string, now time.Time) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "nginx"}, DNSNames: []string{"nginx"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err := writeFixturePEM(certificatePath, 0o644, "CERTIFICATE", der); err != nil {
		return err
	}
	if err := writeFixturePEM(privateKeyPath, 0o600, "EC PRIVATE KEY", keyDER); err != nil {
		_ = os.Remove(certificatePath)
		return err
	}
	return nil
}

func writeFixturePEM(path string, mode os.FileMode, blockType string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: contents}); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func bigOne() *big.Int { return big.NewInt(1) }

func runNginxVerifier(t *testing.T) {
	certificate, err := os.ReadFile(fixtureCertificatePath)
	if err != nil {
		t.Fatal("fixture certificate is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("fixture certificate is invalid")
	}
	tlsTransport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "nginx", MinVersion: tls.VersionTLS12},
	}
	defer tlsTransport.CloseIdleConnections()
	tlsJar, _ := cookiejar.New(nil)
	tlsClient := &http.Client{Transport: tlsTransport, Jar: tlsJar, Timeout: RequestTimeoutSec * time.Second}
	verifyProtectedRequest(t, tlsClient, nginxServerURL, true)

	directTransport := &http.Transport{Proxy: nil}
	defer directTransport.CloseIdleConnections()
	directJar, _ := cookiejar.New(nil)
	directClient := &http.Client{Transport: directTransport, Jar: directJar, Timeout: RequestTimeoutSec * time.Second}
	verifyProtectedRequest(t, directClient, originServerURL, false)

	completionClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: RequestTimeoutSec * time.Second}
	request, err := http.NewRequest(http.MethodPost, originAdminURL+"/complete", nil)
	if err != nil {
		t.Fatal("completion request failed")
	}
	response, err := completionClient.Do(request)
	if err != nil {
		t.Fatal("completion request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("origin fixture rejected aggregate completion")
	}
}

func verifyProtectedRequest(t *testing.T, client *http.Client, baseURL string, wantTLS bool) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+privatePath+"?"+privateQuery, strings.NewReader(privateBody))
	if err != nil {
		t.Fatal("protected request creation failed")
	}
	request.Header.Set("Content-Type", "text/plain")
	request.Header.Set("User-Agent", privateAgent)
	request.Header.Set("X-Real-IP", spoofedAddress)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("CF-Connecting-IP", spoofedAddress)
	request.Header.Set("X-Forwarded-For", spoofedAddress)
	request.Header.Set("Forwarded", "for="+spoofedAddress+";proto=http")
	request.AddCookie(&http.Cookie{Name: "application_session", Value: privateCookie})
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("protected request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaximumResponseSize+1))
	if err != nil || len(body) > MaximumResponseSize {
		t.Fatal("protected response exceeded its boundary")
	}
	if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Palisade-Adapter") != "pass" || len(bytes.TrimSpace(body)) != 0 {
		t.Fatalf("protected response contract failed: status=%d adapter=%q body_bytes=%d", response.StatusCode,
			response.Header.Get("X-Palisade-Adapter"), len(body))
	}
	if wantTLS {
		if response.TLS == nil || response.ProtoMajor != 2 {
			t.Fatal("nginx did not negotiate HTTP/2 over TLS")
		}
	} else if response.TLS != nil || response.ProtoMajor != 1 {
		t.Fatal("direct fixture request changed transport")
	}
}

func remotePeer(value string) (string, bool) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return "", false
	}
	address := net.ParseIP(host)
	if address == nil {
		return "", false
	}
	return address.String(), true
}
