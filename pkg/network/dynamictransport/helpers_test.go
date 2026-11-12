package dynamictransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	libcrypto "github.com/openshift/library-go/pkg/crypto"
)

// testCAProvider is a mutex-protected fake CAContentProvider. The real vendored
// providers do not synchronize AddListener; tests that care about that race use
// the real DynamicFileCAContent instead.
type testCAProvider struct {
	name string

	mu        sync.RWMutex
	content   []byte
	listeners []dynamiccertificates.Listener

	addListenerCount atomic.Int64

	// onRead, when set, runs after each CurrentCABundleContent call reads the
	// content, before it returns.
	onRead func(p *testCAProvider)
	// onAddListener, when set, runs inside AddListener with the listener being
	// added. It runs under the provider lock; only touch the provider's fields
	// directly and the listener's methods.
	onAddListener func(p *testCAProvider, listener dynamiccertificates.Listener)
}

func newTestCAProvider(name string, content []byte) *testCAProvider {
	return &testCAProvider{name: name, content: append([]byte(nil), content...)}
}

func (p *testCAProvider) Name() string { return p.name }

func (p *testCAProvider) AddListener(listener dynamiccertificates.Listener) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addListenerCount.Add(1)
	if p.onAddListener != nil {
		p.onAddListener(p, listener)
	}
	p.listeners = append(p.listeners, listener)
}

func (p *testCAProvider) CurrentCABundleContent() []byte {
	p.mu.RLock()
	content := append([]byte(nil), p.content...)
	p.mu.RUnlock()
	if p.onRead != nil {
		p.onRead(p)
	}
	return content
}

func (p *testCAProvider) VerifyOptions() (x509.VerifyOptions, bool) {
	return x509.VerifyOptions{}, false
}

func (p *testCAProvider) setContent(content []byte) {
	p.mu.Lock()
	p.content = append([]byte(nil), content...)
	p.mu.Unlock()
	p.notify()
}

// setContentQuiet changes the content without notifying listeners.
func (p *testCAProvider) setContentQuiet(content []byte) {
	p.mu.Lock()
	p.content = append([]byte(nil), content...)
	p.mu.Unlock()
}

func (p *testCAProvider) notify() {
	p.mu.RLock()
	listeners := append([]dynamiccertificates.Listener(nil), p.listeners...)
	p.mu.RUnlock()
	for _, listener := range listeners {
		listener.Enqueue()
	}
}

type testCA struct {
	t                 *testing.T
	pem               []byte
	certificate       *x509.Certificate
	signer            *libcrypto.CA
	serverCertificate tls.Certificate
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()

	caDirectory := t.TempDir()
	signer, err := libcrypto.MakeSelfSignedCA(
		filepath.Join(caDirectory, "ca.crt"),
		filepath.Join(caDirectory, "ca.key"),
		"",
		commonName,
		time.Hour,
	)
	require.NoError(t, err)

	certPEM, _, err := signer.Config.GetPEMBytes()
	require.NoError(t, err)

	testCA := &testCA{
		t:           t,
		pem:         certPEM,
		certificate: signer.Config.Certs[0],
		signer:      signer,
	}
	testCA.serverCertificate, _, _ = testCA.NewSignedCertificate(false)
	return testCA
}

func (ca *testCA) NewSignedCertificate(client bool) (tls.Certificate, []byte, []byte) {
	ca.t.Helper()

	var config *libcrypto.TLSCertificateConfig
	var err error
	if client {
		config, err = ca.signer.MakeClientCertificateForDuration(&user.DefaultInfo{Name: "test-client"}, time.Hour)
	} else {
		config, err = ca.signer.MakeServerCertForDuration(sets.New("127.0.0.1", "localhost"), time.Hour)
	}
	require.NoError(ca.t, err)

	certPEM, keyPEM, err := config.GetPEMBytes()
	require.NoError(ca.t, err)

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(ca.t, err)

	return certificate, certPEM, keyPEM
}

// startTLSServer starts an HTTPS test server presenting certificate. When
// clientCAs is non-nil the server requires and verifies a client certificate
// against it (mutual TLS). Optional hooks configure the server before startup.
func startTLSServer(t *testing.T, certificate tls.Certificate, clientCAs *x509.CertPool, configure ...func(*httptest.Server)) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	if clientCAs != nil {
		server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLS.ClientCAs = clientCAs
	}

	for _, configureServer := range configure {
		configureServer(server)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// eventually polls condition until it returns nil or the test times out. It
// replaces hand-rolled sleep-based waiting.
func eventually(t *testing.T, condition func() error) {
	t.Helper()

	pollErr := wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, wait.ForeverTestTimeout, true, func(context.Context) (bool, error) {
		return condition() == nil, nil
	})
	if pollErr != nil {
		t.Fatalf("condition never met: %v", condition())
	}
}

// assertTrusted asserts a GET through roundTripper succeeds against target.
func assertTrusted(t *testing.T, roundTripper http.RoundTripper, target string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)

	response, err := roundTripper.RoundTrip(request)
	require.NoErrorf(t, err, "GET %s", target)
	defer func() {
		assert.NoError(t, response.Body.Close())
	}()
	require.Equalf(t, http.StatusOK, response.StatusCode, "GET %s", target)
}

// assertUntrusted asserts a GET through roundTripper fails against target with
// an unknown-authority error, i.e. the server's CA is not in the trust pool.
func assertUntrusted(t *testing.T, roundTripper http.RoundTripper, target string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)

	response, err := roundTripper.RoundTrip(request)
	if err == nil {
		assert.NoError(t, response.Body.Close())
	}
	require.Errorf(t, err, "GET %s unexpectedly succeeded", target)
	var unknownAuthority x509.UnknownAuthorityError
	require.ErrorAsf(t, err, &unknownAuthority, "GET %s failed with %v, want unknown authority", target, err)
}

func underlyingTransport(t *testing.T, roundTripper http.RoundTripper) *http.Transport {
	t.Helper()
	if transport, ok := roundTripper.(*http.Transport); ok {
		return transport
	}
	if dynamic, ok := roundTripper.(*dynamicTransport); ok {
		return dynamic.current.Load()
	}
	t.Fatalf("got transport type %T, want *http.Transport or *dynamicTransport", roundTripper)
	return nil
}

// newTestRoundTripper builds a round tripper bound to the test's context, so
// its goroutines stop when the test finishes.
func newTestRoundTripper(t *testing.T, opts ...Option) http.RoundTripper {
	t.Helper()
	roundTripper, err := New(t.Context(), opts...)
	require.NoError(t, err)
	t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)
	return roundTripper
}

// getError performs a GET through roundTripper and reports why it failed, for
// use inside eventually conditions.
func getError(roundTripper http.RoundTripper, target string) error {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := roundTripper.RoundTrip(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", target, response.StatusCode)
	}
	return nil
}
