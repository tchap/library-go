package dynamictransport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	libcrypto "github.com/openshift/library-go/pkg/crypto"
)

func TestNewValidation(t *testing.T) {
	pool := x509.NewCertPool()
	ca := newTestCA(t, "pool-ca")
	pool.AddCert(ca.certificate)

	testCases := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{
			name:    "invalid CA data",
			opts:    []Option{WithCAData("bad", []byte("bad"))},
			wantErr: "failed to parse CA certificates",
		},
		{
			name:    "missing CA file",
			opts:    []Option{WithCAFile("missing", "/does/not/exist")},
			wantErr: "failed to load CA certificates",
		},
		{
			name:    "certificate without key",
			opts:    []Option{WithClientCertificateFile("cert.pem", "")},
			wantErr: "certFile and keyFile must be specified together",
		},
		{
			name:    "key without certificate",
			opts:    []Option{WithClientCertificateFile("", "key.pem")},
			wantErr: "certFile and keyFile must be specified together",
		},
		{
			name:    "zero TLS min version",
			opts:    []Option{WithTLSMinVersion(0)},
			wantErr: "WithTLSMinVersion requires a non-zero TLS version",
		},
		{
			name:    "empty TLS cipher suites",
			opts:    []Option{WithTLSCipherSuites(nil)},
			wantErr: "WithTLSCipherSuites requires at least one cipher suite",
		},
		{
			name:    "cert pool twice",
			opts:    []Option{WithCertPool(nil), WithCertPool(nil)},
			wantErr: "WithCertPool may only be specified once",
		},
		{
			name:    "nil cert pool then real cert pool",
			opts:    []Option{WithCertPool(nil), WithCertPool(pool)},
			wantErr: "WithCertPool may only be specified once",
		},
		{
			name:    "nil CA content provider",
			opts:    []Option{WithCAContentProvider(nil)},
			wantErr: "WithCAContentProvider requires a non-nil provider",
		},
		{
			name:    "invalid provider content",
			opts:    []Option{WithCAContentProvider(newTestCAProvider("bad", []byte("bad")))},
			wantErr: "failed to parse CA content from provider",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(t.Context(), tc.opts...)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestNewInvalidProviderRegistersNoListener is the regression test
// for the listener leak on failed construction: when the initial build fails,
// the transport must not have registered itself with the provider.
func TestNewInvalidProviderRegistersNoListener(t *testing.T) {
	provider := newTestCAProvider("bad", []byte("bad"))

	_, err := New(t.Context(), WithCAContentProvider(provider))
	assert.ErrorContains(t, err, "failed to parse CA content from provider")
	assert.Zerof(t, provider.addListenerCount.Load(), "transport registered with provider despite failed construction")
}

func TestWithCertPoolSnapshotsCallerPool(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	secondCA := newTestCA(t, "second-ca")

	pool := x509.NewCertPool()
	pool.AddCert(firstCA.certificate)
	originalPool := pool.Clone()

	roundTripper, err := New(t.Context(), WithCertPool(pool))
	require.NoError(t, err)
	t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)

	// Construction must not mutate the caller's pool.
	assert.True(t, pool.Equal(originalPool), "caller-owned cert pool was mutated")

	firstServer := startTLSServer(t, firstCA.serverCertificate, nil)
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	assertTrusted(t, roundTripper, firstServer.URL)

	// Adding a certificate to the caller's pool after construction must not
	// extend the transport's trust: the pool was snapshotted.
	pool.AddCert(secondCA.certificate)
	assertUntrusted(t, roundTripper, secondServer.URL)
}

func TestProxyConfiguration(t *testing.T) {
	t.Run("environment default", func(t *testing.T) {
		roundTripper, err := New(t.Context())
		require.NoError(t, err)
		assert.NotNil(t, underlyingTransport(t, roundTripper).Proxy)
	})

	t.Run("explicit proxy", func(t *testing.T) {
		want, err := url.Parse("http://proxy.example.com:3128")
		require.NoError(t, err)

		proxyFunc := func(*http.Request) (*url.URL, error) { return want, nil }
		roundTripper, err := New(t.Context(), WithProxyFunc(proxyFunc))
		require.NoError(t, err)

		got, err := underlyingTransport(t, roundTripper).Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}})
		require.NoError(t, err)
		assert.Equal(t, want.String(), got.String())
	})

	t.Run("explicitly disabled", func(t *testing.T) {
		roundTripper, err := New(t.Context(), WithProxyFunc(nil))
		require.NoError(t, err)
		assert.Nil(t, underlyingTransport(t, roundTripper).Proxy)
	})

	t.Run("last of multiple wins", func(t *testing.T) {
		first, err := url.Parse("http://first.example.com:3128")
		require.NoError(t, err)
		second, err := url.Parse("http://second.example.com:3128")
		require.NoError(t, err)

		roundTripper, err := New(t.Context(),
			WithProxyFunc(func(*http.Request) (*url.URL, error) { return first, nil }),
			WithProxyFunc(func(*http.Request) (*url.URL, error) { return second, nil }),
		)
		require.NoError(t, err)

		got, err := underlyingTransport(t, roundTripper).Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}})
		require.NoError(t, err)
		assert.Equal(t, second.String(), got.String())
	})
}

func TestTLSProfile(t *testing.T) {
	cipherSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	t.Run("crypto/tls defaults", func(t *testing.T) {
		roundTripper, err := New(t.Context())
		require.NoError(t, err)

		tlsConfig := underlyingTransport(t, roundTripper).TLSClientConfig
		assert.Equal(t, libcrypto.DefaultTLSVersion(), tlsConfig.MinVersion)
		assert.Equal(t, libcrypto.DefaultCiphers(), tlsConfig.CipherSuites)
	})

	t.Run("configured profile", func(t *testing.T) {
		roundTripper, err := New(t.Context(), WithTLSMinVersion(tls.VersionTLS13), WithTLSCipherSuites(cipherSuites))
		require.NoError(t, err)

		tlsConfig := underlyingTransport(t, roundTripper).TLSClientConfig
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
		assert.Equal(t, cipherSuites, tlsConfig.CipherSuites)
	})

	t.Run("last option wins when specified multiple times", func(t *testing.T) {
		roundTripper, err := New(t.Context(),
			WithTLSMinVersion(tls.VersionTLS12),
			WithTLSMinVersion(tls.VersionTLS13),
			WithTLSCipherSuites(cipherSuites),
			WithTLSCipherSuites(cipherSuites[:1]),
		)
		require.NoError(t, err)

		tlsConfig := underlyingTransport(t, roundTripper).TLSClientConfig
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
		assert.Equal(t, cipherSuites[:1], tlsConfig.CipherSuites)
	})

	// The profile must survive the transport rebuild a CA rotation triggers,
	// otherwise reloading trust would silently widen the TLS configuration.
	t.Run("survives a CA provider rebuild", func(t *testing.T) {
		provider := newTestCAProvider("provider", newTestCA(t, "first-ca").pem)

		roundTripper := newTestRoundTripper(t,
			WithCAContentProvider(provider),
			WithTLSMinVersion(tls.VersionTLS13),
			WithTLSCipherSuites(cipherSuites),
		)
		dynamic := roundTripper.(*dynamicTransport)
		previous := dynamic.current.Load()

		provider.setContent(newTestCA(t, "second-ca").pem)
		eventually(t, func() error {
			if dynamic.current.Load() != previous {
				return nil
			}
			return fmt.Errorf("transport was not rebuilt")
		})

		tlsConfig := underlyingTransport(t, roundTripper).TLSClientConfig
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
		assert.Equal(t, cipherSuites, tlsConfig.CipherSuites)
	})

	// Assert the profile is enforced on the wire, not merely recorded.
	t.Run("rejects a server below the version floor", func(t *testing.T) {
		ca := newTestCA(t, "tls12-only-ca")

		server := startTLSServer(t, ca.serverCertificate, nil, func(server *httptest.Server) {
			server.TLS.MaxVersion = tls.VersionTLS12
		})

		roundTripper, err := New(t.Context(),
			WithCAData("server-ca", ca.pem),
			WithTLSMinVersion(tls.VersionTLS13),
		)
		require.NoError(t, err)
		t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)

		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		_, err = roundTripper.RoundTrip(request)
		require.Error(t, err, "handshake with TLS 1.2-only server unexpectedly succeeded with a TLS 1.3 floor")
	})
}

func TestDisableHTTP2(t *testing.T) {
	t.Setenv("DISABLE_HTTP2", "")
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%t", disabled), func(t *testing.T) {
			ca := newTestCA(t, "protocol-ca")
			server := startTLSServer(t, ca.serverCertificate, nil, func(server *httptest.Server) {
				server.EnableHTTP2 = true
			})

			opts := []Option{WithCAData("server-ca", ca.pem), WithProxyFunc(nil)}
			if disabled {
				opts = append(opts, WithDisabledHTTP2())
			}
			roundTripper, err := New(t.Context(), opts...)
			require.NoError(t, err)
			t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)

			client := &http.Client{Transport: roundTripper}
			t.Cleanup(client.CloseIdleConnections)

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			require.NoError(t, err)
			response, err := client.Do(request)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())

			expectedProto := 2
			if disabled {
				expectedProto = 1
			}
			require.Equal(t, expectedProto, response.ProtoMajor)
		})
	}
}

// TestCloseIdleConnectionsForwarded verifies that closing idle connections
// through an http.Client reaches the underlying transport on both the static
// and the dynamic path, using connection reuse as the observable.
func TestCloseIdleConnectionsForwarded(t *testing.T) {
	testCases := []struct {
		name  string
		dynam bool
	}{
		{
			name:  "static transport",
			dynam: false,
		},
		{
			name:  "dynamic transport",
			dynam: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t, "idle-ca")
			server := startTLSServer(t, ca.serverCertificate, nil)

			opts := []Option{WithCAData("server-ca", ca.pem)}
			if tc.dynam {
				opts = append(opts, WithCAContentProvider(newTestCAProvider("provider", ca.pem)))
			}
			roundTripper := newTestRoundTripper(t, opts...)

			client := &http.Client{Transport: roundTripper}
			t.Cleanup(client.CloseIdleConnections)

			doRequest := func() bool {
				t.Helper()
				reused := false
				trace := &httptrace.ClientTrace{
					GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
				}
				request, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, server.URL, nil)
				require.NoError(t, err)
				response, err := client.Do(request)
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				return reused
			}

			// First request dials; second reuses the idle connection.
			doRequest()
			require.True(t, doRequest(), "expected the idle connection to be reused")

			// Closing idle connections through the client must reach the
			// transport (the current one, on the dynamic path).
			client.CloseIdleConnections()
			require.False(t, doRequest(), "expected a fresh connection after CloseIdleConnections")
		})
	}
}

func TestClientCertificateMutualTLS(t *testing.T) {
	ca := newTestCA(t, "mutual-tls-ca")
	serverCertificate, _, _ := ca.NewSignedCertificate(false)
	_, clientCertPEM, clientKeyPEM := ca.NewSignedCertificate(true)

	clientCertFile := filepath.Join(t.TempDir(), "client.crt")
	clientKeyFile := filepath.Join(t.TempDir(), "client.key")
	require.NoError(t, os.WriteFile(clientCertFile, clientCertPEM, 0o600))
	require.NoError(t, os.WriteFile(clientKeyFile, clientKeyPEM, 0o600))

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.certificate)
	server := startTLSServer(t, serverCertificate, clientCAs)

	// We just use duplicate client certs here to make sure both are being added.
	roundTripper, err := New(t.Context(),
		WithCAData("server-ca", ca.pem),
		WithClientCertificateFile(clientCertFile, clientKeyFile),
		WithClientCertificateFile(clientCertFile, clientKeyFile),
	)
	require.NoError(t, err)
	t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)

	assertTrusted(t, roundTripper, server.URL)
	assert.Len(t, underlyingTransport(t, roundTripper).TLSClientConfig.Certificates, 2)
}

// TestDisableHTTP2SurvivesRebuild verifies the option's "including after CA
// reload" promise on the dynamic path.
func TestDisableHTTP2SurvivesRebuild(t *testing.T) {
	t.Setenv("DISABLE_HTTP2", "")
	ca := newTestCA(t, "protocol-ca")
	rotatedCA := newTestCA(t, "rotated-ca")
	server := startTLSServer(t, ca.serverCertificate, nil, func(server *httptest.Server) {
		server.EnableHTTP2 = true
	})

	provider := newTestCAProvider("provider", ca.pem)
	roundTripper := newTestRoundTripper(t,
		WithCAContentProvider(provider),
		WithCAData("static", ca.pem),
		WithDisabledHTTP2(),
		WithProxyFunc(nil),
	)
	dynamic := roundTripper.(*dynamicTransport)
	previous := dynamic.current.Load()

	client := &http.Client{Transport: roundTripper}
	t.Cleanup(client.CloseIdleConnections)

	doRequest := func() int {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		response, err := client.Do(request)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		return response.ProtoMajor
	}

	require.Equal(t, 1, doRequest(), "HTTP/2 must be disabled before the rebuild")

	provider.setContent(rotatedCA.pem)
	eventually(t, func() error {
		if dynamic.current.Load() != previous {
			return nil
		}
		return fmt.Errorf("transport was not rebuilt")
	})

	require.Equal(t, 1, doRequest(), "HTTP/2 must stay disabled after the rebuild")
}
