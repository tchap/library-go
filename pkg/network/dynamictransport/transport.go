package dynamictransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	clientcert "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/workqueue"

	libcrypto "github.com/openshift/library-go/pkg/crypto"
)

// New constructs an outbound HTTP round tripper from the supplied options. By
// default, it trusts the system certificate pool, honors the standard proxy
// environment variables, and applies the OpenShift-wide TLS defaults (minimum
// version and cipher suites) from pkg/crypto.DefaultTLSVersion and
// pkg/crypto.DefaultCiphers.
//
// The concrete type of the returned http.RoundTripper is not part of the API.
// When no CA content provider is supplied it is a static *http.Transport and
// ctx is ignored. When one or more providers are supplied, the returned round
// tripper follows their CA content changes, rebuilding in the background,
// until ctx is done, then keeps serving the last transport it built; see the
// package documentation for the rebuild and lifecycle semantics, including
// the requirement to construct all round trippers before starting the
// providers' Run.
func New(ctx context.Context, opts ...Option) (http.RoundTripper, error) {
	var config Config
	for i, option := range opts {
		if err := option(&config); err != nil {
			return nil, fmt.Errorf("applying transport option %d failed: %w", i, err)
		}
	}

	if len(config.caContentProviders) > 0 {
		roundTripper := &dynamicTransport{
			config:         &config,
			providers:      config.caContentProviders,
			resyncInterval: defaultResyncInterval,
			done:           make(chan struct{}),
		}
		// The initial build may fail; nothing is registered with the providers
		// and no goroutine exists yet, so failing here leaks nothing.
		if err := roundTripper.sync(); err != nil {
			return nil, err
		}
		// Nothing below this point can fail. The queue's internal goroutine
		// must not be created before the last failing step, so it can always
		// be stopped by run.
		roundTripper.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{},
		)
		for _, provider := range config.caContentProviders {
			provider.AddListener(queueListener{queue: roundTripper.queue})
		}
		go roundTripper.run(ctx)
		return roundTripper, nil
	}

	return config.newHTTPTransport(nil)
}

func (config *Config) newHTTPTransport(caContent [][]byte) (*http.Transport, error) {
	rootCAs, err := config.newCertPool(caContent)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:      rootCAs,
		MinVersion:   libcrypto.DefaultTLSVersion(),
		CipherSuites: libcrypto.DefaultCiphers(),
	}
	if len(config.clientCertificates) > 0 {
		tlsConfig.Certificates = append([]tls.Certificate(nil), config.clientCertificates...)
	}
	if config.tlsMinVersion > 0 {
		tlsConfig.MinVersion = config.tlsMinVersion
	}
	if len(config.tlsCipherSuites) > 0 {
		tlsConfig.CipherSuites = append([]uint16(nil), config.tlsCipherSuites...)
	}

	if config.disableHTTP2 {
		tlsConfig.NextProtos = []string{"http/1.1"}
	}

	transport := utilnet.SetTransportDefaults(&http.Transport{TLSClientConfig: tlsConfig})
	if config.proxyConfigured {
		transport.Proxy = config.proxyFunc
	}
	return transport, nil
}

// newCertPool assembles the trust pool from the base pool, the static CA
// sources, and caContent, the snapshotted current bundles of the CA content
// providers. Taking the snapshot as a parameter guarantees the pool is built
// from exactly the content a caller compared against.
func (config *Config) newCertPool(caContent [][]byte) (*x509.CertPool, error) {
	var rootCAs *x509.CertPool
	if config.basePool != nil {
		rootCAs = config.basePool.Clone()
	} else {
		var err error
		rootCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system certificate pool failed: %w", err)
		}
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
	}

	for _, certificates := range config.staticCAs {
		for _, certificate := range certificates {
			rootCAs.AddCert(certificate)
		}
	}

	for i, content := range caContent {
		if len(content) == 0 {
			continue
		}

		certificates, err := clientcert.ParseCertsPEM(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA content from provider %q: %w", config.caContentProviders[i].Name(), err)
		}

		for _, certificate := range certificates {
			rootCAs.AddCert(certificate)
		}
	}

	return rootCAs, nil
}
