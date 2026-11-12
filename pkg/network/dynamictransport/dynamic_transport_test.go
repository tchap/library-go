package dynamictransport

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/util/workqueue"
)

// TestPrimedBeforeReturn verifies the transport is usable immediately after
// New returns, with no wait for a background rebuild.
func TestPrimedBeforeReturn(t *testing.T) {
	ca := newTestCA(t, "primed-ca")
	server := startTLSServer(t, ca.serverCertificate, nil)

	provider := newTestCAProvider("provider", ca.pem)
	roundTripper := newTestRoundTripper(t, WithCAContentProvider(provider))

	assertTrusted(t, roundTripper, server.URL)
}

func TestRotation(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	firstServer := startTLSServer(t, firstCA.serverCertificate, nil)
	secondCA := newTestCA(t, "second-ca")
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	provider := newTestCAProvider("rotating-provider", firstCA.pem)
	roundTripper := newTestRoundTripper(t, WithCAContentProvider(provider))

	assertTrusted(t, roundTripper, firstServer.URL)

	provider.setContent(secondCA.pem)

	eventually(t, func() error { return getError(roundTripper, secondServer.URL) })
	assertUntrusted(t, roundTripper, firstServer.URL)
}

func TestStaticTrustSurvivesRebuild(t *testing.T) {
	poolCA := newTestCA(t, "pool-ca")
	dataCA := newTestCA(t, "data-ca")
	fileCA := newTestCA(t, "file-ca")
	providerCA := newTestCA(t, "provider-ca")
	rotatedCA := newTestCA(t, "rotated-ca")

	pool := x509.NewCertPool()
	pool.AddCert(poolCA.certificate)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, fileCA.pem, 0600))

	provider := newTestCAProvider("provider", providerCA.pem)
	roundTripper := newTestRoundTripper(t,
		WithCertPool(pool),
		WithCAData("data", dataCA.pem),
		WithCAFile("file", caFile),
		WithCAContentProvider(provider),
	)

	rotatedServer := startTLSServer(t, rotatedCA.serverCertificate, nil)

	provider.setContent(rotatedCA.pem)

	eventually(t, func() error { return getError(roundTripper, rotatedServer.URL) })

	// The static trust sources must survive the rebuild.
	for name, ca := range map[string]*testCA{
		"cert pool": poolCA,
		"CA data":   dataCA,
		"CA file":   fileCA,
	} {
		t.Run(name, func(t *testing.T) {
			server := startTLSServer(t, ca.serverCertificate, nil)
			assertTrusted(t, roundTripper, server.URL)
		})
	}

	// The rotated-out provider CA must no longer be trusted.
	providerServer := startTLSServer(t, providerCA.serverCertificate, nil)
	assertUntrusted(t, roundTripper, providerServer.URL)
}

func TestRetainsLastKnownGood(t *testing.T) {
	ca := newTestCA(t, "valid-ca")
	server := startTLSServer(t, ca.serverCertificate, nil)
	secondCA := newTestCA(t, "second-ca")
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	provider := newTestCAProvider("provider", ca.pem)
	roundTripper := newTestRoundTripper(t, WithCAContentProvider(provider))
	dynamic := roundTripper.(*dynamicTransport)

	t.Run("sync returns the error and keeps the transport", func(t *testing.T) {
		provider.setContentQuiet([]byte("not a certificate"))

		previous := dynamic.current.Load()
		require.Error(t, dynamic.sync())
		assert.Same(t, previous, dynamic.current.Load())
		assertTrusted(t, roundTripper, server.URL)
	})

	t.Run("end to end, the failed rebuild is retried and recovers", func(t *testing.T) {
		syncsBefore := dynamic.syncs.Load()
		previous := dynamic.current.Load()

		// Notify with invalid content: the rebuild fails, the last known-good
		// transport stays in use.
		provider.setContent([]byte("still not a certificate"))
		eventually(t, func() error {
			if dynamic.syncs.Load() > syncsBefore {
				return nil
			}
			return fmt.Errorf("no rebuild attempt observed")
		})
		assert.Same(t, previous, dynamic.current.Load())
		assertTrusted(t, roundTripper, server.URL)

		// Once valid content appears, the transport recovers.
		provider.setContent(secondCA.pem)
		eventually(t, func() error { return getError(roundTripper, secondServer.URL) })
	})
}

// TestMissedChangeBetweenBuildAndRegister covers a change that lands after the
// initial build but before (or without) any notification: the initial sync
// queued by run must pick it up even with no notification at all.
func TestMissedChangeBetweenBuildAndRegister(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	firstServer := startTLSServer(t, firstCA.serverCertificate, nil)
	secondCA := newTestCA(t, "second-ca")
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	provider := newTestCAProvider("provider", firstCA.pem)
	var switched sync.Once
	provider.onRead = func(p *testCAProvider) {
		// After the initial build read, switch the content silently: no
		// notification is ever sent for this change.
		switched.Do(func() { p.setContentQuiet(secondCA.pem) })
	}

	roundTripper := newTestRoundTripper(t, WithCAContentProvider(provider))

	assertTrusted(t, roundTripper, firstServer.URL)
	eventually(t, func() error { return getError(roundTripper, secondServer.URL) })
	assertUntrusted(t, roundTripper, firstServer.URL)
}

// TestNotificationDuringConstructionNotClobbered is the regression test for
// the CA rotation clobber race: a notification that fires during construction
// (from inside AddListener) must not be overwritten by the initial publish,
// and must eventually be applied.
func TestNotificationDuringConstructionNotClobbered(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	secondCA := newTestCA(t, "second-ca")
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	provider := newTestCAProvider("provider", firstCA.pem)
	provider.onAddListener = func(p *testCAProvider, listener dynamiccertificates.Listener) {
		// Switch the content and fire the notification synchronously from
		// inside construction.
		p.content = append([]byte(nil), secondCA.pem...)
		listener.Enqueue()
	}

	roundTripper := newTestRoundTripper(t, WithCAContentProvider(provider))
	dynamic := roundTripper.(*dynamicTransport)

	eventually(t, func() error { return getError(roundTripper, secondServer.URL) })

	// Once the worker is idle, the published content must be the second CA,
	// not a stale first publish.
	eventually(t, func() error {
		dynamic.syncMu.Lock()
		defer dynamic.syncMu.Unlock()
		if len(dynamic.publishedContent) == 1 && bytes.Equal(dynamic.publishedContent[0], secondCA.pem) {
			return nil
		}
		return fmt.Errorf("published content is not the second CA")
	})
}

func TestConcurrentRotationsConverge(t *testing.T) {
	const goroutines = 4
	const rotationsPerGoroutine = 10

	finalCA := newTestCA(t, "final-ca")
	finalServer := startTLSServer(t, finalCA.serverCertificate, nil)

	rotationCAs := make([]*testCA, 4)
	for i := range rotationCAs {
		rotationCAs[i] = newTestCA(t, fmt.Sprintf("rotation-ca-%d", i))
	}

	first := newTestCAProvider("first", rotationCAs[0].pem)
	second := newTestCAProvider("second", rotationCAs[1].pem)
	roundTripper := newTestRoundTripper(t,
		WithCAContentProvider(first),
		WithCAContentProvider(second),
	)
	dynamic := roundTripper.(*dynamicTransport)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Go(func() {
			for r := 0; r < rotationsPerGoroutine; r++ {
				ca := rotationCAs[(g+r)%len(rotationCAs)]
				if r%2 == 0 {
					first.setContent(ca.pem)
				} else {
					second.setContent(ca.pem)
				}
			}
		})
	}
	wg.Wait()

	// Settle on a final known state.
	first.setContentQuiet(finalCA.pem)
	second.setContentQuiet(finalCA.pem)
	first.notify()
	second.notify()

	want := [][]byte{finalCA.pem, finalCA.pem}
	eventually(t, func() error {
		dynamic.syncMu.Lock()
		defer dynamic.syncMu.Unlock()
		if slices.EqualFunc(dynamic.publishedContent, want, bytes.Equal) {
			return nil
		}
		return fmt.Errorf("published content has not converged")
	})

	assertTrusted(t, roundTripper, finalServer.URL)
}

func TestNotificationsCoalesce(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	secondCA := newTestCA(t, "second-ca")
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	provider := newTestCAProvider("provider", firstCA.pem)

	// Build the transport manually so run has not started and the queue state
	// is observable.
	var config Config
	require.NoError(t, WithCAContentProvider(provider)(&config))
	dynamic := &dynamicTransport{
		config:         &config,
		providers:      config.caContentProviders,
		resyncInterval: time.Hour,
		done:           make(chan struct{}),
	}
	require.NoError(t, dynamic.sync())
	dynamic.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
		workqueue.DefaultTypedControllerRateLimiter[string](),
		workqueue.TypedRateLimitingQueueConfig[string]{},
	)

	listener := queueListener{queue: dynamic.queue}
	provider.setContentQuiet(secondCA.pem)
	for i := 0; i < 100; i++ {
		listener.Enqueue()
	}
	require.Equal(t, 1, dynamic.queue.Len(), "notifications did not coalesce")

	syncsBefore := dynamic.syncs.Load()
	go dynamic.run(t.Context())

	eventually(t, func() error { return getError(dynamic, secondServer.URL) })
	// The 100 notifications must drain as exactly one sync.
	eventually(t, func() error {
		if got := dynamic.syncs.Load(); got == syncsBefore+1 {
			return nil
		} else {
			return fmt.Errorf("got %d syncs, want %d", got, syncsBefore+1)
		}
	})
}

func TestUnchangedContentDoesNotRebuild(t *testing.T) {
	ca := newTestCA(t, "stable-ca")
	server := startTLSServer(t, ca.serverCertificate, nil)

	provider := newTestCAProvider("provider", ca.pem)
	roundTripper := newTestRoundTripper(t, WithCAContentProvider(provider))
	dynamic := roundTripper.(*dynamicTransport)

	assertTrusted(t, roundTripper, server.URL)
	previous := dynamic.current.Load()

	syncsBefore := dynamic.syncs.Load()
	provider.notify()
	eventually(t, func() error {
		if dynamic.syncs.Load() > syncsBefore {
			return nil
		}
		return fmt.Errorf("no sync observed")
	})
	assert.Same(t, previous, dynamic.current.Load(), "unchanged content rebuilt the transport")
}

func TestShutdown(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	firstServer := startTLSServer(t, firstCA.serverCertificate, nil)
	secondCA := newTestCA(t, "second-ca")
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	t.Run("cancel stops following providers and keeps serving", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		provider := newTestCAProvider("provider", firstCA.pem)
		roundTripper, err := New(ctx, WithCAContentProvider(provider))
		require.NoError(t, err)
		t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)
		dynamic := roundTripper.(*dynamicTransport)

		assertTrusted(t, roundTripper, firstServer.URL)
		previous := dynamic.current.Load()

		cancel()
		eventually(t, func() error {
			select {
			case <-dynamic.done:
				return nil
			default:
				return fmt.Errorf("run did not stop")
			}
		})

		// Rotations after shutdown must be ignored, not panic, and the
		// transport must keep serving the last known-good trust.
		provider.setContent(secondCA.pem)
		assert.Same(t, previous, dynamic.current.Load())
		assertTrusted(t, roundTripper, firstServer.URL)
		assert.Error(t, getError(roundTripper, secondServer.URL))
	})

	t.Run("context already cancelled at construction", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		provider := newTestCAProvider("provider", firstCA.pem)
		roundTripper, err := New(ctx, WithCAContentProvider(provider))
		require.NoError(t, err)
		t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)
		dynamic := roundTripper.(*dynamicTransport)

		eventually(t, func() error {
			select {
			case <-dynamic.done:
				return nil
			default:
				return fmt.Errorf("run did not stop")
			}
		})
		assertTrusted(t, roundTripper, firstServer.URL)
	})
}

// TestRebuildClosesIdleConnectionsOfReplacedTransport verifies that idle
// connections pooled by the replaced transport are closed, so stale
// connections cannot outlive the CA rotation that replaced them.
func TestRebuildClosesIdleConnectionsOfReplacedTransport(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	secondCA := newTestCA(t, "second-ca")
	server := startTLSServer(t, firstCA.serverCertificate, nil)

	provider := newTestCAProvider("provider", firstCA.pem)
	// The static CA keeps the server reachable across the rotation; only the
	// provider content rotates.
	roundTripper := newTestRoundTripper(t,
		WithCAContentProvider(provider),
		WithCAData("static", firstCA.pem),
	)
	dynamic := roundTripper.(*dynamicTransport)

	reused := func() bool {
		gotReused := false
		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { gotReused = info.Reused },
		}
		request, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		response, err := roundTripper.RoundTrip(request)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		return gotReused
	}

	require.False(t, reused(), "first request should dial")
	require.True(t, reused(), "second request should reuse the idle connection")

	previous := dynamic.current.Load()
	provider.setContent(secondCA.pem)
	eventually(t, func() error {
		if dynamic.current.Load() != previous {
			return nil
		}
		return fmt.Errorf("transport was not rebuilt")
	})

	// The rebuilt transport has no idle connections: the next request dials.
	require.False(t, reused(), "request after rebuild should dial a fresh connection")
}

func TestMultipleProviders(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	secondCA := newTestCA(t, "second-ca")
	thirdCA := newTestCA(t, "third-ca")

	firstServer := startTLSServer(t, firstCA.serverCertificate, nil)
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)
	thirdServer := startTLSServer(t, thirdCA.serverCertificate, nil)

	first := newTestCAProvider("first", firstCA.pem)
	second := newTestCAProvider("second", secondCA.pem)
	roundTripper := newTestRoundTripper(t,
		WithCAContentProvider(first),
		WithCAContentProvider(second),
	)

	assertTrusted(t, roundTripper, firstServer.URL)
	assertTrusted(t, roundTripper, secondServer.URL)

	first.setContent(thirdCA.pem)
	eventually(t, func() error { return getError(roundTripper, thirdServer.URL) })

	// The untouched provider keeps its trust.
	assertTrusted(t, roundTripper, secondServer.URL)
	assertUntrusted(t, roundTripper, firstServer.URL)
}

// TestEmptyProviderThenPopulated mirrors ConfigMapCAController, which returns
// no content until its informer syncs.
func TestEmptyProviderThenPopulated(t *testing.T) {
	ca := newTestCA(t, "late-ca")
	server := startTLSServer(t, ca.serverCertificate, nil)

	provider := newTestCAProvider("provider", nil)
	roundTripper := newTestRoundTripper(t,
		WithCAContentProvider(provider),
		WithCertPool(x509.NewCertPool()),
	)

	assertUntrusted(t, roundTripper, server.URL)

	provider.setContent(ca.pem)
	eventually(t, func() error { return getError(roundTripper, server.URL) })
}

// TestRealDynamicFileProvider is a contract test against the real vendored
// provider, in the documented order: construct the transport before starting
// the provider's Run.
func TestRealDynamicFileProvider(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	firstServer := startTLSServer(t, firstCA.serverCertificate, nil)
	secondCA := newTestCA(t, "second-ca")
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, firstCA.pem, 0600))

	provider, err := dynamiccertificates.NewDynamicCAContentFromFile("file-ca", caFile)
	require.NoError(t, err)

	roundTripper := newTestRoundTripper(t, WithCAContentProvider(provider))
	assertTrusted(t, roundTripper, firstServer.URL)

	go provider.Run(t.Context(), 1)

	require.NoError(t, os.WriteFile(caFile, secondCA.pem, 0600))
	eventually(t, func() error { return getError(roundTripper, secondServer.URL) })
	assertUntrusted(t, roundTripper, firstServer.URL)
}
