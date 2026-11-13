package httptransport

// Reproduction tests for the code-review findings on the AddListener-before-build
// reorder (commit 81bdc6c58). These tests assert the CORRECT behavior and FAIL on
// the current code; they are expected to pass once the findings are fixed:
//
//   - TestReproInitialPublishOverwritesAsyncRebuild   (finding 1, transport.go:175)
//   - TestReproFailedConstructionLeaksListener        (finding 2, transport.go:171)
//
// Finding 3 (the vendored listeners-slice race) cannot be reproduced
// deterministically from this repo: the racing code is in
// vendor/k8s.io/apiserver and only manifests under -race with a running
// provider. See docs/httptransport-code-review.md, Appendix C.

import (
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

// TestReproInitialPublishOverwritesAsyncRebuild demonstrates finding 1: the
// constructor's transport.Store runs outside rebuildMu and can overwrite a
// fresher transport that an Enqueue-triggered async rebuild already swapped in,
// permanently losing a CA rotation.
//
// The gated provider parks the constructor between its read of the rotating
// provider's content (OLD bundle) and its transport.Store, so the test can
// interleave a rotation + completed async rebuild (NEW bundle) before letting
// the constructor publish. The correct outcome is that the rebuild's transport
// (trusting the NEW CA) wins; the buggy outcome is that the constructor's
// stale transport (trusting only the OLD CA) clobbers it, and no further
// notification ever fires to correct it.
func TestReproInitialPublishOverwritesAsyncRebuild(t *testing.T) {
	oldCA := newTestCA(t, "old-ca")
	newCA := newTestCA(t, "new-ca")
	oldServer := startTLSServer(t, oldCA.serverCertificate, nil)
	newServer := startTLSServer(t, newCA.serverCertificate, nil)

	rotating := &reproProvider{name: "rotating", content: oldCA.pem}
	gated := newGatedProvider(t, "gated")

	// Run the constructor concurrently; it will park inside the gated provider's
	// first CurrentCABundleContent call, after having read the OLD bundle.
	resultCh := make(chan *dynamicTransport, 1)
	errCh := make(chan error, 1)
	go func() {
		roundTripper, err := NewRoundTripper(
			WithCAContentProvider(rotating),
			WithCAContentProvider(gated),
		)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- roundTripper.(*dynamicTransport)
	}()

	// Wait until the constructor has read the rotating provider (OLD bundle)
	// and is parked in the gated provider.
	<-gated.arrived

	// Rotate the bundle. This notifies the registered listener, whose Enqueue
	// goroutine rebuilds with the NEW bundle and swaps the result in — while
	// the constructor is still parked and holds no lock.
	rotating.setContent(newCA.pem)

	// Wait for the async rebuild to publish its transport. While the gate is
	// held the constructor cannot Store, so any non-nil transport pointer is
	// the rebuild's (trusting the NEW CA).
	deadline := time.Now().Add(5 * time.Second)
	rebuilt := false
	for time.Now().Before(deadline) {
		if listener := rotating.registeredListener(); listener != nil {
			if dynamic, ok := listener.(*dynamicTransport); ok && dynamic.transport.Load() != nil {
				rebuilt = true
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	require.True(t, rebuilt, "expected the async rebuild to publish a transport with the new CA")

	// Let the constructor finish: it builds from the OLD bundle it read before
	// parking and Stores the result unconditionally, outside rebuildMu.
	gated.releaseNow()

	var roundTripper *dynamicTransport
	select {
	case roundTripper = <-resultCh:
	case err := <-errCh:
		t.Fatalf("NewRoundTripper failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("constructor did not return after the gate was released")
	}

	// Correct behavior: the async rebuild's transport (trusting the NEW CA)
	// must survive. On the current code the constructor's stale transport
	// clobbered it, so this GET fails x509 verification — the CA rotation is
	// lost permanently because the provider already notified for the NEW
	// content and will not notify again.
	assertGetSucceeds(t, roundTripper, newServer.URL)
	assertGetFails(t, roundTripper, oldServer.URL)
}

// TestReproFailedConstructionLeaksListener demonstrates finding 2: AddListener
// registers the dynamicTransport before the initial transport build, so a
// failed construction returns (nil, err) while leaving the abandoned
// dynamicTransport permanently registered on every provider — the
// dynamiccertificates.Notifier interface has no RemoveListener.
//
// Each failed (or retried) construction leaks one zombie listener that pins
// the Config — including any loaded TLS client private keys — for the
// provider's lifetime, and rebuilds a full *http.Transport into an object
// nobody holds on every future CA change.
func TestReproFailedConstructionLeaksListener(t *testing.T) {
	ca := newTestCA(t, "recovery-ca")
	provider := &reproProvider{name: "flaky", content: []byte("not a certificate")}

	// A retry loop is the natural caller pattern for transiently-invalid CA
	// content: each attempt fails, the caller retries until the provider's
	// content becomes valid.
	for range 3 {
		_, err := NewRoundTripper(WithCAContentProvider(provider))
		require.ErrorContains(t, err, "failed to parse CA content from provider")
	}

	// Correct behavior: failed constructions must not have registered any
	// listener on the provider. On the current code three zombies are
	// registered — and each will rebuild a transport nobody uses on every
	// future CA change:
	//
	//   provider.setContent(ca.pem)  // content recovers
	//   -> 3 x Enqueue -> 3 x full rebuild into abandoned objects
	provider.setContent(ca.pem)

	assert.Empty(t, provider.registeredListener(), "failed NewRoundTripper attempts leaked listeners onto the provider")
}

// reproProvider is a CAContentProvider whose listener registrations and content
// changes the test can observe and trigger deterministically.
type reproProvider struct {
	name string

	mu        sync.RWMutex
	content   []byte
	listeners []dynamiccertificates.Listener
}

func (p *reproProvider) Name() string { return p.name }

func (p *reproProvider) AddListener(listener dynamiccertificates.Listener) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listeners = append(p.listeners, listener)
}

func (p *reproProvider) CurrentCABundleContent() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]byte(nil), p.content...)
}

func (p *reproProvider) VerifyOptions() (x509.VerifyOptions, bool) {
	return x509.VerifyOptions{}, false
}

func (p *reproProvider) setContent(content []byte) {
	p.mu.Lock()
	p.content = append([]byte(nil), content...)
	p.mu.Unlock()

	p.mu.RLock()
	listeners := append([]dynamiccertificates.Listener(nil), p.listeners...)
	p.mu.RUnlock()
	for _, listener := range listeners {
		listener.Enqueue()
	}
}

// registeredListener returns the first registered listener, or nil.
func (p *reproProvider) registeredListener() dynamiccertificates.Listener {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.listeners) == 0 {
		return nil
	}
	return p.listeners[0]
}

// gatedProvider parks the FIRST CurrentCABundleContent call until released;
// subsequent calls return empty content immediately. This lets a test hold the
// constructor between its provider reads and its transport.Store.
type gatedProvider struct {
	name string

	mu       sync.Mutex
	parked   bool
	released bool

	arrived chan struct{} // closed when the first call parks
	release chan struct{} // closed by the test to unpark the constructor
}

func newGatedProvider(t *testing.T, name string) *gatedProvider {
	t.Helper()
	provider := &gatedProvider{
		name:    name,
		arrived: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(func() { provider.releaseNow() })
	return provider
}

func (p *gatedProvider) Name() string { return p.name }

func (p *gatedProvider) AddListener(listener dynamiccertificates.Listener) {}

func (p *gatedProvider) CurrentCABundleContent() []byte {
	p.mu.Lock()
	first := !p.parked && !p.released
	if first {
		p.parked = true
	}
	p.mu.Unlock()

	if !first {
		return nil
	}
	close(p.arrived)
	<-p.release
	return nil
}

func (p *gatedProvider) VerifyOptions() (x509.VerifyOptions, bool) {
	return x509.VerifyOptions{}, false
}

func (p *gatedProvider) releaseNow() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.released {
		p.released = true
		close(p.release)
	}
}
