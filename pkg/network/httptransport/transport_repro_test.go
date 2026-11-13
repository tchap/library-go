package httptransport

// Reproduction tests for two findings from the review of the httptransport
// rework in openshift/library-go#2547. Both tests assert the CORRECT behavior
// and FAIL on the current code:
//
//   - TestReproRotationDuringConstructionIsNotLost
//     A CA rotation that happens while NewRoundTripper is constructing must
//     not be lost: the returned RoundTripper must trust the new CA.
//
//   - TestReproFailedConstructionRegistersNoListener
//     A NewRoundTripper call that fails must not leave the abandoned
//     dynamicTransport registered on the provider (Notifier has no
//     RemoveListener), or the leak accumulates one listener per retry.
//
// The tests are fix-agnostic: they assert only the end state, not the internal
// ordering NewRoundTripper uses. Verified to pass under both known fix shapes —
// build-before-register with a post-registration locked rebuild, and
// register-before-build with pre-validation and CompareAndSwap publishing.

import (
	"crypto/x509"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

// TestReproRotationDuringConstructionIsNotLost demonstrates that a CA rotation
// concurrent with NewRoundTripper can be permanently lost: the constructor's
// initial transport publish can overwrite a fresher transport that an
// Enqueue-triggered async rebuild already swapped in, and because the provider
// already notified for the new content, no further notification fires to
// correct it.
//
// The gated provider parks the constructor mid-construction (after it has read
// the rotating provider's OLD bundle), so the test can rotate the bundle and
// let any registered listener's rebuild complete before the constructor
// resumes and publishes. The correct end state is that the returned
// RoundTripper trusts the NEW CA regardless of which internal ordering the
// constructor uses.
func TestReproRotationDuringConstructionIsNotLost(t *testing.T) {
	oldCA := newTestCA(t, "old-ca")
	newCA := newTestCA(t, "new-ca")
	oldServer := startTLSServer(t, oldCA.serverCertificate, nil)
	newServer := startTLSServer(t, newCA.serverCertificate, nil)

	rotating := &reproProvider{name: "rotating", content: oldCA.pem}
	gated := newGatedProvider(t, "gated")

	type constructionResult struct {
		roundTripper http.RoundTripper
		err          error
	}
	resultCh := make(chan constructionResult, 1)
	go func() {
		roundTripper, err := NewRoundTripper(
			WithCAContentProvider(rotating),
			WithCAContentProvider(gated),
		)
		resultCh <- constructionResult{roundTripper, err}
	}()

	// Wait until the constructor has read the rotating provider (OLD bundle)
	// and is parked inside the gated provider's first content read.
	select {
	case <-gated.arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("constructor did not reach the gated provider")
	}

	// Rotate the bundle while construction is in flight. This notifies
	// whoever is registered — in the current code the constructor has
	// already registered, and the notification's rebuild completes with the
	// NEW bundle before the constructor resumes.
	rotating.setContent(newCA.pem)

	// Give any in-flight rebuild time to read the new bundle and finish
	// before the constructor resumes. In fix shapes that register late there
	// is no listener yet, so nothing happens here — their post-registration
	// reconciliation is then expected to pick the rotation up instead.
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) && rotating.readCount() < 2 {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)

	gated.releaseNow()

	var roundTripper http.RoundTripper
	select {
	case result := <-resultCh:
		require.NoError(t, result.err)
		roundTripper = result.roundTripper
	case <-time.After(10 * time.Second):
		t.Fatal("constructor did not return after the gate was released")
	}

	// Correct end state: the rotation is not lost. On the current code the
	// constructor's stale transport (trusting only the OLD CA) has clobbered
	// the rebuild's transport, so the GET below fails x509 verification.
	assertGetSucceeds(t, roundTripper, newServer.URL)
	assertGetFails(t, roundTripper, oldServer.URL)
}

// TestReproFailedConstructionRegistersNoListener demonstrates that a failed
// NewRoundTripper call permanently leaks a listener onto the provider:
// AddListener registers the dynamicTransport before the initial transport
// build, so a failed construction returns (nil, err) while leaving the
// abandoned dynamicTransport registered — dynamiccertificates.Notifier has no
// RemoveListener. A retry loop (the natural pattern for transiently-invalid
// CA content) accumulates one zombie listener per attempt; each pins the
// Config, including any loaded TLS client private keys, for the provider's
// lifetime and rebuilds a full transport nobody holds on every future CA
// change.
func TestReproFailedConstructionRegistersNoListener(t *testing.T) {
	provider := &reproProvider{name: "flaky", content: []byte("not a certificate")}

	for range 3 {
		_, err := NewRoundTripper(WithCAContentProvider(provider))
		require.ErrorContains(t, err, "failed to parse CA content from provider")
	}

	assert.Zero(t, provider.listenerCount(),
		"failed NewRoundTripper attempts must not register listeners on the provider; %d leaked",
		provider.listenerCount())
}

// reproProvider is a CAContentProvider whose listener registrations and content
// changes the test can observe and trigger deterministically.
type reproProvider struct {
	name string

	mu        sync.RWMutex
	content   []byte
	listeners []dynamiccertificates.Listener
	reads     int
}

func (p *reproProvider) Name() string { return p.name }

func (p *reproProvider) AddListener(listener dynamiccertificates.Listener) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listeners = append(p.listeners, listener)
}

func (p *reproProvider) CurrentCABundleContent() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads++
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

// listenerCount returns the number of registered listeners.
func (p *reproProvider) listenerCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.listeners)
}

// readCount returns the number of CurrentCABundleContent calls so far.
func (p *reproProvider) readCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.reads
}

// gatedProvider parks the FIRST CurrentCABundleContent call until released;
// subsequent calls return empty content immediately. This lets a test hold the
// constructor in the middle of construction.
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
