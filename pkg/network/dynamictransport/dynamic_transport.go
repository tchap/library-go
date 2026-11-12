package dynamictransport

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	// syncKey is the queue's single item. The queue coalesces: any number of
	// notifications pending at once collapse into one sync.
	syncKey = "sync"

	// defaultResyncInterval bounds how long a missed notification can go
	// unnoticed. Syncs that find unchanged content are cheap.
	defaultResyncInterval = time.Minute
)

// dynamicTransport is an http.RoundTripper whose CA trust follows its CA
// content providers. RoundTrip reads the current transport without locking;
// only sync publishes transports, serialized by syncMu.
type dynamicTransport struct {
	config    *Config
	providers []dynamiccertificates.CAContentProvider

	current atomic.Pointer[http.Transport]

	// syncMu makes each sync's snapshot-build-publish step one serialized
	// operation, and guards publishedContent.
	syncMu           sync.Mutex
	publishedContent [][]byte

	queue          workqueue.TypedRateLimitingInterface[string]
	resyncInterval time.Duration
	done           chan struct{}
	syncs          atomic.Int64
}

var _ http.RoundTripper = &dynamicTransport{}

func (t *dynamicTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.current.Load().RoundTrip(request)
}

// CloseIdleConnections closes any idle connections held by the current
// underlying transport, so http.Client.CloseIdleConnections works through this
// wrapper.
func (t *dynamicTransport) CloseIdleConnections() {
	t.current.Load().CloseIdleConnections()
}

// queueListener adapts the providers' notification callback to the workqueue.
// Add on a shut-down queue does nothing, so a notification arriving after
// shutdown is safely dropped.
type queueListener struct {
	queue workqueue.TypedInterface[string]
}

func (l queueListener) Enqueue() {
	l.queue.Add(syncKey)
}

// sync snapshots the providers' current CA content and, if it changed, builds
// a new transport and publishes it. On a build error it reports the error and
// leaves the last known-good transport in place. It is the only code that
// publishes transports.
func (t *dynamicTransport) sync() error {
	t.syncMu.Lock()
	defer t.syncMu.Unlock()
	defer t.syncs.Add(1)

	content := make([][]byte, 0, len(t.providers))
	for _, provider := range t.providers {
		content = append(content, bytes.Clone(provider.CurrentCABundleContent()))
	}
	if t.current.Load() != nil && slices.EqualFunc(content, t.publishedContent, bytes.Equal) {
		return nil
	}

	transport, err := t.config.newHTTPTransport(content)
	if err != nil {
		return err
	}

	old := t.current.Swap(transport)
	t.publishedContent = content
	if old != nil {
		old.CloseIdleConnections()
		klog.V(2).InfoS("Rebuilt outbound HTTP transport after CA content changed", "providers", t.providerNames())
	}
	return nil
}

func (t *dynamicTransport) providerNames() []string {
	names := make([]string, 0, len(t.providers))
	for _, provider := range t.providers {
		names = append(names, provider.Name())
	}
	return names
}

// run drives the transport until ctx is done: one worker processing the queue
// and a periodic resync as a safety net for missed notifications. It shuts
// down cleanly: the queue stops, an in-flight sync finishes, and run returns.
func (t *dynamicTransport) run(ctx context.Context) {
	defer close(t.done)
	defer utilruntime.HandleCrashWithContext(ctx)

	// Catch any change between the initial sync in the constructor and the
	// listener registration that follows it.
	t.queue.Add(syncKey)

	var workers sync.WaitGroup
	workers.Go(func() {
		wait.UntilWithContext(ctx, t.runWorker, time.Second)
	})
	workers.Go(func() {
		// A ticker, not wait.UntilWithContext: the resync must wait a full
		// interval before its first Add, since run already queues an initial
		// sync above.
		ticker := time.NewTicker(t.resyncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.queue.Add(syncKey)
			}
		}
	})

	<-ctx.Done()
	t.queue.ShutDown()
	workers.Wait()
}

func (t *dynamicTransport) runWorker(ctx context.Context) {
	for t.processNextWorkItem(ctx) {
	}
}

func (t *dynamicTransport) processNextWorkItem(ctx context.Context) bool {
	key, quit := t.queue.Get()
	if quit {
		return false
	}
	defer t.queue.Done(key)

	if err := t.sync(); err != nil {
		utilruntime.HandleErrorWithContext(ctx, err, "Unable to rebuild outbound HTTP transport; keeping the last known-good transport", "providers", t.providerNames())
		t.queue.AddRateLimited(key)
		return true
	}
	t.queue.Forget(key)
	return true
}
