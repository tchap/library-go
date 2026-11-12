// Package dynamictransport builds outbound HTTP round trippers whose CA trust
// can follow dynamically reloaded CA content providers.
//
// # Static and dynamic transports
//
// New returns a static *http.Transport when no CA content provider is
// supplied, and a wrapper when one or more are. The concrete type of the
// returned http.RoundTripper is not part of the API, but the static path
// returns a plain *http.Transport and starts no goroutines. The wrapper
// forwards CloseIdleConnections, so http.Client.CloseIdleConnections works in
// either case.
//
// # Trust sources
//
// The trust pool is assembled from the base pool (WithCertPool, defaulting to
// the system pool), static PEM data (WithCAData, WithCAFile), and the current
// bundles of the CA content providers (WithCAContentProvider). All sources are
// combined. WithCertPool replaces the system pool entirely, so it can be used
// to pin trust to exactly the supplied certificates.
//
// # Rebuild semantics
//
// When a provider reports a change, the wrapper rebuilds in the background:
// it snapshots every provider's current bundle, builds a new transport from
// that snapshot, and swaps it in for new connections. There is at most one
// pending rebuild (a burst of notifications collapses into it), rebuilds are
// serialized, and a failed build is retried with backoff. If the new content
// cannot be parsed, the previous transport stays in use until a rebuild
// succeeds. Connections already established are not re-verified; idle
// connections held by the replaced transport are closed.
//
// Unlike pkg/network/httptransport, which rebuilt synchronously inside the
// provider's notification, the rebuild here is asynchronous: for a short
// window after a provider reports a change, the previous trust is still in
// use.
//
// A periodic resync bounds how long a missed provider notification can go
// unnoticed.
//
// # Lifecycle
//
// New takes a context. When the context is done, the wrapper stops following
// its providers (notifications are ignored) and keeps serving the last
// transport it built. Callers that want a fresh trust state should build a new
// round tripper.
//
// A dynamic round tripper is not cheap to create: each one starts a small set
// of goroutines and timers that live until its context is done, and registers
// a listener entry with each provider that the providers never remove. Build
// round trippers once per provider set, not per request or per configuration
// reload, and scope their context accordingly.
//
// Callers own the lifecycle of supplied CA content providers. Construct all
// round trippers before starting the providers' Run, and do not construct
// round trippers concurrently on the same provider: the dynamiccertificates
// providers do not synchronize AddListener, so adding a listener to a running
// provider is a data race and a concurrent add can lose a listener.
package dynamictransport
