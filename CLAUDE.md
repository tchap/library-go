# CLAUDE.md

## Project overview

openshift/library-go is a shared Go utility library for the OpenShift ecosystem. It provides helpers that convert APIs and clients into useful runtime constructs (e.g., `config.ServingInfo` to serving constructs). The inclusion bar is high: anything here must have concrete use-cases in at least two separate OpenShift repositories.

## Build commands

```
make build
make test-unit
make verify
make update
```

Single package tests:
```
go test -mod=vendor -race ./pkg/operator/certrotation/...
```

## Directory layout

- `pkg/` — library packages
- `test/` — E2E tests and shared test helpers
- `vendor/` — vendored dependencies (committed, required)

## Testing conventions

- Use the standard `testing` package with `*testing.T`.
- **Table-driven tests** are the dominant pattern. Follow this structure:

```go
func TestFoo(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected Bar
    }{
        {
            name:  "short description of case",
            input: "value",
            expected: Bar{
                Field: "result",
            },
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T) {
            got := Foo(test.input)
            if diff := cmp.Diff(test.expected, got); diff != "" {
                t.Errorf("unexpected result (-want +got):\n%s", diff)
            }
        })
    }
}
```

- Prefer assembling a complete expected object and comparing with `cmp.Diff` (`github.com/google/go-cmp`). Avoid complicated if/else trees for checking individual fields.
- `github.com/stretchr/testify` (`require.*` / `assert.*`) is also used in the codebase.
- Ginkgo is not used.
- Test data files go in `testdata/` directories adjacent to the test files.
- Reuse existing test helpers before creating new ones:
  - `pkg/operator/v1helpers/test_helpers.go` — fake informers, operator clients
  - `pkg/operator/csr/csrtestinghelpers/` — CSR testing utilities
  - `pkg/operator/events/eventstesting/` — event recorder testing
  - `pkg/manifestclienttest/` — manifest client testing
  - `test/library/` — shared E2E helpers

## Coding conventions

- Formatting enforced by `gofmt -s` via `make verify`.
- Logging uses `k8s.io/klog/v2`.
- Controllers follow the factory pattern in `pkg/controller/factory/`.
- Event recording uses `pkg/operator/events.Recorder`, not raw Kubernetes event recorders.
- Platform-specific code uses build tags (`//go:build linux` / `//go:build !linux`).

## Constraints

**Never:**
- Add `k8s.io/kubernetes` or `openshift/origin` as a dependency.
- Edit files under `vendor/` directly — always use `go mod tidy && go mod vendor`.
- Remove or weaken crypto, TLS, or authentication checks without explicit justification.

**Always:**
- Run `make verify` before considering a change complete.
- Run `go mod tidy && go mod vendor` after any dependency change.
- Use `-mod=vendor` when running `go` commands manually.
- Run the relevant package tests for changed packages.

## Security-sensitive packages

Changes to these packages affect authentication, encryption, and certificate handling across the OpenShift ecosystem. Review changes carefully and ensure test coverage:
- `pkg/crypto/` — certificate generation, TLS configuration
- `pkg/certs/` — certificate inspection and validation
- `pkg/authentication/` — bootstrap authenticators
- `pkg/authorization/` — scope metadata, hardcoded authorizers
- `pkg/operator/encryption/` — encryption controllers and key management
- `pkg/operator/certrotation/` — CA and serving certificate rotation
- `pkg/oauth/` — OAuth token handling

## Gotchas

- `GO_BUILD_PACKAGES_EXPANDED` is intentionally set without shell expansion because this is a library, not a binary project. Do not change this in the Makefile.
- `pkg/operator/connectivitycheckcontroller/` has its own Makefile that syncs a CRD from `openshift/api`. Its update/verify targets are wired into the top-level Makefile.
- Unit tests run with `-race` by default.
