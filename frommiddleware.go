package mcp

import (
	"context"
	"net/http"
)

// FromMiddleware adapts an existing authentication middleware into a Verifier.
//
// # Why this exists
//
// Every service that already serves MCP authenticates it with a middleware:
// something shaped func(http.Handler) http.Handler that either writes a 401 or
// puts identity on the context and calls next. A Verifier is shaped differently
// on purpose — it RETURNS a principal rather than deciding the response — because
// that is what lets several credential types share one endpoint.
//
// Rewriting a service's auth into native Verifiers as part of adopting this
// package would mean changing production authentication and changing the
// endpoint in one step. This adapter separates those: adopt the endpoint first with the existing
// middleware unchanged, then graduate to a native Verifier as its own change with
// its own review. Prefer a native Verifier for anything new.
//
// # What it changes, and what it does not
//
// The middleware's own rejection response is DISCARDED and replaced by this
// package's standard 401 and challenge. That is a deliberate behavior change and
// the main point of converging on one convention: every rejection from every
// credential type now carries the same challenge, so a client learns where to
// authenticate no matter which path refused it. Services whose 401 body is part
// of a contract should check that before adopting.
//
// Everything the middleware puts on the request context is preserved and reaches
// the tool surface, so authorization built on that context keeps working
// untouched.
//
// # claims
//
// claims must identify this credential WITHOUT validating it, the same contract
// as Verifier.Claims. Passing a claims that returns true unconditionally makes
// this verifier swallow every credential on the endpoint, including ones meant
// for a later verifier — which is the exact failure the Verifier interface exists
// to prevent. If a middleware genuinely handles every credential, it is the only
// verifier and there is nothing to disambiguate.
func FromMiddleware(name string, claims func(*http.Request) bool, mw func(http.Handler) http.Handler) Verifier {
	return middlewareVerifier{name: name, claims: claims, mw: mw}
}

type middlewareVerifier struct {
	name   string
	claims func(*http.Request) bool
	mw     func(http.Handler) http.Handler
}

func (m middlewareVerifier) Name() string { return m.name }

func (m middlewareVerifier) Claims(r *http.Request) bool {
	if m.claims == nil {
		return false
	}
	return m.claims(r)
}

func (m middlewareVerifier) Verify(r *http.Request) (*Principal, error) {
	if m.mw == nil {
		return nil, ErrUnauthenticated
	}

	// The middleware signals success by calling next. Capture the request it
	// hands on, because that is where it put the identity.
	var passed *http.Request
	sentinel := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		passed = req
	})

	// A sink rather than the real ResponseWriter: on rejection the middleware
	// writes its own 401, and letting that reach the client would produce a
	// response with neither this package's challenge nor its body. On success
	// a well-behaved middleware writes nothing, so there is nothing to lose.
	sink := &discardWriter{header: http.Header{}}
	m.mw(sentinel).ServeHTTP(sink, r)

	if passed == nil {
		return nil, ErrUnauthenticated
	}

	ctx := passed.Context()
	return &Principal{
		Subject: subjectFromContext(ctx),
		Bind: func(context.Context) context.Context {
			// The middleware's context, not one derived from the caller's. It
			// already descends from this request's context — it is the same
			// request — and rebuilding it would drop whatever the middleware
			// installed, which is the only reason this adapter exists.
			return ctx
		},
	}, nil
}

// subjectFromContext is best-effort. The adapter cannot know where a given
// service stores its caller id, so Subject is left empty rather than guessed;
// it is used for logging only, and a wrong value there is worse than none.
func subjectFromContext(context.Context) string { return "" }

// discardWriter swallows whatever a rejecting middleware writes.
type discardWriter struct {
	header http.Header
}

func (d *discardWriter) Header() http.Header         { return d.header }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}
