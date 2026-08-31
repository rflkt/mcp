package mcp

import (
	"net/http"
)

// Endpoint is a configured MCP endpoint. Build one with New and mount its
// Routes.
type Endpoint struct {
	cfg Config
}

// New validates the configuration and returns the endpoint.
//
// It returns an error rather than panicking or degrading, so a misconfiguration
// surfaces at startup in the caller's normal error path — the same contract as
// platform.Wrap and oauth.Middleware. Build this at boot, not per request: a bad
// resource indicator should be a pod that will not start, not a 500 on
// somebody's first tool call.
func New(cfg Config) (*Endpoint, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Endpoint{cfg: cfg}, nil
}

// Config returns the endpoint's configuration.
func (e *Endpoint) Config() Config { return e.cfg }

// Route is one mountable route.
//
// Path and Wildcard are given separately because routers spell a catch-all
// differently -- "/*resource", "/*", "/{rest...}" -- and this package privileges
// none of them. A caller mounting a Wildcard route appends its own router's
// spelling to Path.
type Route struct {
	// Method is the HTTP method, or "" meaning every method (the handler
	// answers OPTIONS and rejects the rest itself).
	Method string

	// Path is the route path.
	Path string

	// Wildcard reports that this route must also match anything below Path.
	Wildcard bool

	// Handler serves the route.
	Handler http.Handler

	// Public reports that the route must NOT be placed behind authentication.
	//
	// Load-bearing, not documentation. The discovery document is fetched by a
	// client BECAUSE it was rejected, so gating it behind the credential it is
	// trying to obtain closes the loop it exists to open. Mounting a Public
	// route inside an auth-gated group is the single most likely way to break
	// an otherwise correct implementation, and it fails in a way that looks
	// like a client bug.
	Public bool
}

// Routes returns everything this endpoint needs mounted.
//
// The discovery document is served at BOTH the resource-suffixed path (the
// canonical RFC 9728 section 3 form, and the one the challenge advertises) and
// the bare well-known path, because clients probe both and a 404 on the one they
// happened to try is unrecoverable. The bare route is a Wildcard so that any
// resource suffix resolves, which is strictly better than enumerating the
// suffixes you expect: a client probing one you did not think of gets the
// document rather than a 404 it cannot recover from.
func (e *Endpoint) Routes() []Route {
	metadata := e.metadataHandler()

	routes := []Route{
		{
			Method:  http.MethodPost,
			Path:    e.cfg.ResourcePath(),
			Handler: e.authenticated(e.cfg.Handler),
		},
		{
			Path:    WellKnownProtectedResource,
			Handler: metadata,
			Public:  true,
		},
		{
			Path:     WellKnownProtectedResource,
			Wildcard: true,
			Handler:  metadata,
			Public:   true,
		},
	}

	if e.cfg.Unauthenticated != nil {
		// Public: someone pasting the connection address into a browser has, by
		// definition, not authenticated yet, and a 401 on the page that explains
		// how to authenticate is a poor joke.
		routes = append(routes, Route{
			Method:  http.MethodGet,
			Path:    e.cfg.ResourcePath(),
			Handler: e.cfg.Unauthenticated,
			Public:  true,
		})
	}

	return routes
}

// Handler mounts Routes on a standard library mux.
//
// Provided for services with no router of their own, and for mcpconform, which
// needs to drive a complete endpoint without knowing anything about the caller's
// routing. A service that already has a router should use Routes instead: this
// cannot express that router's middleware.
func (e *Endpoint) Handler() http.Handler {
	mux := http.NewServeMux()

	// Register the most specific patterns first. Go 1.22+ ServeMux resolves by
	// specificity rather than registration order, but the wildcard and its base
	// path would otherwise be ambiguous to a reader.
	for _, rt := range e.Routes() {
		pattern := rt.Path
		if rt.Wildcard {
			pattern = rt.Path + "/"
		}
		if rt.Method != "" {
			pattern = rt.Method + " " + pattern
		}
		mux.Handle(pattern, rt.Handler)
	}

	return mux
}

// Middleware returns the endpoint's credential dispatch as ordinary middleware,
// for a service whose tool surface is already mounted on its own router.
//
// Routes is the better choice when you can use it: it mounts the tool surface
// and the discovery documents together, so the two cannot drift apart. Reach for
// this when the tool surface is a handler your router already owns and cannot be
// expressed as a plain http.Handler -- a framework handler taking that
// framework's own context, typically -- in which case mount this in front of it
// and mount the Public routes from Routes separately.
//
// The wrapped handler runs only after a Verifier has accepted the request, and
// can rely on Principal.Bind having run. A rejection produces this package's 401
// and challenge, exactly as it would through Routes.
func (e *Endpoint) Middleware() func(http.Handler) http.Handler {
	return e.authenticated
}

// authenticated wraps the tool surface in credential dispatch.
func (e *Endpoint) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, v := range e.cfg.Verifiers {
			if !v.Claims(r) {
				continue
			}
			// First claim wins. A verifier that claimed a credential and then
			// rejected it does NOT fall through to the next one: falling
			// through would turn a revoked key into an attempt to interpret it
			// as some other credential type, and would let a caller probe every
			// verifier with one request.
			principal, err := v.Verify(r)
			if err != nil || principal == nil {
				e.reject(w)
				return
			}
			if principal.Bind != nil {
				r = r.WithContext(principal.Bind(r.Context()))
			}
			next.ServeHTTP(w, r)
			return
		}
		// No verifier claimed the credential, including the case of no
		// credential at all.
		e.reject(w)
	})
}

// reject writes the 401 and its challenge.
func (e *Endpoint) reject(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", e.cfg.Challenge())
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	// A JSON-RPC shaped body, because the caller is a JSON-RPC client and a bare
	// string forces it to special-case the transport error. -32001 matches what
	// the fleet's hand-rolled endpoints already return for auth failures.
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"unauthorized"},"id":null}`)) //nolint:errcheck // the client is already gone if this fails; there is nothing to report it to
}
