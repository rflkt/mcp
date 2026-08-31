package mcp

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownProtectedResource is the RFC 9728 discovery path.
const WellKnownProtectedResource = "/.well-known/oauth-protected-resource"

// Configuration errors. Returned from New, never panicked: a misconfigured
// endpoint has to surface in the caller's startup error path, where the caller
// can decide whether to refuse to start.
var (
	ErrNoResource      = errors.New("mcp: Resource is required")
	ErrResourceNotAbs  = errors.New("mcp: Resource must be an absolute URL with a host")
	ErrResourceNoPath  = errors.New("mcp: Resource must include the endpoint path, for example https://host/mcp")
	ErrResourceQuery   = errors.New("mcp: Resource must not carry a query or fragment")
	ErrNoHandler       = errors.New("mcp: Handler is required")
	ErrIssuerNotAbs    = errors.New("mcp: Issuer must be an absolute URL with a host")
	ErrNoVerifiers     = errors.New("mcp: at least one Verifier is required")
	ErrVerifierNoName  = errors.New("mcp: every Verifier must return a non-empty Name")
	ErrDuplicateVerify = errors.New("mcp: Verifier names must be unique")
)

// Config describes one MCP endpoint.
type Config struct {
	// Resource is the RFC 8707 resource indicator: the absolute URL clients
	// reach this endpoint on, path included. For example
	// "https://api.example.com/mcp" or, for an internal-only surface,
	// "https://api.example.com/internal/mcp".
	//
	// Everything derives from this. See the package doc for why that matters
	// more than any other property here.
	//
	// It must agree exactly with the `resource` parameter clients send and with
	// the `aud` claim the issuer mints, because those are compared byte for
	// byte. Deriving it from the URL clients already reach you on is what keeps
	// the three in step; a separate setting is one more thing to get wrong per
	// environment, with a 401 at the far end as the only symptom.
	Resource string

	// Issuer is the authorization server that mints tokens for this resource.
	//
	// Empty disables the OAuth surface entirely: the discovery documents 404 and
	// the challenge omits resource_metadata. That is a SUPPORTED state, not a
	// degraded one, and 404 is the correct answer rather than an empty document.
	// "This service names no authorization server" and "this service names one,
	// and here it is" have to be distinguishable to a client deciding whether to
	// begin an OAuth flow at all. Advertising a token endpoint that does not
	// exist reads as a broken server, which is worse than offering no OAuth.
	Issuer string

	// ScopesSupported is advertised in the discovery document. Optional, and
	// omitted when empty.
	//
	// Do not populate it with scopes the issuer will not actually grant. An
	// invented list is worse than an absent one: a client that trusts it asks
	// for a scope it cannot have, and the failure surfaces at the authorization
	// server rather than here, where nobody is looking.
	ScopesSupported []string

	// Verifiers authenticate callers, tried in the order given. The first whose
	// Claims reports true owns the request and no later verifier sees it.
	//
	// This ordering is the whole mechanism by which credential types coexist. A
	// service accepting both a pre-shared API key and OAuth tokens lists both;
	// because Claims runs before any validation, neither shadows the other and
	// neither can reject a credential that was never meant for it. Getting this
	// wrong is how an OAuth rollout silently breaks a machine-to-machine caller
	// that was working perfectly.
	Verifiers []Verifier

	// Handler is the JSON-RPC tool surface. It is reached only after a Verifier
	// has accepted the request, and it can rely on Principal.Bind having run.
	Handler http.Handler

	// Unauthenticated, when non-nil, answers non-POST requests to the resource
	// path. It exists because people paste the connection address into a browser
	// to check it works, and an empty 405 tells them nothing. Optional; without
	// it a GET gets a bare 405, which is still correct for a probing client.
	Unauthenticated http.Handler
}

// ResourcePath is the path component of Resource: where the endpoint mounts.
func (c Config) ResourcePath() string {
	u, err := url.Parse(c.Resource)
	if err != nil {
		return ""
	}
	return u.Path
}

// ResourceOrigin is Resource with its path removed.
func (c Config) ResourceOrigin() string {
	u, err := url.Parse(c.Resource)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// MetadataPath is where this endpoint's RFC 9728 document is served.
//
// RFC 9728 section 3 forms the URL by inserting the well-known segment between
// the resource's host and its path, so a resource at /mcp is described at
// /.well-known/oauth-protected-resource/mcp, NOT at the bare well-known path.
// Both are served (see Routes) because clients probe both, but this is the
// canonical one and the one the challenge advertises.
func (c Config) MetadataPath() string {
	return WellKnownProtectedResource + c.ResourcePath()
}

// MetadataURL is the absolute URL of the discovery document, as advertised in
// the WWW-Authenticate challenge. Empty when OAuth is disabled.
func (c Config) MetadataURL() string {
	if !c.OAuthEnabled() {
		return ""
	}
	return c.ResourceOrigin() + c.MetadataPath()
}

// OAuthEnabled reports whether an authorization server is configured.
func (c Config) OAuthEnabled() bool {
	return c.Issuer != ""
}

// validate checks the configuration at startup.
func (c Config) validate() error {
	if c.Resource == "" {
		return ErrNoResource
	}
	u, err := url.Parse(c.Resource)
	if err != nil {
		return fmt.Errorf("mcp: Resource is not a URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return ErrResourceNotAbs
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return ErrResourceQuery
	}
	// A resource of "https://host" would produce a metadata path of exactly the
	// bare well-known path and a mount path of "", which no router can serve and
	// no client can match.
	if u.Path == "" || u.Path == "/" {
		return ErrResourceNoPath
	}
	if c.Issuer != "" {
		iu, ierr := url.Parse(c.Issuer)
		if ierr != nil {
			return fmt.Errorf("mcp: Issuer is not a URL: %w", ierr)
		}
		if iu.Scheme == "" || iu.Host == "" {
			return ErrIssuerNotAbs
		}
	}
	if c.Handler == nil {
		return ErrNoHandler
	}
	if len(c.Verifiers) == 0 {
		// Deliberately an error rather than a permissive default. An endpoint
		// with no verifier would serve every tool to anyone who found the URL.
		// A service that genuinely wants that (a local dev transport) passes
		// AllowAll explicitly, so the decision is visible at the call site and
		// greppable in review.
		return ErrNoVerifiers
	}
	seen := make(map[string]bool, len(c.Verifiers))
	for _, v := range c.Verifiers {
		name := strings.TrimSpace(v.Name())
		if name == "" {
			return ErrVerifierNoName
		}
		if seen[name] {
			return fmt.Errorf("%w: %q", ErrDuplicateVerify, name)
		}
		seen[name] = true
	}
	return nil
}
