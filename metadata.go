package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ProtectedResourceMetadata is the RFC 9728 protected-resource metadata
// document.
//
// Only fields this package can answer honestly are present. RFC 9728 makes
// everything but `resource` optional, and an omitted field is always better than
// an invented one: a client that trusts a fabricated value fails at the
// authorization server, far from anyone who could diagnose it.
type ProtectedResourceMetadata struct {
	// Resource is the RFC 8707 resource indicator this document describes.
	Resource string `json:"resource"`

	// AuthorizationServers names the issuer that mints tokens for it.
	AuthorizationServers []string `json:"authorization_servers"`

	// BearerMethodsSupported is always ["header"]. RFC 6750 also allows the
	// credential in a form body or a query parameter; the query form would put a
	// live token in access logs, proxy logs and browser history, so this package
	// does not offer it and says so rather than staying silent.
	BearerMethodsSupported []string `json:"bearer_methods_supported"`

	// ScopesSupported is omitted when the service did not declare any.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
}

// Metadata builds the discovery document for this configuration.
func (c Config) Metadata() ProtectedResourceMetadata {
	return ProtectedResourceMetadata{
		Resource:               c.Resource,
		AuthorizationServers:   []string{c.Issuer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        c.ScopesSupported,
	}
}

// metadataHandler serves the RFC 9728 document, or 404 when OAuth is off.
func (e *Endpoint) metadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OPTIONS is answered rather than 405'd: this document is fetched
		// cross-origin by browser-based clients, which preflight it.
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !e.cfg.OAuthEnabled() {
			// See Config.Issuer for why this is a 404 and not an empty
			// document.
			http.NotFound(w, r)
			return
		}

		body, err := json.Marshal(e.cfg.Metadata())
		if err != nil {
			http.Error(w, "failed to encode metadata", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Cacheable: the document changes only on redeploy with a different
		// issuer, and a client refetches it on every 401.
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body) //nolint:errcheck // headers are already flushed; a failed write has no recovery
	})
}

// Challenge is the WWW-Authenticate value for a rejected request.
//
// It carries resource_metadata only when OAuth is configured. Naming a document
// that would 404 is worse than omitting the parameter: it sends the client to a
// dead page instead of telling it plainly that this endpoint offers no OAuth.
func (c Config) Challenge() string {
	params := []string{`error="invalid_token"`}
	if url := c.MetadataURL(); url != "" {
		params = append(params, fmt.Sprintf("resource_metadata=%q", url))
	}
	return "Bearer " + strings.Join(params, ", ")
}
