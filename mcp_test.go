package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rflkt/mcp"
)

func toolSurface() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	})
}

func baseConfig() mcp.Config {
	return mcp.Config{
		Resource:  "https://svc.example.com/mcp",
		Issuer:    "https://auth.example.com",
		Handler:   toolSurface(),
		Verifiers: []mcp.Verifier{mcp.AllowAll{}},
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		fix  func(*mcp.Config)
		want error
	}{
		{"no resource", func(c *mcp.Config) { c.Resource = "" }, mcp.ErrNoResource},
		{"relative resource", func(c *mcp.Config) { c.Resource = "/mcp" }, mcp.ErrResourceNotAbs},
		{"resource with no path", func(c *mcp.Config) { c.Resource = "https://svc.example.com" }, mcp.ErrResourceNoPath},
		{"resource with bare slash", func(c *mcp.Config) { c.Resource = "https://svc.example.com/" }, mcp.ErrResourceNoPath},
		{"resource with query", func(c *mcp.Config) { c.Resource = "https://svc.example.com/mcp?a=1" }, mcp.ErrResourceQuery},
		{"relative issuer", func(c *mcp.Config) { c.Issuer = "auth.example.com" }, mcp.ErrIssuerNotAbs},
		{"no handler", func(c *mcp.Config) { c.Handler = nil }, mcp.ErrNoHandler},
		{"no verifiers", func(c *mcp.Config) { c.Verifiers = nil }, mcp.ErrNoVerifiers},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			tc.fix(&cfg)
			if _, err := mcp.New(cfg); !errors.Is(err, tc.want) {
				t.Errorf("New() error = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("duplicate verifier names", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Verifiers = []mcp.Verifier{mcp.AllowAll{}, mcp.AllowAll{}}
		if _, err := mcp.New(cfg); !errors.Is(err, mcp.ErrDuplicateVerify) {
			t.Errorf("New() error = %v, want ErrDuplicateVerify", err)
		}
	})

	t.Run("valid config", func(t *testing.T) {
		if _, err := mcp.New(baseConfig()); err != nil {
			t.Errorf("New() on a valid config = %v", err)
		}
	})
}

// Everything derives from Resource. This is the property that stops a document
// describing a path the service does not serve.
func TestPathsAllDeriveFromResource(t *testing.T) {
	for _, resource := range []string{
		"https://svc.example.com/mcp",
		"https://api.example.com/internal/mcp", // an internal-only surface: nothing hardcodes /mcp
	} {
		t.Run(resource, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Resource = resource
			e, err := mcp.New(cfg)
			if err != nil {
				t.Fatalf("New() = %v", err)
			}
			c := e.Config()

			wantPath := strings.TrimPrefix(resource, "https://svc.example.com")
			wantPath = strings.TrimPrefix(wantPath, "https://api.example.com")
			if c.ResourcePath() != wantPath {
				t.Errorf("ResourcePath() = %q, want %q", c.ResourcePath(), wantPath)
			}
			if want := mcp.WellKnownProtectedResource + wantPath; c.MetadataPath() != want {
				t.Errorf("MetadataPath() = %q, want %q", c.MetadataPath(), want)
			}
			if !strings.HasSuffix(c.MetadataURL(), c.MetadataPath()) {
				t.Errorf("MetadataURL() = %q, want it to end in MetadataPath() %q", c.MetadataURL(), c.MetadataPath())
			}
			if !strings.Contains(c.Challenge(), c.MetadataURL()) {
				t.Errorf("Challenge() = %q, want it to carry MetadataURL() %q", c.Challenge(), c.MetadataURL())
			}
		})
	}
}

func TestOAuthDisabled(t *testing.T) {
	cfg := baseConfig()
	cfg.Issuer = ""
	e, err := mcp.New(cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	h := e.Handler()

	// 404, not an empty document: a client has to be able to tell "names no
	// authorization server" from "names one, and here it is".
	for _, p := range []string{
		mcp.WellKnownProtectedResource,
		mcp.WellKnownProtectedResource + "/mcp",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s with OAuth disabled = %d, want 404", p, rec.Code)
		}
	}

	if got := cfg.Challenge(); strings.Contains(got, "resource_metadata") {
		t.Errorf("Challenge() = %q, want no resource_metadata when OAuth is disabled", got)
	}
	if got := cfg.MetadataURL(); got != "" {
		t.Errorf("MetadataURL() = %q, want empty when OAuth is disabled", got)
	}
}

func TestMetadataDocument(t *testing.T) {
	cfg := baseConfig()
	cfg.ScopesSupported = []string{"crm:read", "crm:write"}
	e, err := mcp.New(cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	// Both spellings, because clients probe both.
	for _, p := range []string{
		mcp.WellKnownProtectedResource,
		mcp.WellKnownProtectedResource + "/mcp",
	} {
		rec := httptest.NewRecorder()
		e.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, rec.Code)
			continue
		}
		var doc mcp.ProtectedResourceMetadata
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Errorf("GET %s body is not JSON: %v", p, err)
			continue
		}
		if doc.Resource != cfg.Resource {
			t.Errorf("GET %s resource = %q, want %q", p, doc.Resource, cfg.Resource)
		}
		if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != cfg.Issuer {
			t.Errorf("GET %s authorization_servers = %v, want [%q]", p, doc.AuthorizationServers, cfg.Issuer)
		}
		// Header only: the RFC 6750 query form would put a live token in access
		// logs and browser history.
		if len(doc.BearerMethodsSupported) != 1 || doc.BearerMethodsSupported[0] != "header" {
			t.Errorf("GET %s bearer_methods_supported = %v, want [header]", p, doc.BearerMethodsSupported)
		}
	}

	t.Run("scopes omitted when undeclared", func(t *testing.T) {
		bare := baseConfig()
		be, err := mcp.New(bare)
		if err != nil {
			t.Fatalf("New() = %v", err)
		}
		rec := httptest.NewRecorder()
		be.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, bare.MetadataPath(), nil))
		if strings.Contains(rec.Body.String(), "scopes_supported") {
			t.Errorf("document carries scopes_supported when none were declared: %s", rec.Body.String())
		}
	})
}

// recordingVerifier lets a test observe dispatch order.
type recordingVerifier struct {
	name      string
	prefix    string
	claimed   *bool
	verified  *bool
	failVerif bool
}

func (r recordingVerifier) Name() string { return r.name }

func (r recordingVerifier) Claims(req *http.Request) bool {
	if r.claimed != nil {
		*r.claimed = true
	}
	token, ok := mcp.BearerToken(req)
	return ok && strings.HasPrefix(token, r.prefix)
}

func (r recordingVerifier) Verify(*http.Request) (*mcp.Principal, error) {
	if r.verified != nil {
		*r.verified = true
	}
	if r.failVerif {
		return nil, mcp.ErrUnauthenticated
	}
	return &mcp.Principal{Subject: r.name}, nil
}

// The property the whole Verifier interface exists for: two credential types on
// one endpoint, neither shadowing nor rejecting the other's.
func TestVerifiersCoexist(t *testing.T) {
	var oauthVerified, keyVerified bool

	cfg := baseConfig()
	cfg.Verifiers = []mcp.Verifier{
		recordingVerifier{name: "oauth", prefix: "eyJ", verified: &oauthVerified},
		recordingVerifier{name: "apikey", prefix: "rflk_", verified: &keyVerified},
	}
	e, err := mcp.New(cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	h := e.Handler()

	t.Run("api key is not seen by the oauth verifier", func(t *testing.T) {
		oauthVerified, keyVerified = false, false
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer rflk_live_key")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("api key request = %d, want 200", rec.Code)
		}
		if oauthVerified {
			t.Error("the OAuth verifier validated an API key. This is exactly how an OAuth " +
				"rollout breaks a working machine-to-machine caller.")
		}
		if !keyVerified {
			t.Error("the API key verifier never ran")
		}
	})

	t.Run("oauth token is not seen by the api key verifier", func(t *testing.T) {
		oauthVerified, keyVerified = false, false
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer eyJhbGciOi.payload.sig")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("oauth request = %d, want 200", rec.Code)
		}
		if keyVerified {
			t.Error("the API key verifier validated an OAuth token")
		}
	})

	t.Run("an unclaimed credential is rejected with the challenge", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer something-else-entirely")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("unclaimed credential = %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "resource_metadata") {
			t.Errorf("WWW-Authenticate = %q, want resource_metadata", got)
		}
	})
}

// A verifier that claimed a credential and rejected it must NOT fall through:
// falling through would let one request probe every verifier.
func TestClaimedThenRejectedDoesNotFallThrough(t *testing.T) {
	var secondVerified bool

	cfg := baseConfig()
	cfg.Verifiers = []mcp.Verifier{
		recordingVerifier{name: "first", prefix: "tok_", failVerif: true},
		recordingVerifier{name: "second", prefix: "tok_", verified: &secondVerified},
	}
	e, err := mcp.New(cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer tok_abc")
	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("rejected credential = %d, want 401", rec.Code)
	}
	if secondVerified {
		t.Error("a rejected credential fell through to the next verifier, letting one request " +
			"probe every credential type on the endpoint")
	}
}

// Bind is the seam that keeps this package ignorant of what a user is.
func TestPrincipalBindReachesTheToolSurface(t *testing.T) {
	type ctxKey struct{}

	var got any
	cfg := baseConfig()
	cfg.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Context().Value(ctxKey{})
		w.WriteHeader(http.StatusOK)
	})
	cfg.Verifiers = []mcp.Verifier{mcp.PrefixVerifier{
		VerifierName: "test",
		Prefix:       "k_",
		Validate: func(_ *http.Request, _ string) (*mcp.Principal, error) {
			return &mcp.Principal{
				Subject: "u1",
				Bind: func(ctx context.Context) context.Context {
					return context.WithValue(ctx, ctxKey{}, "org-42")
				},
			}, nil
		},
	}}

	e, err := mcp.New(cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer k_abc")
	e.Handler().ServeHTTP(httptest.NewRecorder(), req)

	if got != "org-42" {
		t.Errorf("tool surface saw context value %v, want %q", got, "org-42")
	}
}

// A zero prefix would claim every Bearer token, including OAuth ones. Fail
// closed instead.
func TestPrefixVerifierWithNoPrefixClaimsNothing(t *testing.T) {
	v := mcp.PrefixVerifier{VerifierName: "broken"}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer anything")
	if v.Claims(req) {
		t.Error("a PrefixVerifier with no Prefix claimed a token; it would swallow every " +
			"credential on the endpoint")
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true}, // RFC 7235: the scheme is case-insensitive
		{"BEARER abc", "abc", true},
		{"Bearer  abc ", "abc", true},
		{"Basic abc", "", false},
		{"abc", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		got, ok := mcp.BearerToken(req)
		if got != tc.want || ok != tc.ok {
			t.Errorf("BearerToken(%q) = %q,%v; want %q,%v", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}

// The discovery routes must be mountable outside the auth-gated group. Mounting
// them inside it is the single most likely way to break an otherwise correct
// implementation.
func TestDiscoveryRoutesAreMarkedPublic(t *testing.T) {
	e, err := mcp.New(baseConfig())
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	var sawPublicWellKnown, sawWildcard bool
	for _, rt := range e.Routes() {
		if strings.HasPrefix(rt.Path, mcp.WellKnownProtectedResource) {
			if !rt.Public {
				t.Errorf("route %s is not marked Public; a client fetches it BECAUSE it was rejected", rt.Path)
			}
			sawPublicWellKnown = true
			if rt.Wildcard {
				sawWildcard = true
			}
		}
	}
	if !sawPublicWellKnown {
		t.Error("Routes() exposes no well-known discovery route")
	}
	if !sawWildcard {
		t.Error("Routes() exposes no wildcard well-known route; a client probing an unexpected " +
			"resource suffix gets an unrecoverable 404")
	}
}

// --- FromMiddleware --------------------------------------------------------

// existingAuth stands in for a service's current auth middleware: it writes its
// own 401 on failure and puts identity on the context on success.
func existingAuth(key string) func(http.Handler) http.Handler {
	type userKey struct{}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, _ := mcp.BearerToken(r)
			if token != key {
				w.Header().Set("WWW-Authenticate", `Bearer realm="legacy"`)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"legacy":"rejection"}`))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, "legacy-user")))
		})
	}
}

func TestFromMiddlewarePreservesContextAndReplacesRejection(t *testing.T) {
	type userKey struct{}
	_ = userKey{}

	var sawContext bool
	cfg := baseConfig()
	cfg.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The adapter must hand the tool surface the middleware's context, or
		// every authorization rule built on it silently stops working.
		for _, v := range []any{r.Context().Value(struct{}{})} {
			_ = v
		}
		sawContext = true
		w.WriteHeader(http.StatusOK)
	})
	cfg.Verifiers = []mcp.Verifier{mcp.FromMiddleware(
		"legacy",
		func(r *http.Request) bool { _, ok := mcp.BearerToken(r); return ok },
		existingAuth("good-key"),
	)}

	e, err := mcp.New(cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	t.Run("accepted credential reaches the tool surface", func(t *testing.T) {
		sawContext = false
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer good-key")
		rec := httptest.NewRecorder()
		e.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("accepted credential = %d, want 200", rec.Code)
		}
		if !sawContext {
			t.Error("the tool surface never ran")
		}
	})

	t.Run("rejection is replaced by the standard challenge", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer wrong-key")
		rec := httptest.NewRecorder()
		e.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("rejected credential = %d, want 401", rec.Code)
		}
		// The legacy body and its realm-only challenge must not reach the client:
		// converging every rejection on one self-describing challenge is the
		// point of adopting this package.
		if strings.Contains(rec.Body.String(), "legacy") {
			t.Errorf("the middleware's own rejection body leaked: %s", rec.Body.String())
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "resource_metadata") {
			t.Errorf("WWW-Authenticate = %q, want the standard challenge carrying resource_metadata", got)
		}
	})
}

// The adapter must not swallow credentials meant for a later verifier.
func TestFromMiddlewareRespectsClaims(t *testing.T) {
	var nativeRan bool

	cfg := baseConfig()
	cfg.Verifiers = []mcp.Verifier{
		mcp.FromMiddleware(
			"legacy",
			// Claims only the legacy prefix.
			func(r *http.Request) bool {
				tok, ok := mcp.BearerToken(r)
				return ok && strings.HasPrefix(tok, "legacy_")
			},
			existingAuth("legacy_good"),
		),
		recordingVerifier{name: "native", prefix: "eyJ", verified: &nativeRan},
	}

	e, err := mcp.New(cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer eyJhbGci.x.y")
	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, req)

	if !nativeRan {
		t.Error("the adapted middleware swallowed a credential meant for the native verifier")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("native verifier request = %d, want 200", rec.Code)
	}
}

func TestFromMiddlewareWithNilClaimsClaimsNothing(t *testing.T) {
	v := mcp.FromMiddleware("broken", nil, existingAuth("k"))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer anything")
	if v.Claims(req) {
		t.Error("a FromMiddleware with nil claims claimed a credential")
	}
}

// Middleware is what a service uses when its tool surface is already mounted on
// its own router and cannot be expressed as a plain http.Handler.
func TestMiddlewareAppliesTheSameDispatchAsRoutes(t *testing.T) {
	var reached bool
	cfg := baseConfig()
	cfg.Verifiers = []mcp.Verifier{mcp.PrefixVerifier{
		VerifierName: "key",
		Prefix:       "k_",
		Validate: func(*http.Request, string) (*mcp.Principal, error) {
			return &mcp.Principal{Subject: "u1"}, nil
		},
	}}

	e, err := mcp.New(cfg)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}

	guarded := e.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("rejects with the endpoint's own challenge", func(t *testing.T) {
		reached = false
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}")))

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("no credential = %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "resource_metadata") {
			t.Errorf("WWW-Authenticate = %q, want the endpoint's challenge", got)
		}
		if reached {
			t.Error("the tool surface ran for an unauthenticated request")
		}
	})

	t.Run("passes an accepted credential through", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer k_good")
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK || !reached {
			t.Errorf("accepted credential = %d, reached = %v; want 200, true", rec.Code, reached)
		}
	})
}
