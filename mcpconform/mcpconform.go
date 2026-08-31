// Package mcpconform asserts that a service's real MCP endpoint behaves.
//
// This is the enforcement half of the mcp package. It is deliberately
// BEHAVIORAL: it drives the caller's actual http.Handler with actual requests,
// rather than inspecting source.
//
// The predecessor of this package was a CI script that grepped for strings, and
// it failed the way source inspection always fails. It collected exemptions. It
// missed a service whose endpoint path was "/internal/mcp", because the grep
// looked for "/mcp". And it passed a service whose 401 named a discovery
// document at a URL nothing served, because the string it searched for was
// present -- elsewhere in the repository.
//
// A string being present proves nothing. This package proves that a client which
// gets a 401 can follow the challenge to a document that is actually served, and
// that the document describes the path that actually exists.
//
// # Usage
//
//	func TestMCPConformance(t *testing.T) {
//	    mcpconform.Assert(t, app.Router(), mcpconform.Expect{
//	        Resource:      "https://api.example.com/mcp",
//	        Profile:       mcpconform.FirstParty,
//	        OperatorHosts: []string{"example.com"},
//	    })
//	}
//
// Mount the endpoint on a router the same way production does. Handing this a
// specially-built handler proves something about that handler and nothing about
// the service.
package mcpconform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// Profile asserts WHO is allowed to authenticate this endpoint's callers.
//
// It is not a setting on mcp.Config. Which authorization server an endpoint
// trusts is a fact about how it was built -- which Verifier was constructed --
// and stating it here keeps that a property the test checks rather than a switch
// the code carries.
//
// The distinction matters for anyone who ships software they also operate. An
// endpoint you run may reasonably trust your own issuer. The same code shipped
// to a customer to run themselves must not, or their deployment stops working
// the day you retire that issuer, and is quietly coupled to you until then.
type Profile int

const (
	// AnyIssuer skips the profile assertions. The zero value, so a caller who
	// has not thought about it is not held to a rule they did not choose.
	AnyIssuer Profile = iota

	// FirstParty expects the authorization server to be one the operator runs,
	// named by Expect.OperatorHosts.
	FirstParty

	// ThirdParty expects the authorization server NOT to be one the operator
	// runs. This is the profile for software shipped to someone else to
	// operate: it must authenticate against their issuer, not yours.
	ThirdParty
)

func (p Profile) String() string {
	switch p {
	case FirstParty:
		return "FirstParty"
	case ThirdParty:
		return "ThirdParty"
	default:
		return "AnyIssuer"
	}
}

// Expect describes what the endpoint under test should look like.
type Expect struct {
	// Resource is the RFC 8707 resource indicator, the same absolute URL passed
	// to mcp.Config. Required.
	Resource string

	// Profile selects the profile-specific assertions. Defaults to Internal.
	Profile Profile

	// Issuer, when set, is asserted to be the authorization server named in the
	// discovery document. Optional; the profile assertions run regardless.
	Issuer string

	// OAuthDisabled says this deployment configures no authorization server. The
	// suite then requires both discovery paths to 404 and the challenge to omit
	// resource_metadata, rather than requiring a document.
	OAuthDisabled bool

	// Credential, when non-nil, is applied to a request to make it authentic.
	// The suite uses it to prove the happy path still works, which is the
	// assertion that catches an auth change breaking a machine-to-machine
	// caller. Optional but strongly recommended.
	Credential func(*http.Request)

	// OperatorHosts are the hosts the operator of this endpoint runs, matched
	// against the authorization server's host on a label boundary so that
	// "notexample.com" does not match "example.com".
	//
	// Required when Profile is not AnyIssuer. There is deliberately no default:
	// a library cannot know whose infrastructure is whose, and a guessed default
	// would make the profile assertion either vacuous or wrong.
	OperatorHosts []string
}

// reporter is what the checks report through.
//
// Its own interface rather than testing.TB, which carries an unexported method
// and so cannot be implemented outside the testing package. That matters here
// for one reason: a conformance suite nobody can test is a conformance suite
// nobody should trust, and mcpconform_test.go drives these checks against
// deliberately broken handlers to prove each failure is actually caught.
//
// Fatalf and Fatal must abort the current check. *testing.T does this by
// Goexit; the test fake panics with a sentinel and recovers.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Fatal(args ...any)
	Skip(args ...any)
}

// Assert runs the conformance suite against h.
//
// It reports failures through t and does not stop the test, so one run surfaces
// every problem rather than the first.
func Assert(t *testing.T, h http.Handler, e Expect) {
	t.Helper()

	if h == nil {
		t.Fatal("mcpconform: handler is nil")
	}
	if e.Resource == "" {
		t.Fatal("mcpconform: Expect.Resource is required")
	}
	resourceURL, err := url.Parse(e.Resource)
	if err != nil || resourceURL.Path == "" || resourceURL.Path == "/" {
		t.Fatalf("mcpconform: Expect.Resource %q must be an absolute URL including the endpoint path", e.Resource)
	}
	path := resourceURL.Path

	t.Run("unauthenticated POST is rejected with a challenge", func(t *testing.T) {
		checkChallenge(t, h, path, e)
	})

	t.Run("discovery document", func(t *testing.T) {
		checkDiscovery(t, h, path, e)
	})

	t.Run("profile "+e.Profile.String(), func(t *testing.T) {
		checkProfile(t, h, path, e)
	})

	if e.Credential != nil {
		t.Run("a valid credential is accepted", func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(initializeBody))
			req.Header.Set("Content-Type", "application/json")
			e.Credential(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("a credentialled request was rejected with %d; an auth change has broken a working caller", rec.Code)
			}
		})
	}
}

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcpconform","version":"1"}}}`

// challengeParam pulls one parameter out of a WWW-Authenticate value.
var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

func parseChallenge(v string) map[string]string {
	out := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(v, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func checkChallenge(t reporter, h http.Handler, path string, e Expect) {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(initializeBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST %s with no credential = %d, want 401. An MCP endpoint that answers an "+
			"unauthenticated caller is serving its tools to anyone who finds the URL.", path, rec.Code)
	}

	raw := rec.Header().Get("WWW-Authenticate")
	if raw == "" {
		t.Fatal("401 carries no WWW-Authenticate header, so a client cannot discover how to authenticate")
	}
	if !strings.HasPrefix(strings.ToLower(raw), "bearer") {
		t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", raw)
	}

	params := parseChallenge(raw)
	metadataURL, hasMetadata := params["resource_metadata"]

	if e.OAuthDisabled {
		if hasMetadata {
			t.Errorf("OAuth is disabled but the challenge advertises resource_metadata=%q. "+
				"That points a client at a document this service does not serve, which reads as a "+
				"broken server rather than one that offers no OAuth.", metadataURL)
		}
		return
	}

	if !hasMetadata {
		t.Fatalf("challenge %q carries no resource_metadata. Publishing a discovery document "+
			"achieves nothing if the 401 never names its URL.", raw)
	}

	// The assertion that matters most, and the one no grep can make: the URL in
	// the challenge must resolve, on this same handler, to a real document.
	mu, err := url.Parse(metadataURL)
	if err != nil {
		t.Fatalf("resource_metadata=%q is not a URL: %v", metadataURL, err)
	}
	doc, code := fetchMetadata(t, h, mu.Path)
	if code != http.StatusOK {
		t.Fatalf("the challenge names resource_metadata=%q but %s returns %d on this handler. "+
			"The client is being sent to a dead page.", metadataURL, mu.Path, code)
	}
	if doc.Resource != e.Resource {
		t.Errorf("the document at the advertised URL describes resource %q, but this endpoint is %q. "+
			"A document that names a path the service does not serve looks correct until a client fails on it.",
			doc.Resource, e.Resource)
	}
}

type metadataDoc struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
}

func fetchMetadata(t reporter, h http.Handler, path string) (doc metadataDoc, status int) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Errorf("GET %s returned 200 but the body is not JSON: %v", path, err)
		}
	}
	return doc, rec.Code
}

func checkDiscovery(t reporter, h http.Handler, path string, e Expect) {
	t.Helper()

	const bare = "/.well-known/oauth-protected-resource"
	suffixed := bare + path

	if e.OAuthDisabled {
		for _, p := range []string{bare, suffixed} {
			if _, code := fetchMetadata(t, h, p); code != http.StatusNotFound {
				t.Errorf("OAuth is disabled but GET %s = %d, want 404. An empty or stub document "+
					"is not distinguishable from a real one by a client deciding whether to start an "+
					"OAuth flow.", p, code)
			}
		}
		return
	}

	// Both spellings must work. RFC 9728 section 3 makes the suffixed form
	// canonical, but clients probe the bare path too and a 404 on the one they
	// tried is unrecoverable.
	for _, p := range []string{suffixed, bare} {
		doc, code := fetchMetadata(t, h, p)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200. Clients probe both the bare and the resource-suffixed "+
				"well-known path.", p, code)
			continue
		}
		if doc.Resource != e.Resource {
			t.Errorf("GET %s describes resource %q, want %q", p, doc.Resource, e.Resource)
		}
		if len(doc.AuthorizationServers) == 0 {
			t.Errorf("GET %s names no authorization_servers, so the document tells a client nothing "+
				"it did not already know", p)
		}
		if e.Issuer != "" && !contains(doc.AuthorizationServers, e.Issuer) {
			t.Errorf("GET %s names authorization_servers %v, want it to include %q",
				p, doc.AuthorizationServers, e.Issuer)
		}
	}

	// The document is fetched BECAUSE a client was rejected. Gating it behind
	// the credential it is trying to obtain closes the loop it exists to open,
	// and it is the single most likely way to break an otherwise correct
	// implementation: mounting the route inside the auth-gated group.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, suffixed, http.NoBody)
	req.Header.Set("Authorization", "Bearer definitely-not-a-valid-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Errorf("GET %s with a bad credential = %d. The discovery document must be public: it is "+
			"what an unauthenticated client reads to find out how to authenticate.", suffixed, rec.Code)
	}
}

func checkProfile(t reporter, h http.Handler, path string, e Expect) {
	t.Helper()

	if e.Profile == AnyIssuer {
		t.Skip("Profile is AnyIssuer, so no issuer assertion applies")
	}
	if e.OAuthDisabled {
		t.Skip("no authorization server configured, so there is no issuer to hold to a profile")
	}

	doc, code := fetchMetadata(t, h, "/.well-known/oauth-protected-resource"+path)
	if code != http.StatusOK {
		return // already reported by checkDiscovery
	}

	if len(e.OperatorHosts) == 0 {
		t.Fatalf("mcpconform: Profile %s needs Expect.OperatorHosts to say which hosts you operate; "+
			"without it the assertion cannot mean anything", e.Profile)
	}

	for _, as := range doc.AuthorizationServers {
		u, err := url.Parse(as)
		if err != nil {
			t.Errorf("authorization_servers entry %q is not a URL: %v", as, err)
			continue
		}
		if u.Scheme != "https" && !isLoopback(u.Hostname()) {
			t.Errorf("authorization server %q is not https. A token endpoint reached over plaintext "+
				"hands the credential to anyone on the path.", as)
		}

		ours := hostMatches(u.Hostname(), e.OperatorHosts)
		switch e.Profile {
		case ThirdParty:
			if ours {
				t.Errorf("ThirdParty profile, but the discovery document names an authorization server "+
					"you operate, %q. Software shipped to someone else to run must authenticate against "+
					"THEIR issuer: as written, their deployment stops working the day you retire that "+
					"one, and is silently coupled to you until then.", as)
			}
		case FirstParty:
			if !ours {
				t.Errorf("FirstParty profile, but the discovery document names an authorization server "+
					"you do not operate, %q. If that is deliberate, this endpoint is ThirdParty and "+
					"should say so.", as)
			}
		case AnyIssuer:
		}
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// hostMatches reports whether host is one of the suffixes, or a subdomain of
// one. Compared on a label boundary so "notexample.com" does not match
// "example.com", and so "example.com.evil.test" does not either.
func hostMatches(host string, suffixes []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range suffixes {
		s = strings.ToLower(s)
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
