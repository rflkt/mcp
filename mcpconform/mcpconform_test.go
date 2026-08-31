package mcpconform

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// fakeT records what a check reported, so the suite can be tested against
// deliberately broken handlers.
//
// This file is the reason mcpconform is worth trusting. A conformance suite that
// is never itself tested is a suite that quietly stops catching things: every
// check below is proved to FAIL on a handler that violates it, not merely to
// pass on one that does not.
type fakeT struct {
	errs    []string
	fatal   string
	skipped bool
}

type abort struct{}

func (f *fakeT) Helper() {}

func (f *fakeT) Errorf(format string, args ...any) {
	f.errs = append(f.errs, fmt.Sprintf(format, args...))
}

func (f *fakeT) Fatalf(format string, args ...any) {
	f.fatal = fmt.Sprintf(format, args...)
	panic(abort{})
}

func (f *fakeT) Fatal(args ...any) {
	f.fatal = fmt.Sprint(args...)
	panic(abort{})
}

func (f *fakeT) Skip(...any) {
	f.skipped = true
	panic(abort{})
}

func (f *fakeT) failed() bool { return len(f.errs) > 0 || f.fatal != "" }

func (f *fakeT) report() string {
	return strings.Join(append(f.errs, f.fatal), " | ")
}

// check runs one conformance check, absorbing the abort a Fatal raises, and
// returns what it reported.
func check(fn func(*fakeT)) (f *fakeT) {
	f = &fakeT{}
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(abort); !ok {
				panic(r)
			}
		}
	}()
	fn(f)
	return f
}

// --- handlers under test ---------------------------------------------------

const resource = "https://svc.example.com/mcp"
const path = "/mcp"
const wellKnown = "/.well-known/oauth-protected-resource"

// The hosts the fictional operator in these tests runs.
var testOperatorHosts = []string{"example.com"}

type endpointOpts struct {
	challenge    string
	metadataAt   map[string]string // path -> JSON body
	gateMetadata bool              // 401 the discovery routes too
	openPost     bool              // answer an unauthenticated POST
}

func endpoint(o endpointOpts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := o.metadataAt[r.URL.Path]; ok {
			if o.gateMetadata && r.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		if r.URL.Path == path {
			if o.openPost {
				w.WriteHeader(http.StatusOK)
				return
			}
			if o.challenge != "" {
				w.Header().Set("WWW-Authenticate", o.challenge)
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	})
}

func doc(res, as string) string {
	return `{"resource":"` + res + `","authorization_servers":["` + as + `"],"bearer_methods_supported":["header"]}`
}

func goodHandler() http.Handler {
	return endpoint(endpointOpts{
		challenge: `Bearer error="invalid_token", resource_metadata="https://svc.example.com` + wellKnown + path + `"`,
		metadataAt: map[string]string{
			wellKnown:        doc(resource, "https://auth.example.com"),
			wellKnown + path: doc(resource, "https://auth.example.com"),
		},
	})
}

// --- the meta-tests --------------------------------------------------------

func TestConformingHandlerPasses(t *testing.T) {
	e := Expect{Resource: resource, Profile: FirstParty, OperatorHosts: testOperatorHosts}
	checks := map[string]func(*fakeT){
		"challenge": func(f *fakeT) { checkChallenge(f, goodHandler(), path, e) },
		"discovery": func(f *fakeT) { checkDiscovery(f, goodHandler(), path, e) },
		"profile":   func(f *fakeT) { checkProfile(f, goodHandler(), path, e) },
	}
	for name, fn := range checks {
		if f := check(fn); f.failed() {
			t.Errorf("%s check rejected a conforming handler: %s", name, f.report())
		}
	}
}

// The assertion no grep can make, and the reason this package exists.
func TestCatchesChallengeNamingAnUnservedDocument(t *testing.T) {
	h := endpoint(endpointOpts{
		// Names a metadata URL this handler does not serve.
		challenge:  `Bearer resource_metadata="https://svc.example.com` + wellKnown + path + `"`,
		metadataAt: nil,
	})
	f := check(func(f *fakeT) {
		checkChallenge(f, h, path, Expect{Resource: resource})
	})
	if !f.failed() {
		t.Error("a challenge pointing at a document the handler does not serve was accepted")
	}
	if !strings.Contains(f.report(), "dead page") {
		t.Errorf("failure did not explain the problem: %s", f.report())
	}
}

func TestCatchesDocumentDescribingTheWrongResource(t *testing.T) {
	h := endpoint(endpointOpts{
		challenge: `Bearer resource_metadata="https://svc.example.com` + wellKnown + path + `"`,
		metadataAt: map[string]string{
			wellKnown + path: doc("https://svc.example.com/some-other-path", "https://auth.example.com"),
		},
	})
	f := check(func(f *fakeT) {
		checkChallenge(f, h, path, Expect{Resource: resource})
	})
	if !f.failed() {
		t.Error("a document describing a different resource than the endpoint serves was accepted")
	}
}

func TestCatchesUnauthenticatedEndpoint(t *testing.T) {
	f := check(func(f *fakeT) {
		checkChallenge(f, endpoint(endpointOpts{openPost: true}), path, Expect{Resource: resource})
	})
	if !f.failed() {
		t.Error("an endpoint answering an unauthenticated POST was accepted")
	}
}

func TestCatchesMissingChallengeHeader(t *testing.T) {
	f := check(func(f *fakeT) {
		checkChallenge(f, endpoint(endpointOpts{challenge: ""}), path, Expect{Resource: resource})
	})
	if !f.failed() {
		t.Error("a 401 with no WWW-Authenticate was accepted")
	}
}

// Mounting the discovery routes inside the auth-gated group is the most likely
// way to break an otherwise correct implementation.
func TestCatchesGatedDiscoveryDocument(t *testing.T) {
	h := endpoint(endpointOpts{
		challenge: `Bearer resource_metadata="https://svc.example.com` + wellKnown + path + `"`,
		metadataAt: map[string]string{
			wellKnown:        doc(resource, "https://auth.example.com"),
			wellKnown + path: doc(resource, "https://auth.example.com"),
		},
		gateMetadata: true,
	})
	f := check(func(f *fakeT) {
		checkDiscovery(f, h, path, Expect{Resource: resource})
	})
	if !f.failed() {
		t.Error("a discovery document behind authentication was accepted")
	}
	if !strings.Contains(f.report(), "must be public") {
		t.Errorf("failure did not explain the problem: %s", f.report())
	}
}

func TestCatchesMissingBareWellKnownPath(t *testing.T) {
	h := endpoint(endpointOpts{
		challenge: `Bearer resource_metadata="https://svc.example.com` + wellKnown + path + `"`,
		metadataAt: map[string]string{
			// Only the suffixed spelling. A client probing the bare path 404s.
			wellKnown + path: doc(resource, "https://auth.example.com"),
		},
	})
	f := check(func(f *fakeT) {
		checkDiscovery(f, h, path, Expect{Resource: resource})
	})
	if !f.failed() {
		t.Error("an endpoint serving only one spelling of the well-known path was accepted")
	}
}

// The profile split, which is the whole point of having two of them.
func TestHandoverProfileRejectsAnInHouseIssuer(t *testing.T) {
	h := endpoint(endpointOpts{
		challenge: `Bearer resource_metadata="https://svc.example.com` + wellKnown + path + `"`,
		metadataAt: map[string]string{
			wellKnown:        doc(resource, "https://auth.example.com"),
			wellKnown + path: doc(resource, "https://auth.example.com"),
		},
	})
	f := check(func(f *fakeT) {
		checkProfile(f, h, path, Expect{Resource: resource, Profile: ThirdParty, OperatorHosts: testOperatorHosts})
	})
	if !f.failed() {
		t.Error("a third-party deployment naming OUR authorization server was accepted; the customer's " +
			"deployment would be silently coupled to our infrastructure")
	}
}

func TestHandoverProfileAcceptsItsOwnIssuer(t *testing.T) {
	h := endpoint(endpointOpts{
		metadataAt: map[string]string{
			wellKnown + path: doc(resource, "https://auth.customer.example"),
		},
	})
	f := check(func(f *fakeT) {
		checkProfile(f, h, path, Expect{Resource: resource, Profile: ThirdParty, OperatorHosts: testOperatorHosts})
	})
	if f.failed() {
		t.Errorf("a third-party deployment with its own issuer was rejected: %s", f.report())
	}
}

func TestInternalProfileRejectsAThirdPartyIssuer(t *testing.T) {
	h := endpoint(endpointOpts{
		metadataAt: map[string]string{
			wellKnown + path: doc(resource, "https://auth.customer.example"),
		},
	})
	f := check(func(f *fakeT) {
		checkProfile(f, h, path, Expect{Resource: resource, Profile: FirstParty, OperatorHosts: testOperatorHosts})
	})
	if !f.failed() {
		t.Error("an FirstParty service naming a third-party authorization server was accepted")
	}
}

func TestProfileRejectsPlaintextIssuer(t *testing.T) {
	h := endpoint(endpointOpts{
		metadataAt: map[string]string{
			wellKnown + path: doc(resource, "http://auth.customer.example"),
		},
	})
	f := check(func(f *fakeT) {
		checkProfile(f, h, path, Expect{Resource: resource, Profile: ThirdParty, OperatorHosts: testOperatorHosts})
	})
	if !f.failed() {
		t.Error("a plaintext authorization server was accepted; a token endpoint over http hands " +
			"the credential to anyone on the path")
	}
}

// OAuth off is a supported state, and it has its own shape.
func TestOAuthDisabledRequiresNotFoundAndNoMetadataParam(t *testing.T) {
	t.Run("a served document is a failure", func(t *testing.T) {
		h := endpoint(endpointOpts{
			metadataAt: map[string]string{
				wellKnown + path: doc(resource, "https://auth.example.com"),
			},
		})
		f := check(func(f *fakeT) {
			checkDiscovery(f, h, path, Expect{Resource: resource, OAuthDisabled: true})
		})
		if !f.failed() {
			t.Error("OAuth disabled, but a served discovery document was accepted")
		}
	})

	t.Run("an advertised metadata URL is a failure", func(t *testing.T) {
		h := endpoint(endpointOpts{
			challenge: `Bearer resource_metadata="https://svc.example.com` + wellKnown + path + `"`,
		})
		f := check(func(f *fakeT) {
			checkChallenge(f, h, path, Expect{Resource: resource, OAuthDisabled: true})
		})
		if !f.failed() {
			t.Error("OAuth disabled, but a challenge advertising resource_metadata was accepted")
		}
	})

	t.Run("404 and a bare challenge pass", func(t *testing.T) {
		h := endpoint(endpointOpts{challenge: `Bearer error="invalid_token"`})
		f1 := check(func(f *fakeT) {
			checkChallenge(f, h, path, Expect{Resource: resource, OAuthDisabled: true})
		})
		f2 := check(func(f *fakeT) {
			checkDiscovery(f, h, path, Expect{Resource: resource, OAuthDisabled: true})
		})
		if f1.failed() || f2.failed() {
			t.Errorf("a correct OAuth-disabled endpoint was rejected: %s %s", f1.report(), f2.report())
		}
	})
}

func TestHostMatchesOnLabelBoundary(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"auth.example.com", true},
		{"AUTH.EXAMPLE.COM", true},
		{"auth.example.com.", true},
		{"notexample.com", false},
		{"example.com.evil.com", false},
		{"auth.customer.example", false},
	}
	for _, tc := range tests {
		if got := hostMatches(tc.host, testOperatorHosts); got != tc.want {
			t.Errorf("hostMatches(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestParseChallenge(t *testing.T) {
	got := parseChallenge(`Bearer error="invalid_token", resource_metadata="https://a/b"`)
	if got["error"] != "invalid_token" {
		t.Errorf("error = %q", got["error"])
	}
	if got["resource_metadata"] != "https://a/b" {
		t.Errorf("resource_metadata = %q", got["resource_metadata"])
	}
}
