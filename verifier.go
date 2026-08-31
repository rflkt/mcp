package mcp

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ErrUnauthenticated is what a Verifier returns when the credential it claimed
// turns out to be invalid. Verify may return any error; this one exists so a
// caller can distinguish "rejected" from "the verifier itself broke".
var ErrUnauthenticated = errors.New("mcp: unauthenticated")

// Verifier authenticates one kind of credential.
//
// The split between Claims and Verify is the point of this interface. Claims
// answers "is this credential mine" WITHOUT validating it, so several credential
// types can be offered on one endpoint with none of them rejecting another's.
// The usual shape is to inspect a token's issuer, or a fixed key prefix, to
// decide which verifier should see it -- without trusting anything read in the
// process, since the choice only selects who validates, and every verifier
// rejects a credential it does not hold the key for.
//
// Getting this wrong is how an OAuth rollout breaks a working machine-to-machine
// caller. If an OAuth verifier claimed every Bearer token, it would claim the
// pre-shared API keys too, and reject them.
type Verifier interface {
	// Name identifies the verifier in logs and conformance output. Must be
	// non-empty and unique within one Config.
	Name() string

	// Claims reports whether this verifier owns the request's credential.
	//
	// It must be cheap and MUST NOT validate: no signature check, no network,
	// no database. It is asked of every verifier in order until one says yes,
	// and a slow or failing Claims turns credential dispatch into a bottleneck
	// or an outage. Look at the shape of the credential, nothing more.
	Claims(r *http.Request) bool

	// Verify validates the credential and resolves the caller.
	//
	// Returning ErrUnauthenticated (or any error) produces a 401 carrying the
	// challenge. It must not write to the response itself.
	Verify(r *http.Request) (*Principal, error)
}

// Principal is a resolved caller.
//
// It carries only what this package can honestly describe. Everything a service
// actually means by identity travels through Bind, so that this package never
// becomes the place where one service's user id and another's tenant have to be
// reconciled into a single type.
type Principal struct {
	// Subject identifies the caller for logging and correlation. It is not a
	// credential and must be safe to write to a log line.
	Subject string

	// Scopes are the granted OAuth scopes, if any. Empty for credential types
	// that do not express scope, such as a pre-shared API key, which callers
	// should read as "unscoped", never as "no access".
	Scopes []string

	// Bind installs service-specific identity into the request context.
	//
	// This is the seam. crm puts a user id and an org id where its handlers
	// expect them; another puts a tenant, or a device. This package puts neither
	// and does not know what either is.
	//
	// Optional. A nil Bind means the tool surface gets the request unchanged.
	Bind func(context.Context) context.Context
}

// HasScope reports whether the principal was granted the named scope.
func (p *Principal) HasScope(scope string) bool {
	if p == nil {
		return false
	}
	for _, held := range p.Scopes {
		if held == scope {
			return true
		}
	}
	return false
}

// BearerToken returns the Bearer credential on a request, and whether there was
// one. Provided because every Verifier implementation needs it and each
// hand-rolled copy is a chance to differ on case or on spacing.
//
// The scheme comparison is case-insensitive per RFC 7235; the token is returned
// verbatim.
func BearerToken(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	raw := r.Header.Get("Authorization")
	if raw == "" {
		return "", false
	}
	scheme, token, found := strings.Cut(raw, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

// PrefixVerifier claims Bearer tokens carrying a fixed prefix, and delegates
// validation to verify.
//
// It exists for pre-shared API keys, which is how a great many services still
// authenticate machine-to-machine callers. Claiming on the prefix is what lets
// such a key sit alongside an OAuth verifier without either one seeing the
// other's credentials.
type PrefixVerifier struct {
	// VerifierName is returned by Name.
	VerifierName string

	// Prefix is matched against the Bearer token. Must be non-empty: a zero
	// prefix would claim every Bearer token, including OAuth ones, which is
	// exactly the failure this type exists to avoid.
	Prefix string

	// Validate resolves a claimed token to a caller.
	Validate func(r *http.Request, token string) (*Principal, error)
}

// Name implements Verifier.
func (p PrefixVerifier) Name() string { return p.VerifierName }

// Claims implements Verifier. A zero Prefix claims nothing, deliberately: it
// fails closed rather than swallowing every credential on the endpoint.
func (p PrefixVerifier) Claims(r *http.Request) bool {
	if p.Prefix == "" {
		return false
	}
	token, ok := BearerToken(r)
	return ok && strings.HasPrefix(token, p.Prefix)
}

// Verify implements Verifier.
func (p PrefixVerifier) Verify(r *http.Request) (*Principal, error) {
	token, ok := BearerToken(r)
	if !ok {
		return nil, ErrUnauthenticated
	}
	if p.Validate == nil {
		return nil, errors.New("mcp: PrefixVerifier has no Validate")
	}
	return p.Validate(r, token)
}

// AllowAll accepts every request without authenticating it.
//
// For a local development transport and nothing else. It is a named type rather
// than "omit the Verifiers field" so that an unauthenticated endpoint is a
// visible decision at the call site, greppable in review and impossible to
// arrive at by forgetting something.
type AllowAll struct {
	// Subject is reported on the resulting Principal, for logs.
	Subject string
}

// Name implements Verifier.
func (a AllowAll) Name() string { return "allow-all" }

// Claims implements Verifier.
func (a AllowAll) Claims(*http.Request) bool { return true }

// Verify implements Verifier.
func (a AllowAll) Verify(*http.Request) (*Principal, error) {
	subject := a.Subject
	if subject == "" {
		subject = "anonymous"
	}
	return &Principal{Subject: subject}, nil
}
