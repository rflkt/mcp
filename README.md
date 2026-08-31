# mcp

The protocol half of a [Model Context Protocol](https://modelcontextprotocol.io)
endpoint for Go: the paths, the [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)
discovery document, the `401` challenge, and credential dispatch in front of your
JSON-RPC tool surface.

Standard library only. No cryptography. It does not know what a user is, and it
does not know your router.

```go
endpoint, err := mcp.New(mcp.Config{
    Resource: "https://api.example.com/mcp", // everything derives from this
    Issuer:   "https://auth.example.com",    // "" disables OAuth; docs 404
    Handler:  toolSurface,
    Verifiers: []mcp.Verifier{
        oauthVerifier,                        // claims tokens from your issuer
        mcp.PrefixVerifier{                   // claims pre-shared API keys
            VerifierName: "api-key",
            Prefix:       "key_",
            Validate:     validateAPIKey,
        },
    },
})

for _, rt := range endpoint.Routes() {
    // rt.Path, rt.Method, rt.Wildcard, rt.Public — mount them on your router
}
```

## Why

An MCP endpoint is a little protocol wrapped around a lot of service-specific
behaviour, and the protocol part is the part that is easy to get subtly wrong.
Across five services we found the same defects, each of which reads as correct in
isolation:

- the mount path, the discovery document's `resource` field, and the challenge's
  `resource_metadata` written as three separate string literals — so a document
  could come to describe a path the service did not serve;
- a `401` whose `WWW-Authenticate` names no discovery document at all, leaving a
  just-rejected client nowhere to go — in a service that served a complete and
  correct document at two paths;
- the discovery document mounted *inside* the authenticated route group, so the
  one request that exists to escape a `401` gets a `401`;
- an OAuth verifier that claimed every `Bearer` token, including the pre-shared
  API keys a machine caller had been using for a year.

None of these are hard problems. They are easy to not notice.

## The one value everything derives from

`Config.Resource` is the RFC 8707 resource indicator. The mount path, the
document's `resource`, the well-known URL and the challenge's `resource_metadata`
are all computed from it, so they cannot disagree.

Nothing hardcodes `/mcp`. An endpoint at `/internal/mcp` works the same way.

## Credential dispatch

`Verifier` splits `Claims` from `Verify`. `Claims` answers *is this credential
mine* **without validating it**, so several credential types share one endpoint
with none of them rejecting another's.

This is what stops an OAuth rollout breaking the machine-to-machine callers that
were working the day before. An OAuth verifier that claims only tokens from its
own issuer never sees an API key, so it can never reject one.

`Claims` must be cheap: no signature check, no network, no database. It is asked
of every verifier in order until one says yes.

## Identity

`Verify` returns a `Principal` carrying a `Bind` function, and `Bind` installs
whatever *your* service means by identity into the request context — a user and
tenant id, an account, a device. This package installs neither, and so never
becomes the place two services' identity models have to be reconciled.

## Conformance

`mcpconform` drives your **real** handler with real requests:

```go
func TestMCPConformance(t *testing.T) {
    mcpconform.Assert(t, app.Router(), mcpconform.Expect{
        Resource:      "https://api.example.com/mcp",
        Profile:       mcpconform.FirstParty,
        OperatorHosts: []string{"example.com"},
    })
}
```

It proves a client that gets a `401` can follow the challenge to a document that
is **actually served**, describing the path that **actually exists** — and that
the document is reachable without the credential it exists to help obtain.

A grep cannot make that assertion. Its predecessor here was a CI script, and it
missed a service whose path was `/internal/mcp` while passing one whose challenge
named a URL nothing served, because the string it looked for was present
somewhere else in the repository.

`mcpconform` is itself tested: every check is driven against a deliberately
broken handler to prove the failure is caught.

### Profiles

`Profile` asserts *who* may authenticate your callers.

- **`FirstParty`** — the authorization server is one you operate.
- **`ThirdParty`** — it is not. This is the profile for software you ship to
  someone else to run: it must authenticate against *their* issuer, not yours,
  or their deployment stops working the day you retire it.
- **`AnyIssuer`** — the zero value. Skips the assertion.

`OperatorHosts` says which hosts you operate. There is no default: a library
cannot know whose infrastructure is whose, and a guessed one would make the
assertion either vacuous or wrong.

## License

Apache 2.0. See [LICENSE](LICENSE).
