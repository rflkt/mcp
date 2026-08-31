// Package mcp is the protocol half of a Model Context Protocol endpoint: the
// paths, the RFC 9728 discovery document, the 401 challenge, and credential
// dispatch in front of a JSON-RPC tool surface.
//
// # Why this exists
//
// An MCP endpoint is a small amount of protocol wrapped around a large amount of
// service-specific behavior, and the protocol part is the part that is easy to
// get subtly wrong. Across five services we found the same handful of defects,
// each of which looks entirely correct in isolation:
//
//   - the mount path, the discovery document's `resource` field and the
//     challenge's resource_metadata written as separate string literals, so a
//     document could come to describe a path the service did not serve;
//   - a 401 whose WWW-Authenticate names no discovery document at all, leaving a
//     client that has just been rejected with nowhere to go -- in a service that
//     served a complete and correct document at two paths;
//   - the discovery document mounted inside the authenticated route group, so
//     the one request that exists to escape a 401 gets a 401;
//   - an OAuth verifier that claimed every Bearer token, including the
//     pre-shared API keys a machine caller had been using for a year.
//
// None of these are hard problems. They are easy to not notice, and code review
// does not reliably catch them, because each is a single line that reads
// correctly on its own. This package makes them structurally impossible where it
// can, and mcpconform detects the rest by driving a real endpoint with real
// requests.
//
// # The one value everything derives from
//
// Config.Resource is the RFC 8707 resource indicator: the absolute URL clients
// reach this endpoint on. The mount path, the `resource` field of the discovery
// document, the well-known URL, and the resource_metadata parameter of the
// challenge are ALL computed from it. That single property removes the first
// defect above by construction.
//
// Nothing here hardcodes "/mcp". An endpoint served at /internal/mcp, or
// anywhere else, works the same way.
//
// # Credential dispatch
//
// Verifier splits Claims from Verify. Claims answers "is this credential mine"
// WITHOUT validating it, so several credential types can share one endpoint with
// none of them rejecting another's. That removes the fourth defect: an OAuth
// verifier that claims only tokens from its own issuer cannot reject an API key
// it was never meant to see.
//
// # What this package refuses to know
//
// It does not know what a user is. Verify returns a Principal carrying a Bind
// function, and Bind installs whatever the service means by identity into the
// request context -- a user and tenant id, an account, a device. This package
// installs neither, and so never becomes the place two services' identity models
// have to be reconciled.
//
// It also does not know your router. Routes returns descriptions; you mount
// them. Routers spell a wildcard differently and none is privileged here.
//
// It contains no cryptography. Token verification belongs to the Verifier you
// supply, so this package never handles a key.
//
// # Dependencies
//
// The standard library, and nothing else. That is deliberate and worth
// preserving: this package is meant to be embeddable in software handed to a
// customer, where every transitive dependency is something their review has to
// clear.
package mcp
