# AGENTS.md

Guidance for anyone, human or AI agent, working on this repository. Read it
before changing code. [README.md](README.md) explains what acme-proxy is for;
this file explains how the code is written and which rules it must keep.

## Project in one paragraph

acme-proxy holds the only DNS provider API token and lets ACME clients publish
DNS-01 challenge records through it. Clients speak lego's `httpreq` protocol.
Each client has its own token, stored only as a SHA-256 hash. A client may
connect only from its allowed networks, and may only publish the
`_acme-challenge` TXT record for the exact names allowed for it. A compromised
client can therefore get certificates for its own names, and nothing else.

## Layout

```
cmd/acme-proxy/          entry point: wiring, signals, startup
internal/validate/       DNS names and challenge requests (pure functions)
internal/auth/           client authentication (token hash, source address)
internal/server/         HTTP API: POST /present, POST /cleanup
internal/dns/<provider>/ DNS provider clients (one package per provider)
internal/config/         loading and validating the configuration file
```

- `server.DNS` is the interface every provider implements. It is declared in
  the package that uses it, not in the providers.
- Providers receive a validated domain name (`app1.example.com`) and add the
  `_acme-challenge.` prefix themselves.
- One provider is configured at a time, selected by `dns.provider`. Each
  provider has its own sub-object in the configuration (`dns.cloudflare`, …).

## Protocol

lego `httpreq`, default mode only (RAW mode is not supported):

- `POST /present` and `POST /cleanup`;
- JSON body `{"fqdn": "_acme-challenge.app1.example.com.", "value": "…"}`;
  `fqdn` has a trailing dot, and `value` is 43 base64url characters;
- HTTP Basic authentication: the username is the client name, the password is
  the client token.

| Status | Meaning |
|---|---|
| 200 | done |
| 400 | malformed request |
| 401 | authentication failed (any reason) |
| 403 | name not allowed for this client |
| 404 / 405 | unknown path / wrong method |
| 502 | the DNS provider failed |

Error bodies are only `http.StatusText(code)`. The detailed reason goes to the
log, never to the client.

## Commands

```sh
make build   # static Linux binary in bin/
make test    # go test -race ./...
make lint    # go vet ./...
gofmt -l .   # must print nothing
```

All four must pass before a commit.

## Dependencies

- **Runtime:** standard library only. A new module in `go.mod` needs an
  explicit decision, recorded in the commit message. The only one planned is
  `golang.org/x/crypto/acme`, for the proxy's own certificate.
- **Tooling:** no third-party tools in the build or lint steps. Any tool added
  to CI must have a pinned version.
- **Configuration** is JSON, decoded with `encoding/json`.

## Security invariants

These are the point of the project. A change that weakens one of them needs a
very good reason and an update to the threat model in the README.

- **Never trust the client.**
  - The source address comes from the connection (`r.RemoteAddr`), never from
    `X-Forwarded-For` or other headers.
  - Request bodies are size-limited (`http.MaxBytesReader`), decoded with
    `DisallowUnknownFields`, and rejected if anything follows the first JSON
    value.
- **Never trust the provider either.**
  - Responses are size-limited (`io.LimitReader`).
  - Results are re-checked before acting. For example, `Cleanup` deletes only
    records whose type, name and exact value match, even if the API's filter
    already returned them.
  - Identifiers taken from responses are escaped (`url.PathEscape`) before
    they go into a URL.
- **Exact names only.** A client may publish only `_acme-challenge.<name>` for
  the names listed for it. There is no subdomain or suffix matching.
- **Validate before transforming.** Check a value against its pattern first,
  then normalize it (e.g. `strings.ToLower`). The other order lets Unicode
  case folding smuggle characters in: the Kelvin sign U+212A lowercases to
  `k`.
- **Secrets:**
  - client tokens are stored only as SHA-256 hashes and compared with
    `crypto/subtle.ConstantTimeCompare`;
  - the provider token is read from a file, sent only in the `Authorization`
    header, never in a URL;
  - secrets never appear in logs or error messages.
- **Logs cannot be forged.**
  - Values that come from outside (request fields, config values, provider
    responses) are logged as `slog` attributes, never concatenated into the
    message.
  - In error strings they are formatted with `%q`.
- **Timeouts everywhere.**
  - The HTTP server sets every timeout.
  - Outgoing calls use `http.Client` with `Timeout` (never
    `http.DefaultClient`) and the request's `context`.
  - The server's `WriteTimeout` must stay longer than the DNS timeout.
- **Fail closed.**
  - Invalid input is rejected where it is detected, rather than relying on a
    later check to reject it.
  - An invalid configuration on reload keeps the previous one.
- **Least privilege.** The provider token needs only DNS edit rights on one
  zone. Do not add features that need more.

## Go conventions

- **Errors**
  - Handle the error first and `return`; keep the normal path unindented,
    without `else` after a `return`.
  - Sentinel errors are package-level `var ErrX = errors.New(...)`.
  - Errors are wrapped with `%w` so callers can use `errors.Is` and
    `errors.As`.
  - Never call a method on a value that may be `nil`: log `err`, not
    `err.Error()`.
- **HTTP handlers:** every error response is followed by `return`. Headers are
  set before the status code.
- **Resources:** `defer` the release (`cancel()`, `resp.Body.Close()`) on the
  line right after acquiring the resource and checking its error.
- **Logging:** `log/slog` with key/value pairs. Rejections use the message
  `"rejected"` with a `"reason"` attribute, so they can all be found with one
  search.
- **Naming:** MixedCaps, no underscores. A variable named `err…` must hold an
  `error`.
- **Interfaces** are small and declared by the consumer.
- **Comments** explain *why*, not *what*. Exported identifiers have doc
  comments.

## Tests

- Table-driven, with `t.Run` per case and descriptive case names.
- No real network calls. External services are imitated with `httptest`
  servers that can also misbehave: wrong status codes, HTML instead of JSON,
  oversized bodies, ignored filters, never answering.
- Every security invariant above should have, where it can be tested, a test
  that fails if the invariant is removed. When fixing a bug, add the failing
  case first.
- Tests must pass with `-race`.

## Examples and documentation

- Use only reserved example names and addresses: `example.com`, `example.org`,
  `app1`/`app2`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
  `2001:db8::/32`. Never real domains, hostnames, IPs or tokens.
- Code, comments, documentation and commit messages are in English.
- Do not mark a client as "tested" in the README until it has been tested
  against a real ACME server.

## Git

- `main` is protected: commits must be signed, force pushes and deletions are
  blocked.
- Commit messages are short and imperative (`Add Cloudflare DNS provider`).
- Never commit secrets, real configuration files or build output (`bin/`).