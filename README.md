# mcp-login

Sign-in for customer-facing MCP servers. A customer adds your connector in Claude by pasting
one URL and clicking Connect, then signs in with the Google or Microsoft account they already
have. Nobody gets a guest invite or an MFA enrollment from you, and there's nothing to paste.

## Why this exists

I first wired a customer's MCP server to our own Microsoft Entra tenant using B2B guest
accounts. It broke on the first real test. The failure was exactly what a customer would
hit: the invite redeemed fine, then our tenant demanded MFA enrollment before the guest could do anything
(sign-in log: AADSTS50072). Even with that fixed, Entra could only offer a Microsoft-branded
permissions screen. The customer still had to paste a client id and secret into Claude.

So the customer's own provider handles their password and 2FA, and this service only answers
one question: who is this, and are they allowed on this server?

```
Claude -> your-mcp.example.com       fastmcp OIDCProxy: client registration, consent,
                                     PKCE, access + refresh tokens
       -> login.example.com          THIS: "Continue with Google / Microsoft",
                                     per-server allowlist, signed tokens
       -> Google / Microsoft         the customer's own account and 2FA
```

The hard part of MCP auth (dynamic client registration, redirect validation, PKCE, consent,
token refresh) already ships in fastmcp as `OIDCProxy`. This repo is the small OpenID Connect
provider behind it, about 1,100 lines of Python. It has a fixed list of clients, one per MCP
server, so it needs none of the registration machinery.

It was run end to end against a live MCP server with a fake Google that signs real tokens.
All 24 checks passed, including a token refresh and a restart of the MCP server that signed
nobody out. That harness was wired to a private server, so it isn't in this repo.

## Who can sign in: clients.json

Copy `clients.example.json` to `clients.json`. Each entry is one MCP server and the exact list
of people who may sign in to it. Keep the real file in a private repo, where every grant and
removal becomes a reviewed commit (this repo gitignores it so a public fork can't leak it).

- Emails are exact and lower-case. `allow_domains` admits a whole domain, so use it on purpose.
- Removing someone ends their access at their next token refresh, within an hour. The audit
  log records `access_revoked`.
- Microsoft work accounts from other organizations are accepted only when Microsoft marks the
  email as domain-verified (`xms_edov`). The plain `email` claim isn't verified and has been
  used to impersonate people (the "nOAuth" class).
- Optional: set `MCP_LOGIN_STAFF_TENANT` and `MCP_LOGIN_STAFF_DOMAINS` and your own staff
  addresses are accepted only through Microsoft from your tenant, so staff always pass your MFA.

Each client's secret lives only in `MCP_LOGIN_CLIENT_SECRETS` (`client-id:secret,...`), and the
same value goes in that MCP server's own config. The service won't start if a listed client has
no secret, or if a secret is shorter than 32 characters.

The full security model, one row per threat, is in [DESIGN.md](DESIGN.md).

## Run it

Tests first. They need no network: fake Google and Microsoft servers sign real RS256 tokens, so
the production verification code runs unchanged.

```
pip install -r requirements.txt
python -m pytest -q
```

66 tests. Every control in DESIGN.md's security table that lives in this service has at least
one, and a boot test starts the real entry point from environment variables alone.

To deploy, set the variables listed in `docker-compose.yml` and:

```
cp clients.example.json clients.json      # then edit it
docker compose up -d --build
```

Put it behind a reverse proxy that terminates TLS. `MCP_LOGIN_ISSUER` must be the public https
URL exactly as browsers see it, because it's the `iss` of every token. The data volume holds
the signing key and the audit log along with session state, and losing it means everyone signs
in once more.

## Provider setup

Microsoft: `scripts/setup_microsoft_app.ps1` creates one multi-tenant app that accepts any
organization's accounts plus personal ones, with the `email` and `xms_edov` optional claims set.
Its secret is written to a file and never printed. It's a dry run unless you pass `-Apply`, and
safe to re-run. Without Microsoft publisher verification some customer tenants will show "Need admin
approval"; Google has no equivalent block for basic scopes.

Google: create an OAuth client of type Web application with redirect URI
`<issuer>/callback/google` and scopes `openid email profile`. I set this up from memory of the
console, so check the current Google docs for the exact screens.

A provider with no id and secret set is simply not offered on the sign-in page.

## On the MCP server side

Point fastmcp's `OIDCProxy` at `<issuer>/.well-known/openid-configuration` with that server's
client id and secret. Then check the token's `email` claim against the same allowlist on every
call, so one mistake in one place isn't enough on its own.

With Entra the customer's browser only ever talked to Microsoft. With the proxy it talks to the
MCP host itself for `/authorize`, the consent page and `/auth/callback`, so if you restrict that
host by IP, open those paths and keep `/mcp` restricted.

## Endpoints

| Path | Who calls it |
|---|---|
| `/.well-known/openid-configuration`, `/jwks` | MCP servers (discovery, token verification) |
| `/authorize` | the customer's browser, sent by the MCP server |
| `/start/{google,microsoft}`, `/callback/{google,microsoft}` | the customer's browser |
| `/token` | MCP servers only (client secret + PKCE) |
| `/privacy` | anyone; 503 until the three `MCP_LOGIN_PRIVACY_*` fields are set |
| `/healthz` | monitoring |

## License

MIT
