# mcp-login: design and security model

## What the customer sees

1. In Claude: add the connector by pasting one URL, then click Connect. No client id, no secret.
2. A sign-in page with two buttons. Continue with Google works for Gmail and any Google
   Workspace domain, with nothing set up on the customer's side. Continue with Microsoft works
   for a Microsoft 365 work account or a personal Microsoft account.
3. Back in Claude, connected. They aren't asked again for about a month.

Nothing is created in the operator's directory for them, and the operator's MFA policies don't
touch them.

## How it fits together

```
 Claude  --(add URL, Connect)-->  your-mcp.example.com
                                    |  fastmcp OIDCProxy, built in:
                                    |   - dynamic client registration (no id/secret to paste)
                                    |   - Claude's client id metadata document
                                    |   - consent, PKCE, access + refresh tokens
                                    v
                          login.example.com   <- this repo
                           - "Continue with Google"    -> Google (their account, their 2FA)
                           - "Continue with Microsoft" -> Microsoft, multi-tenant
                           - per-server allowlist: is this email allowed on THIS server?
                           - issues a signed ID token: {email, email_verified, idp}
```

The security-sensitive half of MCP auth (client registration, redirect validation, PKCE, token
issuing and refresh, consent) already exists in fastmcp's `OAuthProxy` / `OIDCProxy`, with an
encrypted store for client and token state. None of that is re-implemented here.

What's here is a small OpenID Connect identity provider whose only job is "who is this, and are
they allowed on this server?", brokered to Google or Microsoft. It has a fixed set of clients,
one per MCP server, each with its own id, secret and redirect URI.

One login service can front any number of customer servers. Each server keeps its own customer
scoping in its own code.

## Security model

Access is deny by default, and it's decided twice:

1. At sign-in, by mcp-login. The email must be on the allowlist for the server the customer is
   connecting to. Each server is a separate client with its own list, so a person allowed on one
   customer's server isn't allowed on another's by accident.
2. On every call, by the MCP server. The token's `email` claim is checked against the same
   server's allowlist.

| Concern | Control |
|---|---|
| Google account without a verified email | Require `email_verified = true`; match on the exact email |
| Microsoft `email` claim is not always verified (the "nOAuth" impersonation class) | Personal Microsoft accounts: `email` accepted. Work accounts: accepted only with the `xms_edov` (email domain owner verified) optional claim true. Otherwise refused, with a "use Google instead" message |
| Someone signing in as staff through Google or another tenant | Optional staff rule: addresses on `MCP_LOGIN_STAFF_DOMAINS` accepted ONLY via Microsoft with `MCP_LOGIN_STAFF_TENANT`, so staff always pass the operator's MFA. Unset, no tenant is ever treated as trusted |
| Forged or replayed provider response | Upstream `id_token` verified against the provider's JWKS: issuer (per-tenant issuer for Microsoft), audience, expiry and our `nonce`; RS256 only; upstream PKCE; `state` bound to a browser cookie |
| Stolen authorization code | 60-second lifetime, single use, bound to client, redirect URI and PKCE challenge (S256 required) |
| Open redirect | Redirect URIs fixed per registered client; until client and redirect URI are proven, errors are shown on a page and never redirected |
| Token theft | Short access tokens (1 hour) with refresh tokens. Refresh tokens rotate, and re-presenting a rotated one revokes the whole chain. The allowlist is re-checked on every refresh, so removing an email ends access within an hour |
| Signing keys | RS256 key pair generated on first start and kept on the data volume, never in git or env; public half at `/jwks` |
| Refresh tokens at rest | Stored only as SHA-256 hashes |
| Redeploys logging everyone out | Both services keep state (sessions, registrations, tokens) on volumes |
| Audit | Every sign-in attempt logged with time, server, email, method, result and IP; pruned at the retention period the privacy page states |

The trade-off is plain. A customer's sign-in is only as strong as their own Google or Microsoft
account, and nothing here enforces 2FA on it. I accepted that because the servers it fronts give read-only access to the
customer's own data, and staff can be forced through the operator's tenant and MFA.

## What each MCP server changes

- `OIDCProxy(config_url="<issuer>/.well-known/openid-configuration", ...)` with that server's
  client id and secret for mcp-login, a signing key, and a volume for the proxy's state.
- A per-call check of the token's email against that server's allowlist.
- The browser now reaches the MCP host for `/authorize`, the consent page and `/auth/callback`.
  If the host is restricted by source IP, open those paths; `/mcp` can stay restricted.
  mcp-login itself is browser-facing and open to all addresses by design: the allowlist and the
  providers' own sign-in are its protection.

## Known gap

Many organizations only let users consent to apps from a Microsoft-verified publisher. Without
publisher verification, which needs a Microsoft Partner id, some customer staff will see "Need
admin approval" on the Microsoft button. Google has no equivalent block for basic scopes, so
the Google button is the fallback.
