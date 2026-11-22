"""mcp-login: a small OpenID Connect provider that brokers to Google and
Microsoft, for customer-facing MCP servers.

    MCP server (fastmcp OIDCProxy)  --/authorize-->  chooser page
        chooser --/start/{idp}-->  Google or Microsoft  --/callback/{idp}-->
        verify identity, check this server's allowlist, mint a 60s code
        --> back to the MCP server, which calls /token (client secret + PKCE)

Only fixed, pre-registered clients (clients.json). No dynamic registration
here: the MCP servers' own OIDCProxy does that part for Claude.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from . import pages
from .config import Client, Config
from .idp import IdentityRefused, Identity, Providers, UpstreamError, pkce_pair
from .keys import SigningKey
from .store import Store

logger = logging.getLogger("mcp_login")
COOKIE = "mcpl_b"
KNOWN_SCOPES = {"openid", "email", "profile", "offline_access"}


def _with_query(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True) + list(params.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _html(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(body, status_code=status, headers=pages.HEADERS)


def _oauth_error(error: str, desc: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": desc}, status_code=status,
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def prune_audit(path, retention_days: int) -> int:
    """Drop audit records older than the retention period; return how many.

    The public privacy policy states the retention period, so this is what
    makes that statement true. Rewritten atomically. A line that cannot be
    parsed is KEPT (and counted as kept): losing evidence silently is worse
    than keeping a malformed line.
    """
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return 0
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - retention_days * 86400))
    keep, dropped = [], 0
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            ts = json.loads(line).get("ts", "")
        except ValueError:
            keep.append(line)
            continue
        if isinstance(ts, str) and ts and ts < cutoff:
            dropped += 1
        else:
            keep.append(line)
    if dropped:
        tmp = p.with_suffix(".tmp")
        tmp.write_text("".join(l + "\n" for l in keep), encoding="utf-8")
        tmp.replace(p)
    return dropped


def _s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def build_app(cfg: Config, *, providers: Providers | None = None) -> Starlette:
    store = Store(cfg.data_dir / "mcp-login.sqlite3")
    key = SigningKey(cfg.data_dir / "signing-key.pem")
    prov = providers or Providers(cfg)
    audit_path = cfg.data_dir / "audit.jsonl"

    def audit(request: Request | None, event: str, **fields: Any) -> None:
        ip = None
        if request is not None:
            fwd = request.headers.get("x-forwarded-for", "")
            ip = fwd.split(",")[0].strip() or (request.client.host if request.client else None)
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, "ip": ip, **fields}
        line = json.dumps(row, separators=(",", ":"), default=str)
        logger.info("audit %s", line)
        try:
            with open(audit_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as e:  # the log line above still carries it; say so loudly
            logger.error("AUDIT FILE WRITE FAILED (%s); event only in container log", e)

    # --- discovery ------------------------------------------------------------
    async def openid_configuration(_: Request) -> JSONResponse:
        i = cfg.issuer
        return JSONResponse({
            "issuer": i,
            "authorization_endpoint": f"{i}/authorize",
            "token_endpoint": f"{i}/token",
            "jwks_uri": f"{i}/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": sorted(KNOWN_SCOPES),
            "claims_supported": ["sub", "email", "email_verified", "name", "idp"],
        })

    async def jwks(_: Request) -> JSONResponse:
        return JSONResponse(key.jwks(), headers={"Cache-Control": "public, max-age=300"})

    async def privacy(_: Request) -> Response:
        if not pages.privacy_is_complete():
            # Never serve an unapproved draft as the company's policy.
            return HTMLResponse("Not yet published.", status_code=503, headers=pages.HEADERS)
        return _html(pages.privacy(cfg.audit_retention_days, cfg.refresh_ttl // 86400))

    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "mcp-login",
                             "providers": sorted(cfg.upstreams),
                             "clients": sorted(cfg.clients)})

    # --- browser flow -----------------------------------------------------------
    async def authorize(request: Request) -> Response:
        q = request.query_params
        client = cfg.clients.get(q.get("client_id", ""))
        # Until client AND redirect_uri are proven, errors are shown here and
        # never sent anywhere: an unvalidated redirect_uri is an open redirect.
        if client is None:
            audit(request, "authorize_refused", reason="unknown client", client=q.get("client_id"))
            return _html(pages.error("This sign-in link is not valid."), 400)
        redirect_uri = q.get("redirect_uri", "")
        if redirect_uri not in client.redirect_uris:
            audit(request, "authorize_refused", reason="redirect_uri not registered",
                  client=client.client_id, redirect_uri=redirect_uri)
            return _html(pages.error("This sign-in link is not valid."), 400)
        state = q.get("state", "")

        def back(err: str, desc: str) -> Response:
            return RedirectResponse(_with_query(redirect_uri, {
                "error": err, "error_description": desc, **({"state": state} if state else {})}), 302)

        if q.get("response_type") != "code":
            return back("unsupported_response_type", "only response_type=code")
        if not q.get("code_challenge") or q.get("code_challenge_method") != "S256":
            return back("invalid_request", "PKCE with S256 is required")
        scopes = [s for s in q.get("scope", "openid").split() if s in KNOWN_SCOPES] or ["openid"]
        pid = store.put_pending(client_id=client.client_id, redirect_uri=redirect_uri, state=state,
                                code_challenge=q["code_challenge"], code_challenge_method="S256",
                                scope=" ".join(scopes), nonce=q.get("nonce", ""),
                                resource=q.get("resource", ""))
        links = {name: f"{cfg.issuer}/start/{name}?r={pid}" for name in cfg.upstreams}
        return _html(pages.chooser(client.name, links))

    async def start(request: Request) -> Response:
        idp = request.path_params["idp"]
        up = cfg.upstreams.get(idp)
        pid = request.query_params.get("r", "")
        pending = store.get_pending(pid, cfg.pending_ttl) if pid else None
        if up is None or pending is None:
            return _html(pages.error("This sign-in has expired."), 400)
        browser = secrets.token_urlsafe(24)
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        verifier, challenge = pkce_pair()
        store.put_flow(state, pid, idp, browser, verifier, nonce)
        try:
            url = await prov.authorize_url(up, redirect_uri=f"{cfg.issuer}/callback/{idp}",
                                           state=state, nonce=nonce, code_challenge=challenge)
        except UpstreamError as e:
            audit(request, "upstream_error", idp=idp, client=pending["client_id"], reason=str(e))
            return _html(pages.error(f"{idp.title()} sign-in is unavailable right now. Try again shortly."), 502)
        resp = RedirectResponse(url, 302)
        # Binds the callback to THIS browser: a callback URL replayed in another
        # browser has no cookie and is refused.
        resp.set_cookie(COOKIE, browser, max_age=cfg.pending_ttl, httponly=True,
                        secure=not cfg.insecure_cookies, samesite="lax", path="/callback")
        return resp

    async def callback(request: Request) -> Response:
        idp = request.path_params["idp"]
        q = request.query_params
        up = cfg.upstreams.get(idp)
        flow = store.take_flow(q.get("state", ""), cfg.pending_ttl) if q.get("state") else None
        if up is None or flow is None or flow["idp"] != idp:
            return _html(pages.error("This sign-in has expired or was already used."), 400)
        pending = store.get_pending(flow["pending_id"], cfg.pending_ttl)
        if pending is None:
            return _html(pages.error("This sign-in has expired."), 400)
        client = cfg.clients[pending["client_id"]]
        browser = request.cookies.get(COOKIE, "")
        if not browser or not hmac.compare_digest(
                hashlib.sha256(browser.encode()).hexdigest(), flow["browser_hash"]):
            audit(request, "callback_refused", reason="browser binding mismatch",
                  idp=idp, client=client.client_id)
            return _html(pages.error("Please finish signing in in the same browser you started in."), 400)
        if q.get("error"):
            audit(request, "signin_cancelled", idp=idp, client=client.client_id, reason=q.get("error"))
            return _html(pages.error("Sign-in was cancelled."), 400)
        try:
            id_token = await prov.exchange(up, code=q.get("code", ""), verifier=flow["verifier"],
                                           redirect_uri=f"{cfg.issuer}/callback/{idp}")
            claims = await prov.verify(up, id_token, nonce=flow["nonce"])
            who: Identity = prov.identity(up, claims)
        except IdentityRefused as e:
            audit(request, "signin_refused", idp=idp, client=client.client_id, reason=e.reason)
            return _html(pages.refused(client.name, None, e.user_message), 403)
        except UpstreamError as e:
            audit(request, "upstream_error", idp=idp, client=client.client_id, reason=str(e))
            return _html(pages.error("We could not confirm your sign-in. Please try again."), 502)
        if not client.allows(who.email):
            audit(request, "signin_refused", idp=idp, client=client.client_id, email=who.email,
                  tenant=who.tenant, reason="not on allowlist")
            return _html(pages.refused(client.name, who.email,
                                       "This account has not been given access."), 403)
        code = store.put_code({"client_id": client.client_id, "redirect_uri": pending["redirect_uri"],
                               "code_challenge": pending["code_challenge"], "scope": pending["scope"],
                               "nonce": pending["nonce"], "resource": pending["resource"],
                               "sub": who.subject, "email": who.email, "idp": who.idp,
                               "tenant": who.tenant, "name": who.name})
        store.drop_pending(flow["pending_id"])
        audit(request, "signin_ok", idp=idp, client=client.client_id, email=who.email, tenant=who.tenant)
        params = {"code": code}
        if pending["state"]:
            params["state"] = pending["state"]
        return RedirectResponse(_with_query(pending["redirect_uri"], params), 302)

    # --- token endpoint -------------------------------------------------------
    def _client_auth(request: Request, form: Any) -> Client | None:
        cid = sec = None
        authz = request.headers.get("authorization", "")
        if authz.lower().startswith("basic "):
            try:
                from urllib.parse import unquote
                cid, sec = base64.b64decode(authz[6:]).decode().split(":", 1)
                cid, sec = unquote(cid), unquote(sec)
            except (ValueError, UnicodeDecodeError):
                return None
        else:
            cid, sec = form.get("client_id"), form.get("client_secret")
        c = cfg.clients.get(cid or "")
        if c is None or not sec or not hmac.compare_digest(c.secret.encode(), str(sec).encode()):
            return None
        return c

    def _issue(client: Client, d: dict[str, Any], *, family: str | None,
               nonce: str | None) -> dict[str, Any]:
        now = int(time.time())
        base = {"iss": cfg.issuer, "sub": d["sub"], "aud": client.client_id, "azp": client.client_id,
                "iat": now, "nbf": now, "exp": now + cfg.access_ttl, "email": d["email"],
                "email_verified": True, "idp": d["idp"], "client_id": client.client_id,
                **({"name": d["name"]} if d.get("name") else {}),
                **({"tid": d["tenant"]} if d.get("tenant") else {})}
        access = key.sign({**base, "jti": secrets.token_urlsafe(16), "scope": d["scope"]})
        idt = key.sign({**base, **({"nonce": nonce} if nonce else {})})
        refresh = store.put_refresh(client.client_id, d, cfg.refresh_ttl, family=family)
        return {"access_token": access, "token_type": "Bearer", "expires_in": cfg.access_ttl,
                "refresh_token": refresh, "id_token": idt, "scope": d["scope"]}

    async def token(request: Request) -> Response:
        form = await request.form()
        client = _client_auth(request, form)
        if client is None:
            audit(request, "token_refused", reason="client authentication failed")
            return _oauth_error("invalid_client", "client authentication failed", 401)
        grant = form.get("grant_type")
        if grant == "authorization_code":
            status, d = store.take_code(str(form.get("code", "")), cfg.code_ttl)
            if status != "ok" or d is None:
                audit(request, "token_refused", client=client.client_id, reason=f"code {status}")
                return _oauth_error("invalid_grant", f"authorization code {status}")
            if d["client_id"] != client.client_id or form.get("redirect_uri") != d["redirect_uri"]:
                audit(request, "token_refused", client=client.client_id, reason="code/client/redirect mismatch")
                return _oauth_error("invalid_grant", "code was not issued to this client/redirect_uri")
            verifier = str(form.get("code_verifier", ""))
            if not verifier or not hmac.compare_digest(_s256(verifier), d["code_challenge"]):
                audit(request, "token_refused", client=client.client_id, reason="PKCE mismatch")
                return _oauth_error("invalid_grant", "PKCE verification failed")
            if not client.allows(d["email"]):
                return _oauth_error("invalid_grant", "account no longer has access")
            out = _issue(client, d, family=None, nonce=d.get("nonce") or None)
            audit(request, "token_issued", client=client.client_id, email=d["email"], grant=grant)
        elif grant == "refresh_token":
            status, d, family = store.rotate_refresh(str(form.get("refresh_token", "")), client.client_id)
            if status != "ok" or d is None:
                audit(request, "token_refused", client=client.client_id, reason=f"refresh {status}",
                      family=family)
                return _oauth_error("invalid_grant", f"refresh token {status}")
            if not client.allows(d["email"]):
                store.revoke_family(family)
                audit(request, "access_revoked", client=client.client_id, email=d["email"],
                      reason="no longer on allowlist")
                return _oauth_error("invalid_grant", "account no longer has access")
            out = _issue(client, d, family=family, nonce=None)
            audit(request, "token_refreshed", client=client.client_id, email=d["email"])
        else:
            return _oauth_error("unsupported_grant_type", "authorization_code or refresh_token")
        return JSONResponse(out, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        async def sweeper() -> None:
            n = 0
            while True:
                try:
                    store.sweep(cfg.pending_ttl, cfg.code_ttl)
                    if n % 12 == 0:   # hourly: rewriting the audit file is not free
                        dropped = prune_audit(audit_path, cfg.audit_retention_days)
                        if dropped:
                            logger.info("audit retention: dropped %d record(s) older than %d days",
                                        dropped, cfg.audit_retention_days)
                except Exception as e:  # noqa: BLE001 - housekeeping must never kill the service
                    logger.warning("sweep failed: %s: %s", type(e).__name__, e)
                n += 1
                await asyncio.sleep(300)
        task = asyncio.create_task(sweeper())
        logger.info("mcp-login issuer=%s providers=%s clients=%s", cfg.issuer,
                    ",".join(sorted(cfg.upstreams)), ",".join(sorted(cfg.clients)))
        try:
            yield
        finally:
            task.cancel()

    return Starlette(routes=[
        Route("/.well-known/openid-configuration", openid_configuration),
        Route("/jwks", jwks),
        Route("/healthz", healthz),
        Route("/privacy", privacy),
        Route("/authorize", authorize),
        Route("/start/{idp}", start),
        Route("/callback/{idp}", callback),
        Route("/token", token, methods=["POST"]),
    ], lifespan=lifespan)
