"""Upstream identity providers: Google and Microsoft.

This module turns "the provider says this person signed in" into ONE verified,
lower-cased email address, or refuses. The rules are the security model, so
they live here in one place:

  Google     email_verified must be true.
  Microsoft  personal accounts (tid 9188040d-...): the email claim is Microsoft's
             own, verified. The operator's own tenant (MCP_LOGIN_STAFF_TENANT,
             optional): trusted (it is theirs, with their MFA).
             Any other tenant: the `email` claim is NOT verified by default and
             has been used for impersonation ("nOAuth"), so it is accepted only
             when the `xms_edov` optional claim (email domain owner verified)
             is true. Otherwise refused, with a "use Google instead" message.
  Staff      an address on one of the operator's domains (MCP_LOGIN_STAFF_DOMAINS)
             is accepted ONLY from Microsoft with the staff tenant id, so staff
             always pass the operator's MFA.

Endpoints are read from each provider's published discovery document, never
typed in here.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from .config import Config, Upstream

MSA_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"
GOOGLE_ISSUERS = {"https://accounts.google.com", "accounts.google.com"}
HTTP_TIMEOUT = 15.0


class UpstreamError(RuntimeError):
    """The provider could not be reached or answered nonsense."""


class IdentityRefused(PermissionError):
    """A real sign-in that we will not accept. `user_message` is safe to show."""

    def __init__(self, reason: str, user_message: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.user_message = user_message


@dataclass(frozen=True)
class Identity:
    email: str
    subject: str        # stable per provider account: "google|<sub>", "microsoft|<tid>|<oid>"
    idp: str
    tenant: str | None
    name: str | None


def pkce_pair() -> tuple[str, str]:
    import secrets
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class Providers:
    """Discovery + JWKS caches. Caches hold in-flight TASKS, not results, so a
    burst of sign-ins after a restart makes one fetch, not one each."""

    def __init__(self, cfg: Config, http: httpx.AsyncClient | None = None) -> None:
        self._cfg = cfg
        self._http = http or httpx.AsyncClient(timeout=HTTP_TIMEOUT)
        self._disc: dict[str, asyncio.Task] = {}
        self._jwks: dict[str, tuple[float, asyncio.Task]] = {}

    async def _get_json(self, url: str) -> dict[str, Any]:
        try:
            r = await self._http.get(url)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise UpstreamError(f"GET {url}: {type(e).__name__}: {e}") from e

    async def discovery(self, up: Upstream) -> dict[str, Any]:
        t = self._disc.get(up.discovery_url)
        if t is None or (t.done() and t.exception() is not None):
            t = asyncio.ensure_future(self._get_json(up.discovery_url))
            self._disc[up.discovery_url] = t
        return await t

    async def _keys(self, jwks_uri: str, *, force: bool = False) -> dict[str, Any]:
        entry = self._jwks.get(jwks_uri)
        stale = entry is None or (time.time() - entry[0] > 3600)
        failed = entry is not None and entry[1].done() and entry[1].exception() is not None
        # A forced refetch (unknown kid) is limited to once a minute, so a
        # stream of junk tokens cannot turn us into a JWKS-fetching amplifier.
        recent = entry is not None and time.time() - entry[0] < 60
        if stale or failed or (force and not recent):
            entry = (time.time(), asyncio.ensure_future(self._get_json(jwks_uri)))
            self._jwks[jwks_uri] = entry
        return await entry[1]

    async def authorize_url(self, up: Upstream, *, redirect_uri: str, state: str,
                            nonce: str, code_challenge: str) -> str:
        d = await self.discovery(up)
        params = {
            "client_id": up.client_id, "response_type": "code",
            "redirect_uri": redirect_uri, "scope": "openid email profile",
            "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
            # Let a person with several accounts pick the right one.
            "prompt": "select_account",
        }
        if up.name == "microsoft":
            params["response_mode"] = "query"
        return f"{d['authorization_endpoint']}?{urlencode(params)}"

    async def exchange(self, up: Upstream, *, code: str, redirect_uri: str,
                       verifier: str) -> str:
        """Authorization code -> the provider's id_token (a JWT)."""
        d = await self.discovery(up)
        try:
            r = await self._http.post(d["token_endpoint"], data={
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": redirect_uri, "client_id": up.client_id,
                "client_secret": up.client_secret, "code_verifier": verifier,
            }, headers={"Accept": "application/json"})
        except httpx.HTTPError as e:
            raise UpstreamError(f"{up.name} token endpoint: {type(e).__name__}: {e}") from e
        if r.status_code != 200:
            # The body can name the problem (redirect mismatch, bad secret) and
            # holds no credential on an error, so it is kept for the log.
            raise UpstreamError(f"{up.name} token endpoint -> {r.status_code}: {r.text[:300]}")
        idt = r.json().get("id_token")
        if not idt:
            raise UpstreamError(f"{up.name} returned no id_token")
        return idt

    async def verify(self, up: Upstream, id_token: str, *, nonce: str) -> dict[str, Any]:
        d = await self.discovery(up)
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as e:
            raise UpstreamError(f"{up.name} id_token is not a JWT: {e}") from e
        if header.get("alg") != "RS256":
            raise UpstreamError(f"{up.name} id_token alg {header.get('alg')!r} refused")
        keys = await self._keys(d["jwks_uri"])
        jwk = next((k for k in keys.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if jwk is None:
            keys = await self._keys(d["jwks_uri"], force=True)
            jwk = next((k for k in keys.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if jwk is None:
            raise UpstreamError(f"{up.name} id_token signed with an unknown key")
        key = jwt.PyJWK(jwk).key
        try:
            claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=up.client_id,
                                options={"require": ["iss", "aud", "exp", "iat", "sub"],
                                         "verify_iss": False}, leeway=60)
        except jwt.PyJWTError as e:
            raise UpstreamError(f"{up.name} id_token rejected: {e}") from e
        # Issuer, checked by hand because Microsoft's is per-tenant.
        iss = claims.get("iss")
        if up.name == "google":
            ok = iss in GOOGLE_ISSUERS
        else:
            tid = claims.get("tid") or ""
            ok = bool(tid) and iss == d["issuer"].replace("{tenantid}", tid)
        if not ok:
            raise UpstreamError(f"{up.name} id_token issuer {iss!r} refused")
        if claims.get("nonce") != nonce:
            raise UpstreamError(f"{up.name} id_token nonce mismatch (replay?)")
        return claims

    def identity(self, up: Upstream, claims: dict[str, Any]) -> Identity:
        return identity_from_claims(self._cfg, up.name, claims)


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1")


def identity_from_claims(cfg: Config, idp: str, c: dict[str, Any]) -> Identity:
    """The acceptance rules. Pure, so every branch is unit-tested."""
    use_google = ("Try Continue with Google, or ask whoever gave you access to add "
                  "the address your account uses.")
    # An unset staff tenant must never match: compare only when one is configured.
    staff_tenant = cfg.staff_tenant or None
    if idp == "google":
        email = str(c.get("email") or "").strip().lower()
        if not email or not _truthy(c.get("email_verified")):
            raise IdentityRefused("google: no verified email",
                                  "Your Google account does not have a verified email address.")
        tenant, subject = None, f"google|{c['sub']}"
    elif idp == "microsoft":
        tid = str(c.get("tid") or "")
        oid = str(c.get("oid") or c["sub"])
        if staff_tenant is not None and tid == staff_tenant:
            # Our own directory: its accounts, its MFA. The UPN is authoritative.
            email = str(c.get("email") or c.get("preferred_username") or "").strip().lower()
        elif tid == MSA_TENANT:
            email = str(c.get("email") or "").strip().lower()
        else:
            email = str(c.get("email") or "").strip().lower()
            if not _truthy(c.get("xms_edov")):
                raise IdentityRefused(
                    f"microsoft: tenant {tid} email not domain-verified (xms_edov absent/false)",
                    "Your organization's Microsoft account does not confirm your email "
                    "address to us, so we cannot use it to sign you in. " + use_google)
        if not email:
            raise IdentityRefused("microsoft: no email claim",
                                  "Your Microsoft account did not share an email address. " + use_google)
        tenant, subject = tid, f"microsoft|{tid}|{oid}"
    else:
        raise IdentityRefused(f"unknown idp {idp}", "Unknown sign-in method.")

    domain = email.rsplit("@", 1)[-1]
    if domain in cfg.staff_domains and not (
            idp == "microsoft" and staff_tenant is not None and tenant == staff_tenant):
        raise IdentityRefused(
            f"staff address {email} via {idp}/{tenant}: refused",
            "Staff sign in with Continue with Microsoft, using their work account.")
    return Identity(email=email, subject=subject, idp=idp, tenant=tenant,
                    name=(c.get("name") or None))
