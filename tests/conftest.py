"""Fake Google and Microsoft, served through httpx.MockTransport.

They sign real RS256 id_tokens with their own keys, so the production
verification code (JWKS lookup, issuer, audience, nonce, alg) runs unmodified.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from mcp_login.app import build_app
from mcp_login.config import Client, Config, Upstream
from mcp_login.idp import MSA_TENANT, Providers

STAFF_TENANT = "00000000-0000-0000-0000-000000000002"
OTHER_TENANT = "00000000-0000-0000-0000-000000000003"
REDIRECT = "https://demo-mcp.example.com/auth/callback"
SECRET = "s" * 40
ISSUER = "https://mcp-login.test"


def _b64(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


class FakeIdP:
    def __init__(self, name: str, issuer: str, base: str) -> None:
        self.name, self.issuer, self.base = name, issuer, base
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = f"{name}-k1"
        self.codes: dict[str, dict] = {}   # upstream code -> claims to mint
        self.token_calls: list[dict] = []

    @property
    def discovery_url(self) -> str:
        return f"{self.base}/.well-known/openid-configuration"

    def jwks(self) -> dict:
        n = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "kid": self.kid, "alg": "RS256", "use": "sig",
                          "n": _b64(n.n), "e": _b64(n.e)}]}

    def mint(self, claims: dict, *, key=None, kid=None, alg="RS256") -> str:
        now = int(time.time())
        body = {"iat": now, "exp": now + 600, **claims}
        k = key or self.key
        if alg == "HS256":
            return jwt.encode(body, "not-a-real-key-but-long-enough-for-hs256", algorithm="HS256",
                              headers={"kid": kid or self.kid})
        return jwt.encode(body, k, algorithm=alg, headers={"kid": kid or self.kid})

    def handle(self, request: httpx.Request) -> httpx.Response | None:
        url = str(request.url)
        if url == self.discovery_url:
            return httpx.Response(200, json={
                "issuer": self.issuer, "authorization_endpoint": f"{self.base}/authorize",
                "token_endpoint": f"{self.base}/token", "jwks_uri": f"{self.base}/jwks"})
        if url == f"{self.base}/jwks":
            return httpx.Response(200, json=self.jwks())
        if url == f"{self.base}/token":
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            self.token_calls.append(form)
            code = form.get("code", "")
            if code not in self.codes:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.codes.pop(code)["__token__"]})
        return None


class Env:
    def __init__(self, tmp: Path) -> None:
        self.google = FakeIdP("google", "https://accounts.google.com", "https://google.fake")
        self.ms = FakeIdP("microsoft", "https://login.microsoftonline.com/{tenantid}/v2.0",
                          "https://microsoft.fake")

        def route(req: httpx.Request) -> httpx.Response:
            for idp in (self.google, self.ms):
                r = idp.handle(req)
                if r is not None:
                    return r
            return httpx.Response(404)

        self.cfg = Config(
            issuer=ISSUER, data_dir=tmp,
            clients={"demo-info-mcp": Client(
                client_id="demo-info-mcp", name="Example Movers", secret=SECRET,
                redirect_uris=(REDIRECT,),
                allow=frozenset({"customer@example.com", "boss@customer.example",
                                 "admin@staff.example", "personal@example.org"}),
                allow_domains=frozenset())},
            upstreams={"google": Upstream("google", "g-client", "g-secret", self.google.discovery_url),
                       "microsoft": Upstream("microsoft", "m-client", "m-secret", self.ms.discovery_url)},
            staff_tenant=STAFF_TENANT, staff_domains=("staff.example",),
            insecure_cookies=True,
        )
        self.providers = Providers(self.cfg, http=httpx.AsyncClient(transport=httpx.MockTransport(route)))
        self.app = build_app(self.cfg, providers=self.providers)
        self.client = TestClient(self.app, base_url="https://mcp-login.test", follow_redirects=False)

    # --- the flow, step by step ------------------------------------------------
    def authorize(self, **over) -> httpx.Response:
        self.verifier = "v" * 50
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()
        params = {"client_id": "demo-info-mcp", "redirect_uri": REDIRECT, "response_type": "code",
                  "state": "client-state", "code_challenge": challenge, "code_challenge_method": "S256",
                  "scope": "openid email offline_access", "nonce": "client-nonce",
                  "resource": "https://demo-mcp.example.com/mcp"}
        params.update(over)
        params = {k: v for k, v in params.items() if v is not None}
        return self.client.get("/authorize", params=params)

    def start(self, idp: str) -> tuple[httpx.Response, dict]:
        page = self.authorize()
        assert page.status_code == 200, page.text
        href = page.text.split(f'href="{ISSUER}/start/{idp}?r=', 1)[1].split('"', 1)[0]
        r = self.client.get(f"/start/{idp}", params={"r": href})
        assert r.status_code == 302, r.text
        up = {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
        return r, up

    def signin(self, idp: str, claims: dict, *, token_kw: dict | None = None,
               tamper: dict | None = None) -> httpx.Response:
        """Full browser flow; returns the /callback response."""
        _, up = self.start(idp)
        fake = self.google if idp == "google" else self.ms
        body = {"aud": fake.name[0] + "-client", "nonce": up["nonce"], **claims}
        if tamper:
            body.update(tamper)
        fake.codes["up-code"] = {"__token__": fake.mint(body, **(token_kw or {}))}
        return self.client.get(f"/callback/{idp}", params={"code": "up-code", "state": up["state"]})

    def code_from(self, r: httpx.Response) -> str:
        assert r.status_code == 302, r.text
        loc = r.headers["location"]
        assert loc.startswith(REDIRECT), loc
        q = {k: v[0] for k, v in parse_qs(urlsplit(loc).query).items()}
        assert q["state"] == "client-state"
        return q["code"]

    def exchange(self, code: str, **over) -> httpx.Response:
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                "code_verifier": self.verifier, "client_id": "demo-info-mcp",
                "client_secret": SECRET}
        data.update(over)
        return self.client.post("/token", data={k: v for k, v in data.items() if v is not None})

    def refresh(self, rt: str, **over) -> httpx.Response:
        data = {"grant_type": "refresh_token", "refresh_token": rt,
                "client_id": "demo-info-mcp", "client_secret": SECRET}
        data.update(over)
        return self.client.post("/token", data=data)


GOOGLE_OK = {"iss": "https://accounts.google.com", "sub": "g-123",
             "email": "customer@example.com", "email_verified": True, "name": "Cust Omer"}


def ms_claims(tid: str, email: str, **extra) -> dict:
    return {"iss": f"https://login.microsoftonline.com/{tid}/v2.0", "sub": "m-sub",
            "tid": tid, "oid": "m-oid", "email": email, **extra}


@pytest.fixture()
def env(tmp_path):
    e = Env(tmp_path)
    with e.client:
        yield e
