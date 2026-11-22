"""End-to-end browser + token flows, and every row of the security table."""
from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import (GOOGLE_OK, ISSUER, MSA_TENANT, OTHER_TENANT, REDIRECT, SECRET,
                      STAFF_TENANT, ms_claims)
from mcp_login.config import ConfigError, _parse_secrets, load_clients


def _verify(env, token: str) -> dict:
    jwks = env.client.get("/jwks").json()
    key = jwt.PyJWK(jwks["keys"][0]).key
    return jwt.decode(token, key, algorithms=["RS256"], audience="demo-info-mcp", issuer=ISSUER)


# --- discovery -----------------------------------------------------------------
def test_discovery_document(env):
    d = env.client.get("/.well-known/openid-configuration").json()
    assert d["issuer"] == ISSUER
    assert d["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert d["token_endpoint"] == f"{ISSUER}/token"
    assert d["jwks_uri"] == f"{ISSUER}/jwks"
    assert d["code_challenge_methods_supported"] == ["S256"]
    assert "registration_endpoint" not in d   # no DCR here, by design


# --- /authorize never redirects until client + redirect_uri are proven ---------
def test_unknown_client_is_an_error_page_not_a_redirect(env):
    r = env.authorize(client_id="evil")
    assert r.status_code == 400 and "location" not in r.headers


def test_unregistered_redirect_uri_is_an_error_page_not_a_redirect(env):
    r = env.authorize(redirect_uri="https://evil.example/cb")
    assert r.status_code == 400 and "location" not in r.headers


def test_redirect_uri_must_match_exactly(env):
    assert env.authorize(redirect_uri=REDIRECT + "/extra").status_code == 400
    assert env.authorize(redirect_uri=REDIRECT + "?x=1").status_code == 400


@pytest.mark.parametrize("over", [{"code_challenge": None}, {"code_challenge_method": "plain"},
                                  {"code_challenge_method": None}])
def test_pkce_s256_is_required(env, over):
    r = env.authorize(**over)
    assert r.status_code == 302
    assert "error=invalid_request" in r.headers["location"]
    assert r.headers["location"].startswith(REDIRECT)


def test_chooser_offers_both_providers_and_names_the_server(env):
    r = env.authorize()
    assert r.status_code == 200
    assert "Continue with Google" in r.text and "Continue with Microsoft" in r.text
    assert "Sign in to Example Movers" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


# --- Google ----------------------------------------------------------------------
def test_google_happy_path_end_to_end(env):
    code = env.code_from(env.signin("google", GOOGLE_OK))
    tok = env.exchange(code)
    assert tok.status_code == 200, tok.text
    t = tok.json()
    a = _verify(env, t["access_token"])
    assert a["email"] == "customer@example.com" and a["idp"] == "google"
    assert a["aud"] == "demo-info-mcp" and a["sub"] == "google|g-123"
    assert "offline_access" in a["scope"]
    i = _verify(env, t["id_token"])
    assert i["nonce"] == "client-nonce"
    assert t["refresh_token"] and t["expires_in"] == 3600
    assert tok.headers["cache-control"] == "no-store"


def test_upstream_is_called_with_pkce_verifier(env):
    env.code_from(env.signin("google", GOOGLE_OK))
    call = env.google.token_calls[-1]
    assert call["code_verifier"] and call["client_secret"] == "g-secret"


def test_google_unverified_email_is_refused(env):
    r = env.signin("google", {**GOOGLE_OK, "email_verified": False})
    assert r.status_code == 403 and "location" not in r.headers


def test_email_not_on_allowlist_is_refused_and_gets_no_code(env):
    r = env.signin("google", {**GOOGLE_OK, "email": "stranger@example.net"})
    assert r.status_code == 403
    assert "stranger@example.net" in r.text and "has not been given access" in r.text


def test_allowlist_match_is_case_insensitive(env):
    env.code_from(env.signin("google", {**GOOGLE_OK, "email": "Customer@EXAMPLE.com"}))


# --- Microsoft ------------------------------------------------------------------
def test_personal_microsoft_account_is_accepted(env):
    env.code_from(env.signin("microsoft", ms_claims(MSA_TENANT, "personal@example.org")))


def test_work_account_without_domain_verified_email_is_refused(env):
    """The nOAuth class: an unverified `email` claim from someone else's tenant."""
    r = env.signin("microsoft", ms_claims(OTHER_TENANT, "boss@customer.example"))
    assert r.status_code == 403 and "Continue with Google" in r.text


@pytest.mark.parametrize("edov", [False, "false", "0", None])
def test_work_account_edov_false_is_refused(env, edov):
    extra = {} if edov is None else {"xms_edov": edov}
    r = env.signin("microsoft", ms_claims(OTHER_TENANT, "boss@customer.example", **extra))
    assert r.status_code == 403


@pytest.mark.parametrize("edov", [True, "true", "1", 1])
def test_work_account_with_domain_verified_email_is_accepted(env, edov):
    env.code_from(env.signin("microsoft", ms_claims(OTHER_TENANT, "boss@customer.example",
                                                   xms_edov=edov)))


def test_staff_sign_in_through_our_own_tenant(env):
    c = ms_claims(STAFF_TENANT, "")
    c.pop("email")
    c["preferred_username"] = "admin@staff.example"
    code = env.code_from(env.signin("microsoft", c))
    assert _verify(env, env.exchange(code).json()["access_token"])["email"] == "admin@staff.example"


def test_staff_address_via_google_is_refused(env):
    r = env.signin("google", {**GOOGLE_OK, "email": "admin@staff.example"})
    assert r.status_code == 403 and "Continue with Microsoft" in r.text


def test_staff_address_from_another_tenant_is_refused_even_if_domain_verified(env):
    r = env.signin("microsoft", ms_claims(OTHER_TENANT, "admin@staff.example", xms_edov=True))
    assert r.status_code == 403


def test_unset_staff_tenant_never_matches_a_token(env):
    """With no staff tenant configured, an empty `tid` must not be read as 'ours'."""
    import dataclasses
    from mcp_login.idp import IdentityRefused, identity_from_claims
    cfg = dataclasses.replace(env.cfg, staff_tenant="", staff_domains=("staff.example",))
    with pytest.raises(IdentityRefused):   # empty tid, no xms_edov: not trusted
        identity_from_claims(cfg, "microsoft", {"sub": "s", "tid": "", "email": "a@customer.example"})
    with pytest.raises(IdentityRefused):   # staff domain with no staff tenant: refused
        identity_from_claims(cfg, "microsoft", {"sub": "s", "tid": "", "preferred_username": "x@staff.example"})


# --- forged / replayed provider responses --------------------------------------
def test_microsoft_issuer_must_match_the_tokens_own_tenant(env):
    r = env.signin("microsoft", ms_claims(MSA_TENANT, "personal@example.org"),
                   tamper={"iss": f"https://login.microsoftonline.com/{OTHER_TENANT}/v2.0"})
    assert r.status_code == 502


def test_google_wrong_issuer_is_refused(env):
    r = env.signin("google", GOOGLE_OK, tamper={"iss": "https://evil.example"})
    assert r.status_code == 502


def test_wrong_audience_is_refused(env):
    r = env.signin("google", GOOGLE_OK, tamper={"aud": "someone-elses-app"})
    assert r.status_code == 502


def test_nonce_mismatch_is_refused(env):
    r = env.signin("google", GOOGLE_OK, tamper={"nonce": "replayed"})
    assert r.status_code == 502


def test_expired_id_token_is_refused(env):
    r = env.signin("google", GOOGLE_OK, tamper={"exp": int(time.time()) - 3600,
                                                "iat": int(time.time()) - 7200})
    assert r.status_code == 502


def test_token_signed_by_an_unknown_key_is_refused(env):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    r = env.signin("google", GOOGLE_OK, token_kw={"key": other, "kid": "attacker"})
    assert r.status_code == 502


def test_token_signed_with_the_right_kid_but_wrong_key_is_refused(env):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    r = env.signin("google", GOOGLE_OK, token_kw={"key": other})
    assert r.status_code == 502


def test_hs256_token_is_refused(env):
    r = env.signin("google", GOOGLE_OK, token_kw={"alg": "HS256"})
    assert r.status_code == 502


# --- browser binding and replay --------------------------------------------------
def test_callback_in_a_different_browser_is_refused(env):
    _, up = env.start("google")
    env.google.codes["up-code"] = {"__token__": env.google.mint(
        {**GOOGLE_OK, "aud": "g-client", "nonce": up["nonce"]})}
    env.client.cookies.clear()
    r = env.client.get("/callback/google", params={"code": "up-code", "state": up["state"]})
    assert r.status_code == 400 and "same browser" in r.text


def test_callback_state_is_single_use(env):
    _, up = env.start("google")
    env.google.codes["up-code"] = {"__token__": env.google.mint(
        {**GOOGLE_OK, "aud": "g-client", "nonce": up["nonce"]})}
    first = env.client.get("/callback/google", params={"code": "up-code", "state": up["state"]})
    assert first.status_code == 302
    again = env.client.get("/callback/google", params={"code": "up-code", "state": up["state"]})
    assert again.status_code == 400


def test_cancelled_sign_in_is_a_clean_page(env):
    _, up = env.start("google")
    r = env.client.get("/callback/google", params={"error": "access_denied", "state": up["state"]})
    assert r.status_code == 400 and "cancelled" in r.text


def test_browser_cookie_is_secure_httponly_by_default(tmp_path):
    from conftest import Env
    e = Env(tmp_path)
    e.cfg.insecure_cookies = False
    from mcp_login.app import build_app
    from starlette.testclient import TestClient
    app = build_app(e.cfg, providers=e.providers)
    with TestClient(app, base_url="https://mcp-login.test", follow_redirects=False) as c:
        e.client = c
        r, _ = e.start("google")
    cookie = r.headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie


# --- /token ----------------------------------------------------------------------
def test_wrong_client_secret_is_refused(env):
    code = env.code_from(env.signin("google", GOOGLE_OK))
    assert env.exchange(code, client_secret="x" * 40).status_code == 401


def test_basic_auth_client_credentials_work(env):
    import base64
    code = env.code_from(env.signin("google", GOOGLE_OK))
    basic = base64.b64encode(f"demo-info-mcp:{SECRET}".encode()).decode()
    r = env.client.post("/token", headers={"Authorization": f"Basic {basic}"}, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "code_verifier": env.verifier})
    assert r.status_code == 200, r.text


def test_authorization_code_is_single_use(env):
    code = env.code_from(env.signin("google", GOOGLE_OK))
    assert env.exchange(code).status_code == 200
    r = env.exchange(code)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_code_redirect_uri_must_match(env):
    code = env.code_from(env.signin("google", GOOGLE_OK))
    assert env.exchange(code, redirect_uri="https://evil.example/cb").json()["error"] == "invalid_grant"


def test_pkce_verifier_must_match(env):
    code = env.code_from(env.signin("google", GOOGLE_OK))
    assert env.exchange(code, code_verifier="w" * 50).json()["error"] == "invalid_grant"


def test_pkce_verifier_is_required(env):
    code = env.code_from(env.signin("google", GOOGLE_OK))
    assert env.exchange(code, code_verifier=None).json()["error"] == "invalid_grant"


def test_expired_code_is_refused(env):
    env.cfg.code_ttl = 1
    code = env.code_from(env.signin("google", GOOGLE_OK))
    time.sleep(1.2)
    assert env.exchange(code).json()["error"] == "invalid_grant"


def test_unknown_grant_type(env):
    r = env.client.post("/token", data={"grant_type": "password", "client_id": "demo-info-mcp",
                                        "client_secret": SECRET})
    assert r.json()["error"] == "unsupported_grant_type"


# --- refresh ---------------------------------------------------------------------
def _tokens(env):
    return env.exchange(env.code_from(env.signin("google", GOOGLE_OK))).json()


def test_refresh_rotates_and_keeps_identity(env):
    t = _tokens(env)
    r = env.refresh(t["refresh_token"])
    assert r.status_code == 200, r.text
    n = r.json()
    assert n["refresh_token"] != t["refresh_token"]
    assert _verify(env, n["access_token"])["email"] == "customer@example.com"


def test_reusing_a_rotated_refresh_token_revokes_the_whole_chain(env):
    t = _tokens(env)
    n = env.refresh(t["refresh_token"]).json()
    stolen = env.refresh(t["refresh_token"])            # old one, presented again
    assert stolen.json()["error"] == "invalid_grant"
    assert env.refresh(n["refresh_token"]).json()["error"] == "invalid_grant"   # chain is dead


def test_removing_an_email_from_the_allowlist_ends_access_at_next_refresh(env):
    import dataclasses
    t = _tokens(env)
    c = env.cfg.clients["demo-info-mcp"]
    env.cfg.clients["demo-info-mcp"] = dataclasses.replace(
        c, allow=frozenset(c.allow - {"customer@example.com"}))
    assert env.refresh(t["refresh_token"]).json()["error"] == "invalid_grant"
    lines = (env.cfg.data_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert any(json.loads(l)["event"] == "access_revoked" for l in lines)


def test_refresh_token_is_bound_to_its_client(env):
    t = _tokens(env)
    r = env.refresh(t["refresh_token"], client_id="other", client_secret=SECRET)
    assert r.status_code == 401


def test_nothing_credential_like_is_stored_in_clear(env):
    t = _tokens(env)
    raw = (env.cfg.data_dir / "mcp-login.sqlite3").read_bytes()
    assert t["refresh_token"].encode() not in raw


# --- audit -------------------------------------------------------------------------
def test_every_sign_in_outcome_is_audited(env):
    env.code_from(env.signin("google", GOOGLE_OK))
    env.signin("google", {**GOOGLE_OK, "email": "stranger@example.net"})
    rows = [json.loads(l) for l in (env.cfg.data_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    events = [(r["event"], r.get("email")) for r in rows]
    assert ("signin_ok", "customer@example.com") in events
    assert ("signin_refused", "stranger@example.net") in events


# --- configuration ---------------------------------------------------------------
def test_client_without_a_secret_refuses_to_start(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"clients": {"a": {"redirect_uris": ["https://x/cb"]}}}))
    with pytest.raises(ConfigError, match="no secret"):
        load_clients(p, {})


def test_short_secret_refuses_to_start():
    with pytest.raises(ConfigError, match="shorter than 32"):
        _parse_secrets("a:short")


def test_non_https_redirect_refuses_to_start(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"clients": {"a": {"redirect_uris": ["http://x/cb"]}}}))
    with pytest.raises(ConfigError, match="https"):
        load_clients(p, {"a": "s" * 40})


def test_example_clients_file_parses_and_has_no_secrets():
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "clients.example.json"
    raw = json.loads(p.read_text(encoding="utf-8"))
    import re
    for cid, c in raw["clients"].items():
        assert not any("secret" in k.lower() for k in c), f"{cid} carries a secret field"
        for v in json.dumps(c).split('"'):
            # a long unbroken token-like string would be a pasted secret
            assert not re.fullmatch(r"[A-Za-z0-9_\-~.]{32,}", v), f"{cid}: secret-looking value"
    # Every committed client must load, so give each one a stand-in secret.
    cl = load_clients(p, {cid: "s" * 40 for cid in raw["clients"]})
    assert cl["demo-info-mcp"].redirect_uris == ("https://demo-mcp.example.com/auth/callback",)


# --- audit retention (the privacy policy states it, so it is enforced) ------------
def test_audit_records_older_than_retention_are_pruned(tmp_path):
    from mcp_login.app import prune_audit
    p = tmp_path / "audit.jsonl"
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 400 * 86400))
    new = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10 * 86400))
    p.write_text("\n".join([json.dumps({"ts": old, "event": "signin_ok"}),
                            json.dumps({"ts": new, "event": "signin_ok"}),
                            "not json"]) + "\n", encoding="utf-8")
    assert prune_audit(p, 365) == 1
    lines = p.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and "not json" in lines
    assert json.loads(lines[0])["ts"] == new


def test_prune_is_a_no_op_without_old_records(tmp_path):
    from mcp_login.app import prune_audit
    assert prune_audit(tmp_path / "missing.jsonl", 365) == 0


# --- privacy policy ------------------------------------------------------------------
def test_an_unfilled_privacy_draft_is_never_served(env):
    from mcp_login import pages
    if pages.privacy_is_complete():
        pytest.skip("policy has been completed")
    r = env.client.get("/privacy")
    assert r.status_code == 503 and "[" not in r.text


def test_privacy_page_states_the_enforced_numbers(env, monkeypatch):
    from mcp_login import pages
    monkeypatch.setattr(pages, "PRIVACY_FIELDS", {"ENTITY": "Acme", "CONTACT": "p@x", "EFFECTIVE": "today"})
    r = env.client.get("/privacy")
    assert r.status_code == 200
    assert f"{env.cfg.audit_retention_days} days" in r.text
    assert f"{env.cfg.refresh_ttl // 86400}" in r.text
    assert "never receive or store your password" in r.text


def test_a_secret_ahead_of_its_clients_entry_is_tolerated(tmp_path, caplog):
    """Onboarding order: secret in the environment first, clients.json second. The
    service must keep running in between, or every customer loses sign-in."""
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"clients": {"a": {"redirect_uris": ["https://x/cb"]}}}))
    cl = load_clients(p, {"a": "s" * 40, "not-yet-listed": "t" * 40})
    assert set(cl) == {"a"}
    assert "not-yet-listed" in caplog.text
