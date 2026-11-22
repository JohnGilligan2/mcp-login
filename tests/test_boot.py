"""Boot test: the real entry point, configured only from the environment, serves health and
discovery. Unit-green is not deploy-green; this is the closest thing to a container start
that runs without a network."""
from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent


def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_LOGIN_ISSUER", "https://login.example.com")
    monkeypatch.setenv("MCP_LOGIN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MCP_LOGIN_CLIENTS_FILE", str(ROOT / "clients.example.json"))
    monkeypatch.setenv("MCP_LOGIN_CLIENT_SECRETS",
                       "demo-info-mcp:" + "a" * 40 + ",acme-reports-mcp:" + "b" * 40)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "stub-google-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "stub-google-secret")


def test_main_starts_from_env_and_serves_health(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    import uvicorn
    from mcp_login import __main__ as entry

    started = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: started.update(app=app, **kw))
    entry.main()
    assert started["port"] == 8000 and started["proxy_headers"] is True
    with TestClient(started["app"], base_url="https://login.example.com") as c:
        h = c.get("/healthz").json()
        assert h["status"] == "ok" and h["providers"] == ["google"]
        assert h["clients"] == ["acme-reports-mcp", "demo-info-mcp"]
        d = c.get("/.well-known/openid-configuration").json()
        assert d["issuer"] == "https://login.example.com"
        assert c.get("/jwks").json()["keys"][0]["alg"] == "RS256"
        # privacy fields unset -> the draft is never served
        assert c.get("/privacy").status_code == 503
    assert (tmp_path / "signing-key.pem").exists()


def test_missing_secret_refuses_to_boot(monkeypatch, tmp_path):
    import pytest
    from mcp_login.config import ConfigError, load
    _env(monkeypatch, tmp_path)
    monkeypatch.setenv("MCP_LOGIN_CLIENT_SECRETS", "demo-info-mcp:" + "a" * 40)
    with pytest.raises(ConfigError, match="acme-reports-mcp"):
        load()
