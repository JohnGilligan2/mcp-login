"""Configuration for mcp-login. Fail-fast: a misconfigured sign-in service
refuses to start rather than serving a door that is open or broken.

Two sources:
  * the ENVIRONMENT (container variables): secrets and URLs.
  * clients.json: which MCP servers may use this service, their redirect URIs,
    and WHO may sign in to each. Keep it in a private repo and every grant and
    removal is a reviewed commit with history. No secrets in that file.
    clients.example.json shows the shape.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    pass


# Optional: the operator's own Entra tenant and email domains. Staff addresses
# are then accepted ONLY through Microsoft sign-in with this tenant id, so staff
# always pass the operator's Conditional Access and MFA. Empty = no staff rule.
DEFAULT_STAFF_TENANT = ""
DEFAULT_STAFF_DOMAINS: tuple[str, ...] = ()

GOOGLE_DISCOVERY = "https://accounts.google.com/.well-known/openid-configuration"
MICROSOFT_DISCOVERY = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"


@dataclass(frozen=True)
class Client:
    """One MCP server that uses this service for sign-in."""

    client_id: str
    name: str                      # shown to the customer: "Example Movers"
    secret: str
    redirect_uris: tuple[str, ...]
    allow: frozenset[str]          # exact, lower-cased email addresses
    allow_domains: frozenset[str]  # whole domains; use deliberately

    def allows(self, email: str) -> bool:
        e = email.strip().lower()
        if e in self.allow:
            return True
        return "@" in e and e.rsplit("@", 1)[1] in self.allow_domains


@dataclass(frozen=True)
class Upstream:
    name: str             # "google" | "microsoft"
    client_id: str
    client_secret: str
    discovery_url: str


@dataclass
class Config:
    issuer: str
    data_dir: Path
    clients: dict[str, Client]
    upstreams: dict[str, Upstream]
    staff_tenant: str
    staff_domains: tuple[str, ...]
    access_ttl: int = 3600
    refresh_ttl: int = 30 * 86400
    code_ttl: int = 60
    pending_ttl: int = 600
    # How long sign-in audit records are kept. The public privacy policy
    # (/privacy) states this number, so it is enforced by the sweeper, not
    # just written down.
    audit_retention_days: int = 365
    host: str = "0.0.0.0"
    port: int = 8000
    # Only for the test suite and local runs. In production the cookie that
    # binds a sign-in to the browser must be Secure.
    insecure_cookies: bool = False
    extra: dict = field(default_factory=dict)


def _int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    try:
        n = int(v)
    except ValueError as e:
        raise ConfigError(f"{name} must be an integer") from e
    if n <= 0:
        raise ConfigError(f"{name} must be > 0")
    return n


def _parse_secrets(raw: str) -> dict[str, str]:
    """MCP_LOGIN_CLIENT_SECRETS='client-id:secret,other:secret'."""
    out: dict[str, str] = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ConfigError("MCP_LOGIN_CLIENT_SECRETS entries must be 'client-id:secret'")
        cid, sec = (x.strip() for x in part.split(":", 1))
        if len(sec) < 32:
            raise ConfigError(f"client secret for {cid!r} is shorter than 32 characters")
        out[cid] = sec
    return out


def load_clients(path: Path, secrets: dict[str, str]) -> dict[str, Client]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ConfigError(f"clients file not found: {path}") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"clients file is not valid JSON: {e}") from e
    clients: dict[str, Client] = {}
    for cid, c in (raw.get("clients") or {}).items():
        if cid not in secrets:
            raise ConfigError(
                f"client {cid!r} is in clients.json but has no secret in "
                "MCP_LOGIN_CLIENT_SECRETS; refusing to start")
        uris = tuple(c.get("redirect_uris") or ())
        if not uris or any(not u.startswith("https://") for u in uris):
            raise ConfigError(f"client {cid!r} needs https:// redirect_uris")
        clients[cid] = Client(
            client_id=cid,
            name=str(c.get("name") or cid),
            secret=secrets[cid],
            redirect_uris=uris,
            allow=frozenset(e.strip().lower() for e in c.get("allow") or () if e.strip()),
            allow_domains=frozenset(d.strip().lower().lstrip("@")
                                    for d in c.get("allow_domains") or () if d.strip()),
        )
    unknown = sorted(set(secrets) - set(clients))
    if unknown:
        # NOT fatal. Adding a server needs a secret in the environment AND an entry
        # in clients.json, and a redeploy picks up whichever landed first. If this
        # refused to start, every onboarding would take sign-in down for every
        # customer for the minutes between the two. So: secret first (this
        # warning), clients.json second. A client listed WITHOUT a secret is
        # still fatal, because that one would be a door with no lock.
        import logging
        logging.getLogger("mcp_login").warning(
            "MCP_LOGIN_CLIENT_SECRETS has secrets for clients not in clients.json "
            "(ignored until they are added): %s", unknown)
    if not clients:
        raise ConfigError("clients.json lists no clients")
    return clients


def load() -> Config:
    issuer = os.environ.get("MCP_LOGIN_ISSUER", "").strip().rstrip("/")
    if not issuer.startswith("https://") and os.environ.get("MCP_LOGIN_INSECURE") != "1":
        raise ConfigError("MCP_LOGIN_ISSUER must be the public https:// URL of this service")

    upstreams: dict[str, Upstream] = {}
    for name, disc in (("google", GOOGLE_DISCOVERY), ("microsoft", MICROSOFT_DISCOVERY)):
        cid = os.environ.get(f"{name.upper()}_CLIENT_ID", "").strip()
        sec = os.environ.get(f"{name.upper()}_CLIENT_SECRET", "").strip()
        if bool(cid) != bool(sec):
            raise ConfigError(f"{name.upper()}_CLIENT_ID and _CLIENT_SECRET must be set together")
        if cid:
            upstreams[name] = Upstream(name, cid, sec, disc)
    if not upstreams:
        raise ConfigError("no sign-in provider configured: set GOOGLE_* and/or MICROSOFT_*")

    here = Path(__file__).resolve().parent
    clients_path = Path(os.environ.get("MCP_LOGIN_CLIENTS_FILE", str(here.parent / "clients.json")))
    clients = load_clients(clients_path, _parse_secrets(os.environ.get("MCP_LOGIN_CLIENT_SECRETS", "")))

    return Config(
        issuer=issuer,
        data_dir=Path(os.environ.get("MCP_LOGIN_DATA_DIR", "/var/lib/mcp-login")),
        clients=clients,
        upstreams=upstreams,
        staff_tenant=os.environ.get("MCP_LOGIN_STAFF_TENANT", DEFAULT_STAFF_TENANT).strip(),
        staff_domains=tuple(d.strip().lower() for d in os.environ.get(
            "MCP_LOGIN_STAFF_DOMAINS", ",".join(DEFAULT_STAFF_DOMAINS)).split(",") if d.strip()),
        access_ttl=_int("MCP_LOGIN_ACCESS_TTL", 3600),
        refresh_ttl=_int("MCP_LOGIN_REFRESH_TTL_DAYS", 30) * 86400,
        audit_retention_days=_int("MCP_LOGIN_AUDIT_RETENTION_DAYS", 365),
        host=os.environ.get("MCP_LOGIN_HOST", "0.0.0.0"),
        port=_int("MCP_LOGIN_PORT", 8000),
        insecure_cookies=os.environ.get("MCP_LOGIN_INSECURE") == "1",
    )
