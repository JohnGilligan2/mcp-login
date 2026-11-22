"""Every variable the code reads is declared in compose (stack managers only
substitute into compose; a missing one silently falls back to a default)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_every_env_var_the_code_reads_is_in_compose():
    read: set[str] = set()
    for py in (ROOT / "mcp_login").rglob("*.py"):
        t = py.read_text(encoding="utf-8")
        read |= set(re.findall(r"os\.environ\.get\(\s*[\"']([A-Z0-9_]+)[\"']", t))
        read |= set(re.findall(r"_int\(\s*[\"']([A-Z0-9_]+)[\"']", t))
        # f"{name.upper()}_CLIENT_ID" and friends
        for n in ("GOOGLE", "MICROSOFT"):
            for suf in ("CLIENT_ID", "CLIENT_SECRET"):
                if "{name.upper()}_" + suf in t:
                    read.add(f"{n}_{suf}")
    # Test/local-only switches and per-provider discovery overrides, never set in production.
    read -= {"MCP_LOGIN_INSECURE"}
    body = (ROOT / "docker-compose.yml").read_text(encoding="utf-8").split("environment:", 1)[1]
    declared = set(re.findall(r"^\s{6}([A-Z0-9_]+):", body, flags=re.M))
    missing = sorted(read - declared)
    assert not missing, f"read by code but not in compose: {missing}"


def test_insecure_switch_is_never_in_compose():
    assert "MCP_LOGIN_INSECURE" not in (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
