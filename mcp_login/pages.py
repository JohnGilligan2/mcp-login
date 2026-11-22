"""The only pages a customer sees. No JavaScript; everything escaped."""
from __future__ import annotations

import os
from html import escape

# The name at the top of every page and in the privacy policy.
BRAND = os.environ.get("MCP_LOGIN_BRAND", "").strip() or "MCP Sign-in"

_CSS = """
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --fg:#1b1f24; --muted:#5b6470;
        --line:#d9dde3; --btn:#fff; --btnh:#f0f2f5; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#111418; --card:#1a1f25; --fg:#e8eaed; --muted:#9aa3ad; --line:#2c333b;
          --btn:#222830; --btnh:#2a313a; } }
* { box-sizing:border-box } body { margin:0; background:var(--bg); color:var(--fg);
  font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:420px; margin:10vh auto 0; padding:0 16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:28px; }
.brand { font-weight:700; letter-spacing:.2px; margin:0 0 4px; }
h1 { font-size:20px; margin:0 0 6px; } p { color:var(--muted); margin:0 0 20px; }
a.btn { display:flex; align-items:center; justify-content:center; gap:10px; width:100%;
  padding:12px 14px; margin:0 0 12px; border:1px solid var(--line); border-radius:8px;
  background:var(--btn); color:var(--fg); text-decoration:none; font-weight:600; }
a.btn:hover { background:var(--btnh); }
.small { font-size:13px; color:var(--muted); margin:16px 0 0; }
"""

_G = ('<svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/>'
      '<path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/>'
      '<path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z"/>'
      '<path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>')
_M = ('<svg width="18" height="18" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#F25022"/>'
      '<rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/>'
      '<rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>')

HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
                                "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"),
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


def _page(title: str, body: str) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{escape(title)}</title><style>{_CSS}</style></head>"
            f'<body><main><div class="card"><div class="brand">{escape(BRAND)}</div>{body}</div></main></body></html>')


def chooser(server_name: str, links: dict[str, str]) -> str:
    buttons = []
    if "google" in links:
        buttons.append(f'<a class="btn" href="{escape(links["google"])}">{_G}Continue with Google</a>')
    if "microsoft" in links:
        buttons.append(f'<a class="btn" href="{escape(links["microsoft"])}">{_M}Continue with Microsoft</a>')
    return _page("Sign in", (
        f"<h1>Sign in to {escape(server_name)}</h1>"
        "<p>Use the Google or Microsoft account you already have. "
        "We never see your password.</p>" + "".join(buttons) +
        '<p class="small">Only addresses your organization has asked us to allow can sign in.</p>'))


def refused(server_name: str, email: str | None, message: str) -> str:
    who = f"<p>Signed in as <strong>{escape(email)}</strong>.</p>" if email else ""
    return _page("Cannot sign in", (
        f"<h1>You can't sign in to {escape(server_name)}</h1>{who}"
        f"<p>{escape(message)}</p>"
        f'<p class="small">If you think this is a mistake, contact {escape(BRAND)} support.</p>'))


# PRIVACY POLICY. A public statement on the operator's behalf. Every field comes from the
# environment, and until all three are set /privacy answers "not yet published" instead of
# serving a draft with blanks in it. Every claim in the text is true of the code; if the code
# changes what it collects or how long it keeps it, change this text in the same commit.
PRIVACY_FIELDS = {
    "ENTITY": os.environ.get("MCP_LOGIN_PRIVACY_ENTITY", "").strip() or "[legal entity]",
    "CONTACT": os.environ.get("MCP_LOGIN_PRIVACY_CONTACT", "").strip() or "[contact address]",
    "EFFECTIVE": os.environ.get("MCP_LOGIN_PRIVACY_EFFECTIVE", "").strip() or "[effective date]",
}


def privacy_is_complete() -> bool:
    return not any(v.startswith("[") for v in PRIVACY_FIELDS.values())


def privacy(audit_days: int, session_days: int) -> str:
    f = {k: escape(v) for k, v in PRIVACY_FIELDS.items()}
    b = escape(BRAND)
    return _page("Privacy policy", f"""
<h1>Privacy policy: {b}</h1>
<p>Effective {f['EFFECTIVE']}</p>
<div style="color:var(--fg)">
<h2 style="font-size:16px">Who we are</h2>
<p>{b} is operated by {f['ENTITY']}. It lets people whom our customers have
authorized sign in to services they use through AI assistants such as Claude, with the
Google or Microsoft account they already have.</p>

<h2 style="font-size:16px">What we receive</h2>
<p>When you sign in, Google or Microsoft sends us your email address, your name and an
account identifier (for Microsoft work accounts, also your organization's tenant
identifier). We never receive or store your password. We ask only for basic sign-in
permissions (openid, email, profile). We cannot see your mailbox, files, contacts,
calendar or anything else in your Google or Microsoft account.</p>

<h2 style="font-size:16px">How we use it</h2>
<p>Only to: check whether your organization has authorized your email address for the
service you are signing in to; keep you signed in; and keep a security record of
sign-in attempts. The service you connect to records which account used
it and when, to run the service, for security, and for billing your organization.</p>

<h2 style="font-size:16px">What we keep, and for how long</h2>
<p>Sign-in session records (email address, name, account identifier): until {session_days}
days after you last use the service, then deleted. A security log of sign-in attempts
(time, email address, sign-in method, result, IP address): {audit_days} days, then deleted.
A browser cookie used during sign-in expires within 10 minutes. Operational logs are
rotated automatically.</p>

<h2 style="font-size:16px">Sharing</h2>
<p>We do not sell your information and do not use it for advertising. We share it only
with the service you are signing in to, with the providers that host our
systems, and where the law requires it. Our use of information received from Google
APIs adheres to the Google API Services User Data Policy, including the Limited Use
requirements.</p>

<h2 style="font-size:16px">Your choices</h2>
<p>Your organization decides who has access; ask them, or us, to remove yours. You can
also remove this app from your Google account (myaccount.google.com/permissions) or your
Microsoft account at any time. To ask what we hold about you, or to have it deleted,
contact {f['CONTACT']}.</p>

<h2 style="font-size:16px">Security</h2>
<p>Sign-in tokens are signed, and are stored only as one-way hashes. Access to our
systems is limited to authorized staff of {f['ENTITY']}.</p>

<h2 style="font-size:16px">Changes</h2>
<p>If this policy changes we will update this page and its effective date.</p>
</div>""")


def error(message: str) -> str:
    return _page("Sign-in problem", (
        "<h1>Something went wrong signing you in</h1>"
        f"<p>{escape(message)}</p>"
        '<p class="small">Go back to Claude and click Connect again.</p>'))
