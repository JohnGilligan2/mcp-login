"""The RS256 key that signs every token this service issues.

Generated on first start and kept on the volume (never in git, never in env),
so a redeploy does not invalidate every customer's session. The public half is
served at /jwks; the MCP servers verify tokens against it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class SigningKey:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            self._key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = self._key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
            # Write-then-rename so a crash mid-write cannot leave a half key.
            tmp = path.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
            os.replace(tmp, path)
        pub = self._key.public_key().public_numbers()
        self._jwk = {"kty": "RSA", "use": "sig", "alg": "RS256",
                     "n": _b64(pub.n), "e": _b64(pub.e)}
        # RFC 7638 thumbprint as the key id.
        canon = json.dumps({"e": self._jwk["e"], "kty": "RSA", "n": self._jwk["n"]},
                           separators=(",", ":"), sort_keys=True)
        self.kid = base64.urlsafe_b64encode(hashlib.sha256(canon.encode()).digest()).rstrip(b"=").decode()
        self._jwk["kid"] = self.kid

    def jwks(self) -> dict:
        return {"keys": [self._jwk]}

    def sign(self, claims: dict) -> str:
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid})
