"""Minimal Nexum client for Python agents.

Signs a fresh proof of possession for every request and asks the gateway for
a decision. Depends only on `cryptography` and the standard library.

    from nexum_client import NexumClient
    nx = NexumClient("http://127.0.0.1:8088", ["root.jwt"], "procurement.key.json")
    d = nx.authorize("inventory.read", "supplier://abc/sku/123")
    if d.allowed: ...
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _read(path_or_token: str) -> str:
    p = Path(path_or_token)
    return p.read_text().strip() if p.exists() else path_or_token.strip()


@dataclass
class Decision:
    status: int
    outcome: str
    code: str | None
    message: str | None
    approval_id: str | None
    raw: dict

    @property
    def allowed(self) -> bool:
        return self.outcome == "ALLOW"


class NexumClient:
    def __init__(self, gateway: str, grants: list[str], key_file: str, audience: str | None = None):
        self.gateway = gateway.rstrip("/")
        self.chain = [_read(g) for g in grants]
        jwk = json.loads(Path(key_file).read_text())
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError("key file must be an Ed25519 private JWK")
        self.key = Ed25519PrivateKey.from_private_bytes(_unb64(jwk["d"]))
        leaf_claims = json.loads(_unb64(self.chain[-1].split(".")[1]))
        if audience is None:
            if len(leaf_claims["aud"]) != 1:
                raise ValueError("leaf grant has several audiences; pass audience=")
            audience = leaf_claims["aud"][0]
        self.audience = audience

    def _proof(self, body: bytes) -> str:
        header = {"alg": "EdDSA", "typ": "nexum-proof+jwt"}
        claims = {
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "aud": self.audience,
            "gh": _b64(hashlib.sha256(self.chain[-1].encode()).digest()),
            "bh": _b64(hashlib.sha256(body).digest()),
        }
        signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
        return f"{signing_input}.{_b64(self.key.sign(signing_input.encode()))}"

    def post(self, path: str, payload: dict, approval_id: str | None = None) -> tuple[int, dict]:
        """POST a JSON payload through the gateway with fresh credentials."""
        body = json.dumps(payload).encode()
        headers = {
            "content-type": "application/json",
            "nexum-grant": ",".join(self.chain),
            "nexum-proof": self._proof(body),
        }
        if approval_id:
            headers["nexum-approval"] = approval_id
        req = urllib.request.Request(self.gateway + path, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def authorize(self, action: str, resource: str, value: int | None = None,
                  approval_id: str | None = None) -> Decision:
        payload: dict = {"action": action, "resource": resource}
        if value is not None:
            payload["value"] = value
        status, resp = self.post("/v1/authorize", payload, approval_id)
        d = resp.get("decision", {})
        obligations = d.get("obligations") or [{}]
        return Decision(
            status=status,
            outcome=d.get("outcome", "DENY"),
            code=resp.get("code"),
            message=resp.get("message"),
            approval_id=obligations[0].get("approval_id"),
            raw=resp,
        )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Ask a Nexum gateway for a decision")
    ap.add_argument("--gateway", default="http://127.0.0.1:8080")
    ap.add_argument("--grant", action="append", required=True, help="grant file, root first")
    ap.add_argument("--key", required=True)
    ap.add_argument("--action", required=True)
    ap.add_argument("--resource", required=True)
    ap.add_argument("--value", type=int)
    a = ap.parse_args()
    d = NexumClient(a.gateway, a.grant, a.key).authorize(a.action, a.resource, a.value)
    print(d.outcome, d.code, d.message)
    raise SystemExit(0 if d.allowed else 2)
