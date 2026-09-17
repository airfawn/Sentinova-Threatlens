from __future__ import annotations

import base64
import hashlib
import hmac
import json
import hashlib
import secrets
from typing import Any

from sentinova_threatlens.compliance import AuthenticatedActor, actor_from_claims


def issue_token(subject: str, role: str, scopes: list[str], secret: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps({"sub": subject, "role": role, "scopes": scopes}).encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def verify_token(token: str, secret: str) -> AuthenticatedActor:
    body, signature = token.removeprefix("Bearer ").split(".", 1)
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid token signature")
    padded = body + "=" * (-len(body) % 4)
    return actor_from_claims(json.loads(base64.urlsafe_b64decode(padded)))


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240_000).hex()
    return f"pbkdf2_sha256$240000${salt}${digest}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False