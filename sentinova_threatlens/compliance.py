from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

IOC_TYPES = {"IP", "DOMAIN", "URL", "HASH_MD5", "HASH_SHA1", "HASH_SHA256", "EMAIL", "CVE"}
TLP_VALUES = {"Clear", "Green", "Amber", "Red"}
ROLES = {"Admin", "Analyst", "Hunter", "Exec"}
INCIDENT_STATES = ("new", "acknowledged", "in-progress", "resolved", "closed")
TRANSITIONS = {
    "new": {"acknowledged"},
    "acknowledged": {"in-progress"},
    "in-progress": {"resolved"},
    "resolved": {"closed"},
    "closed": set(),
}


def validate_ioc_type(ioc_type: str) -> str:
    value = ioc_type.upper()
    if value not in IOC_TYPES:
        raise ValueError(f"Unsupported IOC type: {ioc_type}")
    return value


def validate_tlp(tlp: str) -> str:
    if tlp not in TLP_VALUES:
        raise ValueError(f"Unsupported TLP marking: {tlp}")
    return tlp


def validate_transition(current: str, target: str) -> None:
    if target not in INCIDENT_STATES or target not in TRANSITIONS.get(current, set()):
        raise ValueError(f"Invalid lifecycle transition: {current} -> {target}")


def stable_stix_id(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"indicator--{digest[:8]}-{digest[8:12]}-5{digest[13:16]}-{digest[16:20]}-{digest[20:32]}"


def stix_bundle(records: Iterable[dict[str, Any]], tlp: str = "Clear") -> dict[str, Any]:
    validate_tlp(tlp)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    objects: list[dict[str, Any]] = []
    for record in records:
        normalized = record.get("normalized_data", record) or {}
        value = str(record.get("ioc_value", normalized.get("ioc_value", "")))
        ioc_type = normalized.get("ioc_type", "unknown")
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": stable_stix_id(value),
            "created": now,
            "modified": now,
            "pattern_type": "stix",
            "pattern": f"[x-threatlens:{ioc_type.lower()} = '{escaped}']",
            "valid_from": now,
            "labels": list(normalized.get("tags", [])),
            "confidence": int(normalized.get("confidence_score", 0)),
            "object_marking_refs": [f"marking-definition--{tlp.lower()}"],
        })
    return {"type": "bundle", "id": f"bundle--{secrets.token_hex(16)}", "objects": objects}


def verify_signature(body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.removeprefix("sha256="))


@dataclass(frozen=True)
class AuthenticatedActor:
    subject: str
    role: str
    scopes: frozenset[str]

    def allows(self, scope: str) -> bool:
        return self.role == "Admin" or scope in self.scopes


def actor_from_claims(claims: dict[str, Any]) -> AuthenticatedActor:
    subject = str(claims.get("sub", ""))
    role = str(claims.get("role", ""))
    if not subject or role not in ROLES:
        raise ValueError("Invalid identity claims")
    return AuthenticatedActor(subject, role, frozenset(str(item) for item in claims.get("scopes", [])))
