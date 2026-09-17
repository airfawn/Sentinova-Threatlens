from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

THREAT_WEIGHTS = {
    "exploit": 100,
    "C2": 92,
    "malware": 86,
    "phishing": 74,
    "scanner": 48,
    "unknown": 30,
}


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _recency_score(value: Any, half_life_days: float = 30.0) -> float:
    if not value:
        return 50.0
    try:
        timestamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        age_days = max(0.0, (datetime.now(timezone.utc) - timestamp).total_seconds() / 86400)
        return max(0.0, min(100.0, 100.0 * math.exp(-math.log(2) * age_days / half_life_days)))
    except (TypeError, ValueError, OverflowError):
        return 50.0


def calculate_severity(record: dict[str, Any]) -> int:
    """Return a deterministic 0-100 score using the shared weighting model."""
    normalized = record.get("normalized_data", record) or {}
    metadata = normalized.get("metadata", {}) or {}
    cvss = _number(metadata.get("cvss_score"), -1.0)
    cvss_score = max(0.0, min(100.0, cvss * 10.0)) if cvss >= 0 else 50.0
    confidence = max(0.0, min(100.0, _number(normalized.get("confidence_score"))))
    recency = _recency_score(normalized.get("last_seen") or record.get("last_seen"))
    threat = THREAT_WEIGHTS.get(str(normalized.get("threat_type", "unknown")), 30)
    return max(0, min(100, round(cvss_score * 0.40 + confidence * 0.30 + recency * 0.15 + threat * 0.15)))


def is_expired(record: dict[str, Any]) -> bool:
    normalized = record.get("normalized_data", record) or {}
    metadata = normalized.get("metadata", {}) or {}
    expires_at = metadata.get("expires_at")
    if expires_at:
        try:
            timestamp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            return timestamp <= datetime.now(timezone.utc)
        except (TypeError, ValueError):
            return False
    ttl = metadata.get("ttl_seconds")
    last_seen = normalized.get("last_seen") or record.get("last_seen")
    if ttl is None or not last_seen:
        return False
    try:
        timestamp = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp + timedelta(seconds=float(ttl)) <= datetime.now(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return False