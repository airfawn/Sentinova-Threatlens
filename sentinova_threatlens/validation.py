from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

CANONICAL_IOC_TYPES = {"IP", "DOMAIN", "URL", "HASH_MD5", "HASH_SHA256", "CVE"}
KNOWN_SOURCES = {"MalwareBazaar", "AbuseIPDB", "ThreatFox", "GreyNoise", "CISA_KEV"}
KNOWN_THREAT_TYPES = {"malware", "scanner", "C2", "exploit", "phishing", "unknown"}
REQUIRED_FIELDS = {
    "ioc_value", "ioc_type", "source", "threat_type",
    "confidence_score", "tags", "first_seen", "last_seen",
    "metadata", "raw_data",
}

_MAX_IOC_LEN = 4000
_MAX_SOURCE_LEN = 64
_MAX_TYPE_LEN = 20


@dataclass
class ValidationResult:
    valid: list[dict[str, Any]] = field(default_factory=list)
    skipped: int = 0
    reasons: dict[str, int] = field(default_factory=dict)
    checks: list[tuple[str, bool, str]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.skipped == 0

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, ok, detail))


_TYPED_VALUE_RE = {
    "IP": re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    ),
    "DOMAIN": re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}$"
    ),
    "URL": re.compile(r"^https?://", re.IGNORECASE),
    "HASH_MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "HASH_SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "CVE": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
}

_RULE_LABELS = {
    "required_fields": "Required fields",
    "json_validation": "JSON validation",
    "indicator_structure": "Indicator structure",
    "duplicate_detection": "Duplicate detection",
    "severity_validation": "Severity validation",
    "source_validation": "Source validation",
    "database_compatibility": "Database compatibility",
}


class ImportRuleValidator:
    """Validates normalized records against the application import rules."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def validate(self, records: list[dict[str, Any]]) -> ValidationResult:
        result = ValidationResult()
        self._seen.clear()

        missing_field = 0
        bad_json = 0
        bad_structure = 0
        duplicates = 0
        bad_severity = 0
        bad_source = 0
        bad_db = 0

        for rec in records:
            if not self._check_required(rec):
                missing_field += 1
                continue

            if not self._check_json(rec):
                bad_json += 1
                continue

            if not self._check_structure(rec):
                bad_structure += 1
                continue

            if rec["ioc_value"] in self._seen:
                duplicates += 1
                continue
            self._seen.add(rec["ioc_value"])

            if not self._check_severity(rec):
                bad_severity += 1
                continue

            if not self._check_source(rec):
                bad_source += 1
                continue

            if not self._check_database_compat(rec):
                bad_db += 1
                continue

            result.valid.append(rec)

        def _finalize(name: str, count: int, detail: str) -> None:
            ok = count == 0
            result.check(name, ok, detail)
            if not ok:
                result.reasons[detail or name] = result.reasons.get(detail or name, 0) + count
            result.skipped += count

        checks = {
            "required_fields": (missing_field, "Missing required field"),
            "json_validation": (bad_json, "Invalid JSON structure"),
            "indicator_structure": (bad_structure, "Invalid indicator structure"),
            "duplicate_detection": (duplicates, "Duplicate indicator value"),
            "severity_validation": (bad_severity, "Severity out of range"),
            "source_validation": (bad_source, "Unknown source name"),
            "database_compatibility": (bad_db, "Incompatible with database schema"),
        }
        for name, (count, detail) in checks.items():
            _finalize(_RULE_LABELS.get(name, name), count, detail)

        return result

    @staticmethod
    def _check_required(rec: dict[str, Any]) -> bool:
        return all(k in rec for k in REQUIRED_FIELDS)

    @staticmethod
    def _check_json(rec: dict[str, Any]) -> bool:
        if rec["ioc_type"] not in CANONICAL_IOC_TYPES:
            return False
        try:
            json.dumps(rec)
            json.dumps(rec.get("metadata", {}))
            json.dumps(rec.get("raw_data", {}))
            return True
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _check_structure(rec: dict[str, Any]) -> bool:
        ioc_type = rec["ioc_type"]
        value = rec["ioc_value"]
        if not isinstance(value, str) or not value.strip():
            return False
        regex = _TYPED_VALUE_RE.get(ioc_type)
        if regex is None:
            return False
        return bool(regex.match(value.strip()))

    @staticmethod
    def _check_severity(rec: dict[str, Any]) -> bool:
        score = rec["confidence_score"]
        if not isinstance(score, int):
            return False
        return 0 <= score <= 100

    @staticmethod
    def _check_source(rec: dict[str, Any]) -> bool:
        return rec["source"] in KNOWN_SOURCES

    @staticmethod
    def _check_database_compat(rec: dict[str, Any]) -> bool:
        return (
            len(rec["ioc_value"]) <= _MAX_IOC_LEN
            and len(rec["source"]) <= _MAX_SOURCE_LEN
            and len(rec["ioc_type"]) <= _MAX_TYPE_LEN
        )