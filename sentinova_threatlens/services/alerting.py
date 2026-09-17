from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AlertMatch:
    rule_id: int
    route: list[str]
    reason: str


class AlertRuleEngine:
    """Pure, deterministic rule evaluator for IOC and event alert conditions."""

    def evaluate(self, record: dict[str, Any], rules: list[dict[str, Any]]) -> list[AlertMatch]:
        normalized = record.get("normalized_data", record) or {}
        metadata = normalized.get("metadata", {}) or {}
        score = int(record.get("severity_score", 0))
        matches: list[AlertMatch] = []
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            conditions = rule.get("conditions", {}) or {}
            if score < int(conditions.get("min_score", 0)):
                continue
            if conditions.get("ioc_type") and normalized.get("ioc_type") not in conditions["ioc_type"]:
                continue
            if conditions.get("source") and record.get("source_name") not in conditions["source"]:
                continue
            if conditions.get("tlp") and metadata.get("tlp", "Clear") not in conditions["tlp"]:
                continue
            if conditions.get("category") and normalized.get("threat_type") not in conditions["category"]:
                continue
            matches.append(AlertMatch(int(rule["id"]), list((rule.get("routing") or {}).get("users", [])), f"rule:{rule.get('name', rule['id'])}"))
        return matches
