from __future__ import annotations

from typing import Any


class EventCorrelator:
    """Correlate normalized security events with IOC records and relationships."""

    def correlate(self, event: dict[str, Any], records: list[dict[str, Any]], relationships: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        blob = str(event).lower()
        matches = []
        for record in records:
            value = str(record.get("ioc_value", ""))
            if value and value.lower() in blob:
                matches.append({"ioc": record, "reason": "direct-value", "score": record.get("severity_score", 0)})
        for relationship in relationships or []:
            if str(relationship.get("source_ioc_id")) in blob or str(relationship.get("target_ioc_id")) in blob:
                matches.append({"relationship": relationship, "reason": relationship.get("relationship_type", "related")})
        return matches
