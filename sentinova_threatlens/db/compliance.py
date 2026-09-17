from __future__ import annotations

import json
from typing import Any

from sentinova_threatlens.db.engine import DatabaseEngine


class ComplianceRepository:
    def __init__(self, db: DatabaseEngine) -> None:
        self.db = db

    def _query(self, sql: str, params: tuple[Any, ...] = (), write: bool = False) -> list[dict[str, Any]]:
        conn = self.db._pool.getconn()  # noqa: SLF001 - repository shares the existing pool
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = []
                if cur.description:
                    columns = [column.name for column in cur.description]
                    rows = [dict(zip(columns, row)) for row in cur.fetchall()]
            if write:
                conn.commit()
            return rows
        except Exception:
            conn.rollback()
            raise
        finally:
            self.db._pool.putconn(conn)  # noqa: SLF001

    def audit(self, actor: str, action: str, target_type: str, target_id: str | None, result: str, request_id: str | None = None, before: Any = None, after: Any = None) -> None:
        self._query(
            """INSERT INTO cti_iocs.audit_log
               (actor, action, target_type, target_id, result, request_id, before_data, after_data)
               VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)""",
            (actor, action, target_type, target_id, result, request_id, json.dumps(before) if before is not None else None, json.dumps(after) if after is not None else None),
            write=True,
        )

    def feeds(self) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cti_iocs.feed_registry ORDER BY name")

    def feed(self, feed_id: int) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cti_iocs.feed_registry WHERE id=%s", (feed_id,))

    def save_feed(self, payload: dict[str, Any], actor: str) -> dict[str, Any]:
        rows = self._query(
            """INSERT INTO cti_iocs.feed_registry
               (name, source_type, endpoint, credential_ref, enabled, poll_interval_seconds, settings)
               VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)
               ON CONFLICT (name) DO UPDATE SET source_type=EXCLUDED.source_type,
                 endpoint=EXCLUDED.endpoint, credential_ref=EXCLUDED.credential_ref,
                 enabled=EXCLUDED.enabled, poll_interval_seconds=EXCLUDED.poll_interval_seconds,
                 settings=EXCLUDED.settings RETURNING *""",
            (payload["name"], payload.get("source_type", "json"), payload["endpoint"], payload.get("credential_ref"), payload.get("enabled", True), int(payload.get("poll_interval_seconds", 3600)), json.dumps(payload.get("settings", {}))),
            write=True,
        )
        self.audit(actor, "feed.changed", "feed", str(rows[0]["id"]), "success", after=payload)
        return rows[0]

    def relationship(self, source: int, target: int, relation: str, metadata: dict[str, Any]) -> dict[str, Any]:
        rows = self._query("""INSERT INTO cti_iocs.ioc_relationships
          (source_ioc_id,target_ioc_id,relationship_type,confidence_score,metadata)
          VALUES (%s,%s,%s,%s,%s::jsonb) RETURNING *""", (source, target, relation, metadata.get("confidence_score"), json.dumps(metadata)), write=True)
        return rows[0]

    def event(self, payload: dict[str, Any]) -> dict[str, Any]:
        rows = self._query("""INSERT INTO cti_iocs.security_events
          (external_id,event_type,occurred_at,payload,source,correlation_key)
          VALUES (%s,%s,COALESCE(%s,NOW()),%s::jsonb,%s,%s) RETURNING *""", (payload.get("external_id"), payload["event_type"], payload.get("occurred_at"), json.dumps(payload), payload.get("source", "api"), payload.get("correlation_key")), write=True)
        return rows[0]

    def create_alert(self, ioc_id: int | None, event_id: int | None, rule_id: int | None, score: int, payload: dict[str, Any]) -> dict[str, Any]:
        rows = self._query("""INSERT INTO cti_iocs.alerts(ioc_id,event_id,rule_id,severity_score,payload)
          VALUES (%s,%s,%s,%s,%s::jsonb) RETURNING *""", (ioc_id, event_id, rule_id, score, json.dumps(payload)), write=True)
        return rows[0]

    def link_alert_to_incident(self, alert_id: int, incident_id: int) -> None:
        self._query("UPDATE cti_iocs.incidents SET updated_at=NOW() WHERE id=%s", (incident_id,), write=True)
        self.timeline(incident_id, "system", "alert.linked", {"alert_id": alert_id})

    def expire_iocs(self) -> int:
        rows = self._query("""UPDATE cti_iocs.iocs SET normalized_data=jsonb_set(normalized_data,'{metadata,expired}','true'::jsonb), updated_at=NOW()
          WHERE COALESCE(normalized_data->'metadata'->>'expires_at','') <> ''
          AND (normalized_data->'metadata'->>'expires_at')::timestamptz <= NOW()
          AND COALESCE((normalized_data->'metadata'->>'expired')::boolean,FALSE)=FALSE
          RETURNING id""", write=True)
        return len(rows)

    def pending_reports(self) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cti_iocs.reports WHERE status='queued' ORDER BY created_at LIMIT 10")

    def complete_report(self, report_id: int, artifact: str) -> None:
        self._query("UPDATE cti_iocs.reports SET status='completed',artifact_path=%s,completed_at=NOW() WHERE id=%s", (artifact, report_id), write=True)

    def incidents(self) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cti_iocs.incidents ORDER BY updated_at DESC")

    def incident(self, incident_id: int) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cti_iocs.incidents WHERE id=%s", (incident_id,))

    def create_incident(self, title: str, actor: str, score: int = 0) -> dict[str, Any]:
        rows = self._query("INSERT INTO cti_iocs.incidents(title, severity_score, assignee) VALUES (%s,%s,%s) RETURNING *", (title, score, actor), write=True)
        self.timeline(int(rows[0]["id"]), actor, "created", {"title": title})
        return rows[0]

    def timeline(self, incident_id: int, actor: str, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        rows = self._query("INSERT INTO cti_iocs.incident_timeline(incident_id,actor,action,payload) VALUES (%s,%s,%s,%s::jsonb) RETURNING *", (incident_id, actor, action, json.dumps(payload)), write=True)
        return rows[0]

    def transition(self, incident_id: int, status: str, actor: str, assignee: str | None, reason: str) -> dict[str, Any]:
        rows = self._query("UPDATE cti_iocs.incidents SET status=%s, assignee=COALESCE(%s,assignee), updated_at=NOW() WHERE id=%s RETURNING *", (status, assignee, incident_id), write=True)
        if not rows:
            raise LookupError("Incident not found")
        self.timeline(incident_id, actor, "status.changed", {"status": status, "reason": reason, "assignee": assignee})
        return rows[0]

    def alert_rules(self) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cti_iocs.alert_rules ORDER BY name")

    def save_rule(self, payload: dict[str, Any], actor: str) -> dict[str, Any]:
        rows = self._query("INSERT INTO cti_iocs.alert_rules(name,conditions,routing,created_by) VALUES (%s,%s::jsonb,%s::jsonb,%s) ON CONFLICT(name) DO UPDATE SET version=cti_iocs.alert_rules.version+1,conditions=EXCLUDED.conditions,routing=EXCLUDED.routing,updated_at=NOW() RETURNING *", (payload["name"], json.dumps(payload.get("conditions", {})), json.dumps(payload.get("routing", {})), actor), write=True)
        self.audit(actor, "rule.changed", "alert_rule", str(rows[0]["id"]), "success", after=payload)
        return rows[0]

    def search(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cti_iocs.iocs WHERE to_tsvector('simple', ioc_value || ' ' || source_name) @@ plainto_tsquery('simple', %s) ORDER BY updated_at DESC LIMIT %s", (query, min(max(limit, 1), 500)))

    def user(self, username: str) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cti_iocs.users WHERE username=%s AND enabled=TRUE", (username,))

    def create_user(self, username: str, password_hash: str, role: str, scopes: list[str]) -> dict[str, Any]:
        rows = self._query("INSERT INTO cti_iocs.users(username,password_hash,role,scopes) VALUES (%s,%s,%s,%s::jsonb) RETURNING id,username,role,scopes", (username, password_hash, role, json.dumps(scopes)), write=True)
        return rows[0]

    def mark_login(self, username: str) -> None:
        self._query("UPDATE cti_iocs.users SET last_login=NOW() WHERE username=%s", (username,), write=True)
