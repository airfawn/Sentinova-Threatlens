from __future__ import annotations

from typing import Any, Callable

from sentinova_threatlens.compliance import TRANSITIONS, validate_ioc_type, validate_tlp, validate_transition, stix_bundle
from sentinova_threatlens.db.compliance import ComplianceRepository
from sentinova_threatlens.services.webhooks import WebhookGuard
from sentinova_threatlens.services.correlation import EventCorrelator


def register_routes(app: Any, db: Any, actor_dependency: Callable[..., Any], publish: Callable[[dict[str, Any]], Any], feed_manager: Any = None) -> None:
    from fastapi import Depends, HTTPException, Request
    from fastapi.responses import JSONResponse

    repo = ComplianceRepository(db)
    webhook_guard = WebhookGuard(app.state.config.api.webhook_secret)
    correlator = EventCorrelator()

    def actor(request: Request, current: Any = Depends(actor_dependency)) -> Any:
        request.state.actor = current
        return current

    @app.post("/api/v1/auth/token")
    def token(payload: dict[str, Any], request: Request) -> dict[str, str]:
        from sentinova_threatlens.api.auth import issue_token, verify_password
        username, password = str(payload.get("username", "")), str(payload.get("password", ""))
        users = repo.user(username)
        if not users or not verify_password(password, users[0]["password_hash"]):
            repo.audit(username or "anonymous", "auth.failure", "user", username or None, "denied")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user = users[0]
        repo.mark_login(username)
        scopes = list(user.get("scopes") or [])
        return {"access_token": issue_token(username, user["role"], scopes, request.app.state.config.api.token_secret), "token_type": "bearer"}

    @app.post("/api/v1/users")
    def create_user(payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if current.role != "Admin":
            raise HTTPException(status_code=403, detail="User administration denied")
        from sentinova_threatlens.api.auth import hash_password
        return repo.create_user(str(payload["username"]), hash_password(str(payload["password"])), str(payload["role"]), list(payload.get("scopes", ["read"])))

    @app.get("/api/v1/feeds")
    def feeds(_actor: Any = Depends(actor)) -> dict[str, Any]:
        return {"items": repo.feeds()}

    @app.post("/api/v1/feeds")
    def save_feed(payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("feeds:write"):
            raise HTTPException(status_code=403, detail="Feed management denied")
        try:
            return repo.save_feed(payload, current.subject)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Feed persistence unavailable") from exc

    @app.post("/api/v1/feeds/{feed_id}/poll")
    async def poll_feed(feed_id: int, current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("feeds:write"):
            raise HTTPException(status_code=403, detail="Feed management denied")
        feed = repo.feed(feed_id)
        if not feed:
            raise HTTPException(status_code=404, detail="Feed not found")
        if feed_manager is not None:
            feed_manager.poll_now(feed_id)
        event = {"event": "feed.poll.requested", "feed_id": feed_id, "actor": current.subject}
        await publish(event)
        repo.audit(current.subject, "feed.poll", "feed", str(feed_id), "success")
        return event

    @app.get("/api/v1/search")
    def search(q: str, limit: int = 100, _actor: Any = Depends(actor)) -> dict[str, Any]:
        try:
            items = repo.search(q, limit)
            return {"items": items, "count": len(items)}
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Search unavailable") from exc

    @app.post("/api/v1/iocs")
    def create_ioc(payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("iocs:write"):
            raise HTTPException(status_code=403, detail="IOC write denied")
        try:
            validate_ioc_type(str(payload["ioc_type"]))
            validate_tlp(payload.get("tlp", "Clear"))
            db.upsert_batch([{
                "ioc_value": payload["ioc_value"], "ioc_type": payload["ioc_type"], "source": "manual",
                "threat_type": payload.get("threat_type", "unknown"), "confidence_score": int(payload.get("confidence_score", 0)),
                "tags": payload.get("tags", []), "first_seen": payload.get("first_seen"), "last_seen": payload.get("last_seen"),
                "metadata": {"tlp": payload.get("tlp", "Clear"), "attack_techniques": payload.get("attack_techniques", []), "analyst_notes": payload.get("analyst_notes", {})}, "raw_data": payload,
            }])
            repo.audit(current.subject, "ioc.created", "ioc", payload["ioc_value"], "success", after=payload)
            return {"status": "created", "ioc_value": payload["ioc_value"]}
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="IOC persistence unavailable") from exc

    @app.post("/api/v1/ioc-relationships")
    def relationship(payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("iocs:write"):
            raise HTTPException(status_code=403, detail="Relationship write denied")
        try:
            return repo.relationship(int(payload["source_ioc_id"]), int(payload["target_ioc_id"]), str(payload["relationship_type"]), payload)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Relationship persistence unavailable") from exc

    @app.post("/api/v1/events")
    async def event(payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("events:write"):
            raise HTTPException(status_code=403, detail="Event ingestion denied")
        try:
            result = repo.event(payload)
            matches = correlator.correlate(payload, db.records_with_scores())
            for match in matches:
                ioc = match.get("ioc") or {}
                alert = repo.create_alert(None, int(result["id"]), None, int(match.get("score", 0)), match)
                incident = repo.create_incident(f"Correlated event: {payload.get('event_type', 'security event')}", current.subject, int(match.get("score", 0)))
                repo.link_alert_to_incident(int(alert["id"]), int(incident["id"]))
            await publish({"event": "security.event", "data": result})
            return {"event": result, "matches": len(matches)}
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Event ingestion unavailable") from exc

    @app.get("/api/v1/incidents")
    def incidents(_actor: Any = Depends(actor)) -> dict[str, Any]:
        return {"items": repo.incidents()}

    @app.post("/api/v1/incidents")
    def create_incident(payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("incidents:write"):
            raise HTTPException(status_code=403, detail="Incident write denied")
        return repo.create_incident(str(payload["title"]), current.subject, int(payload.get("severity_score", 0)))

    @app.post("/api/v1/incidents/{incident_id}/transition")
    def transition(incident_id: int, payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("incidents:write"):
            raise HTTPException(status_code=403, detail="Incident write denied")
        incident = repo.incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        try:
            validate_transition(str(incident[0]["status"]), str(payload["status"]))
            return repo.transition(incident_id, payload["status"], current.subject, payload.get("assignee"), payload.get("reason", ""))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/incidents/{incident_id}/timeline")
    def timeline(incident_id: int, _actor: Any = Depends(actor)) -> dict[str, Any]:
        return {"items": repo._query("SELECT * FROM cti_iocs.incident_timeline WHERE incident_id=%s ORDER BY occurred_at, id", (incident_id,))}

    @app.get("/api/v1/alert-rules")
    def rules(_actor: Any = Depends(actor)) -> dict[str, Any]:
        return {"items": repo.alert_rules()}

    @app.post("/api/v1/alert-rules")
    def save_rule(payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("rules:write"):
            raise HTTPException(status_code=403, detail="Rule write denied")
        return repo.save_rule(payload, current.subject)

    @app.get("/api/v1/exports/iocs.stix.json")
    def export_stix(current: Any = Depends(actor)) -> JSONResponse:
        if not current.allows("exports:read"):
            raise HTTPException(status_code=403, detail="Export denied")
        records = [record for record in db.records_with_scores() if current.role in {"Admin", "Analyst", "Hunter"} or ((record.get("normalized_data", {}) or {}).get("metadata", {}) or {}).get("tlp", "Clear") in {"Clear", "Green"}]
        return JSONResponse(stix_bundle(records))

    @app.get("/api/v1/dashboards/{role}")
    def dashboard(role: str, current: Any = Depends(actor)) -> dict[str, Any]:
        rows = repo._query("SELECT layout FROM cti_iocs.dashboard_layouts WHERE owner=%s AND role=%s", (current.subject, role))
        if rows:
            return rows[0]
        return {"layout": {"widgets": ["risk_summary", "severity_trend", "source_breakdown", "alert_queue"]}}

    @app.put("/api/v1/dashboards/{role}")
    def save_dashboard(role: str, payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("dashboards:write"):
            raise HTTPException(status_code=403, detail="Dashboard write denied")
        rows = repo._query("""INSERT INTO cti_iocs.dashboard_layouts(owner,role,layout)
          VALUES (%s,%s,%s::jsonb) ON CONFLICT(owner,role) DO UPDATE SET layout=EXCLUDED.layout,updated_at=NOW()
          RETURNING *""", (current.subject, role, __import__("json").dumps(payload)), write=True)
        return rows[0]

    @app.post("/api/v1/reports")
    def report(payload: dict[str, Any], current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("reports:write"):
            raise HTTPException(status_code=403, detail="Report generation denied")
        rows = repo._query("INSERT INTO cti_iocs.reports(requested_by,parameters) VALUES (%s,%s::jsonb) RETURNING *", (current.subject, __import__("json").dumps(payload)), write=True)
        repo.audit(current.subject, "report.requested", "report", str(rows[0]["id"]), "success", after=payload)
        return rows[0]

    @app.post("/api/v1/reports/{report_id}/generate")
    def generate_report(report_id: int, current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("reports:write"):
            raise HTTPException(status_code=403, detail="Report generation denied")
        from sentinova_threatlens.services.reporting import ReportGenerator
        path = f"reports/threatlens-{report_id}.pdf"
        records = db.records_with_scores()
        artifact = ReportGenerator().generate(path, "Sentinova ThreatLens Report", {"records": len(records)}, records)
        repo._query("UPDATE cti_iocs.reports SET status='completed', artifact_path=%s, completed_at=NOW() WHERE id=%s", (str(artifact), report_id), write=True)
        return {"id": report_id, "status": "completed", "artifact_path": str(artifact)}

    @app.get("/api/v1/analytics/summary")
    def analytics(_actor: Any = Depends(actor)) -> dict[str, Any]:
        records = db.records_with_scores()
        categories: dict[str, int] = {}
        sources: dict[str, int] = {}
        scores = []
        for record in records:
            normalized = record.get("normalized_data", {}) or {}
            categories[normalized.get("threat_type", "unknown")] = categories.get(normalized.get("threat_type", "unknown"), 0) + 1
            sources[record.get("source_name", "unknown")] = sources.get(record.get("source_name", "unknown"), 0) + 1
            scores.append(int(record.get("severity_score", 0)))
        return {"total": len(records), "categories": categories, "sources": sources, "severity_distribution": {str(score // 10 * 10): scores.count(score // 10 * 10) for score in set(scores)}}

    @app.get("/api/v1/analytics/map")
    def map_data(_actor: Any = Depends(actor)) -> dict[str, Any]:
        points = []
        for record in db.records_with_scores():
            metadata = (record.get("normalized_data", {}) or {}).get("metadata", {}) or {}
            if metadata.get("latitude") is not None and metadata.get("longitude") is not None:
                points.append({"latitude": metadata["latitude"], "longitude": metadata["longitude"], "score": record.get("severity_score", 0), "ioc_value": record.get("ioc_value")})
        return {"points": points}

    @app.post("/api/v1/integrations/{kind}")
    async def integration(kind: str, request: Request, current: Any = Depends(actor)) -> dict[str, Any]:
        if not current.allows("integrations:write"):
            raise HTTPException(status_code=403, detail="Integration denied")
        body = await request.body()
        signature = request.headers.get("X-Signature", "")
        request_id = request.headers.get("X-Request-ID", "")
        timestamp = float(request.headers.get("X-Timestamp", "0"))
        if not request_id or not webhook_guard.accept(body, signature, request_id, timestamp):
            raise HTTPException(status_code=401, detail="Invalid or replayed webhook")
        payload = __import__("json").loads(body)
        result = repo.event({"event_type": f"integration.{kind}", "payload": payload, "source": kind, "external_id": payload.get("id")})
        repo.audit(current.subject, "integration.received", "integration", kind, "success", after=payload)
        await publish({"event": "integration.received", "kind": kind, "data": result})
        return {"accepted": True, "event": result}
