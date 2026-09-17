from __future__ import annotations

import csv
import io
import logging
import time
from collections import defaultdict, deque
from typing import Any

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.api.auth import verify_token
from sentinova_threatlens.api.auth import hash_password
from sentinova_threatlens.services.feed_manager import FeedManager
from sentinova_threatlens.services.report_scheduler import ReportScheduler
from sentinova_threatlens.services.scheduler import ExpirationWorker
from sentinova_threatlens.db.compliance import ComplianceRepository
from sentinova_threatlens.services.cache import RedisCache
from sentinova_threatlens.services.enrichment_adapters import GeoASNEnricher, VirusTotalEnricher
from sentinova_threatlens.severity import is_expired

logger = logging.getLogger(__name__)
ROLES = {"Admin", "Analyst", "Hunter", "Exec"}


class _Hub:
    def __init__(self) -> None:
        self.clients: dict[Any, Any] = {}

    async def broadcast(self, payload: dict[str, Any]) -> None:
        stale = set()
        for client, actor in self.clients.items():
            try:
                changes = payload.get("changes", {}) if isinstance(payload, dict) else {}
                if actor.role == "Exec" and changes.get("tlp") in {"Amber", "Red"}:
                    continue
                await client.send_json(payload)
            except Exception:
                stale.add(client)
        for client in stale:
            self.clients.pop(client, None)


def create_app(config: AppConfig | None = None) -> Any:
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
        from fastapi.responses import StreamingResponse
    except ImportError as exc:
        raise RuntimeError("FastAPI is not installed; install requirements.txt to enable the API") from exc

    app_config = config or AppConfig()
    db = DatabaseEngine(app_config)
    cache = RedisCache(app_config.redis)
    hub = _Hub()
    app = FastAPI(title="Sentinova ThreatLens API", version="1.0")
    app.state.config = app_config
    feed_manager = FeedManager(app_config, db)
    compliance_repo = ComplianceRepository(db)
    report_scheduler = ReportScheduler(compliance_repo.pending_reports, db.records_with_scores, compliance_repo.complete_report)
    expiration_worker = ExpirationWorker(compliance_repo.expire_iocs)
    request_hits: dict[str, deque[float]] = defaultdict(deque)

    @app.middleware("http")
    async def rate_limit(request: Any, call_next: Any) -> Any:
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        hits = request_hits[client]
        while hits and now - hits[0] >= 60:
            hits.popleft()
        if len(hits) >= app_config.api.rate_limit_per_minute:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        hits.append(now)
        return await call_next(request)

    def authenticated_actor(authorization: str | None = Header(default=None)) -> Any:
        if not authorization:
            raise HTTPException(status_code=401, detail="Bearer token required")
        try:
            return verify_token(authorization, app_config.api.token_secret)
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(status_code=401, detail="Invalid bearer token") from exc

    def role(required: set[str]):
        def dependency(current: Any = Depends(authenticated_actor)) -> Any:
            if current.role not in ROLES or not (required & {current.role} or current.role == "Admin"):
                raise HTTPException(status_code=403, detail="Insufficient role")
            return current
        return dependency

    def permitted(record: dict[str, Any], current: Any) -> bool:
        tlp = ((record.get("normalized_data", {}) or {}).get("metadata", {}) or {}).get("tlp", "Clear")
        return current.role == "Admin" or tlp in {"Clear", "Green"} or current.role in {"Analyst", "Hunter"}

    def records() -> list[dict[str, Any]]:
        try:
            db.connect()
            return db.records_with_scores()
        except Exception as exc:
            logger.exception("IOC query failed")
            raise HTTPException(status_code=503, detail="Database unavailable") from exc

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/iocs")
    def list_iocs(
        q: str | None = None,
        ioc_type: str | None = None,
        tlp: str | None = None,
        min_score: int = 0,
        _role: str = Depends(role({"Admin", "Analyst", "Hunter", "Exec"})),
    ) -> dict[str, Any]:
        filtered = []
        for record in records():
            if not permitted(record, _role):
                continue
            normalized = record.get("normalized_data", {}) or {}
            metadata = normalized.get("metadata", {}) or {}
            score = int(record.get("severity_score", 0))
            if is_expired(record):
                continue
            haystack = f"{record.get('ioc_value', '')} {record.get('source_name', '')}".lower()
            if q and q.lower() not in haystack:
                continue
            if ioc_type and normalized.get("ioc_type") != ioc_type:
                continue
            if tlp and metadata.get("tlp", "Clear") != tlp:
                continue
            if score >= min_score:
                filtered.append(record)
        return {"items": filtered, "count": len(filtered)}

    @app.get("/api/v1/iocs/{value}")
    def get_ioc(value: str, _role: str = Depends(role({"Admin", "Analyst", "Hunter", "Exec"}))) -> dict[str, Any]:
        found = next((item for item in records() if item.get("ioc_value") == value and permitted(item, _role)), None)
        if found is None:
            raise HTTPException(status_code=404, detail="IOC not found")
        return found

    @app.get("/api/v1/sources/status")
    def source_status(_role: str = Depends(role({"Admin", "Analyst", "Hunter", "Exec"}))) -> dict[str, Any]:
        try:
            db.connect()
            return {"items": db.source_status()}
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Database unavailable") from exc

    @app.post("/api/v1/iocs/{value}/metadata")
    async def update_metadata(
        value: str,
        payload: dict[str, Any],
        _role: str = Depends(role({"Admin", "Analyst", "Hunter"})),
    ) -> dict[str, Any]:
        allowed = {"tags", "tlp", "ttl_seconds", "expires_at", "status"}
        update = {key: payload[key] for key in allowed if key in payload}
        if "ttl_seconds" in update:
            try:
                from datetime import datetime, timedelta, timezone
                update["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=int(update["ttl_seconds"]))).isoformat()
            except (TypeError, ValueError):
                raise HTTPException(status_code=422, detail="Invalid TTL value")
        if "tlp" in update and update["tlp"] not in {"Clear", "Green", "Amber", "Red"}:
            raise HTTPException(status_code=422, detail="Invalid TLP value")
        try:
            db.connect()
            if not db.update_ioc_metadata(value, {"metadata": update}):
                raise HTTPException(status_code=404, detail="IOC not found")
            event = {"event": "ioc.updated", "ioc_value": value, "changes": update}
            cache.publish("threatlens.ioc_updates", event)
            await hub.broadcast(event)
            return {"status": "updated", "ioc_value": value, "changes": update}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Database unavailable") from exc

    @app.post("/api/v1/iocs/{value}/enrich")
    async def enrich(value: str, _role: str = Depends(role({"Admin", "Analyst", "Hunter"}))) -> dict[str, Any]:
        result = {"virustotal": VirusTotalEnricher(app_config.sources).lookup(value), "geo": GeoASNEnricher().lookup(value)}
        try:
            db.connect()
            db.update_ioc_metadata(value, {"enrichment": result})
            await hub.broadcast({"event": "ioc.enriched", "ioc_value": value, "enrichment": result})
            return result
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Database unavailable") from exc

    @app.get("/api/v1/exports/iocs.csv")
    def export_csv(_role: str = Depends(role({"Admin", "Analyst", "Hunter", "Exec"}))) -> Any:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["ioc_value", "ioc_type", "source_name", "severity_score"])
        writer.writeheader()
        writer.writerows({key: item.get(key) for key in writer.fieldnames} for item in records() if permitted(item, _role))
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=iocs.csv"})

    @app.websocket("/api/v1/alerts.stream")
    async def alerts_stream(websocket: WebSocket) -> None:
        token = websocket.query_params.get("access_token", "")
        try:
            verify_token(token, app_config.api.token_secret)
        except (ValueError, KeyError, TypeError):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        actor = verify_token(token, app_config.api.token_secret)
        hub.clients[websocket] = actor
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            hub.clients.pop(websocket, None)
        except Exception:
            hub.clients.pop(websocket, None)

    @app.on_event("shutdown")
    def shutdown() -> None:
        feed_manager.stop()
        report_scheduler.stop()
        expiration_worker.stop()
        try:
            db.close()
        except Exception:
            logger.debug("Database close failed", exc_info=True)

    from sentinova_threatlens.api.compliance_routes import register_routes
    register_routes(app, db, authenticated_actor, hub.broadcast, feed_manager)

    def startup() -> None:
        try:
            db.connect()
            db.init_schema()
            if app_config.api.bootstrap_admin and app_config.api.bootstrap_password and not compliance_repo.user(app_config.api.bootstrap_admin):
                compliance_repo.create_user(app_config.api.bootstrap_admin, hash_password(app_config.api.bootstrap_password), "Admin", ["*"])
            feed_manager.start()
            report_scheduler.start()
            expiration_worker.start()
        except Exception:
            logger.exception("API startup persistence initialization failed")

    app.router.on_startup.append(startup)

    return app
