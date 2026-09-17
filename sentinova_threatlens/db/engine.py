from __future__ import annotations

import json
import logging
from typing import Any

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.severity import calculate_severity, is_expired

logger = logging.getLogger(__name__)

UPSERT_SQL = """
INSERT INTO cti_iocs.iocs (
    ioc_value, ioc_type, source_name, raw_data,
    normalized_data, first_seen, last_seen, last_enriched, updated_at
) VALUES (
    %(ioc_value)s, %(ioc_type)s, %(source_name)s, %(raw_data)s,
    %(normalized_data)s, %(first_seen)s, %(last_seen)s, NOW(), NOW()
)
ON CONFLICT (ioc_value) DO UPDATE SET
    source_name   = EXCLUDED.source_name,
    raw_data      = EXCLUDED.raw_data,
    last_seen     = GREATEST(cti_iocs.iocs.last_seen, EXCLUDED.last_seen),
    last_enriched = NOW(),
    updated_at    = NOW(),
    normalized_data = cti_iocs.iocs.normalized_data || EXCLUDED.normalized_data;
"""


class DatabaseEngine:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._pool: ThreadedConnectionPool | None = None

    def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = ThreadedConnectionPool(
            self._config.db.pool_min,
            self._config.db.pool_max,
            self._config.db.dsn,
        )
        logger.info("Connection pool established (min=%d, max=%d)",
                     self._config.db.pool_min, self._config.db.pool_max)

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
            logger.info("Connection pool closed")

    def init_schema(self) -> None:
        ddl_path = self._config.schema_ddl
        if not ddl_path.exists():
            logger.warning("Schema DDL not found at %s — skipping", ddl_path)
            return
        ddl = ddl_path.read_text()
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(ddl)
            conn.commit()
            logger.info("Schema initialized from %s", ddl_path)
        finally:
            self._pool.putconn(conn)
        migration_dir = ddl_path.parent / "migrations"
        for migration in sorted(migration_dir.glob("*.sql")):
            conn = self._pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute(migration.read_text())
                conn.commit()
                logger.info("Applied migration %s", migration.name)
            finally:
                self._pool.putconn(conn)

    def upsert_batch(self, records: list[dict[str, Any]]) -> int:
        if not records:
            return 0

        serialised = []
        for rec in records:
            serialised.append({
                "ioc_value": rec["ioc_value"],
                "ioc_type": rec["ioc_type"],
                "source_name": rec["source"],
                "raw_data": json.dumps(rec.get("raw_data", {}), default=str),
                "normalized_data": json.dumps(rec, default=str),
                "first_seen": rec.get("first_seen"),
                "last_seen": rec.get("last_seen"),
            })

        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                psycopg2.extras.execute_batch(
                    cur, UPSERT_SQL, serialised, page_size=self._config.sources.batch_size
                )
            conn.commit()
            logger.info("Upserted %d records", len(serialised))
            self._store_provenance(serialised)
            return len(serialised)
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def _store_provenance(self, records: list[dict[str, Any]]) -> None:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                for record in records:
                    cur.execute(
                        """INSERT INTO cti_iocs.ioc_provenance
                           (ioc_id, source_name, first_seen, last_seen, raw_data)
                           SELECT id, %s, first_seen, last_seen, raw_data
                           FROM cti_iocs.iocs WHERE ioc_value = %s
                           ON CONFLICT (ioc_id, source_name) DO UPDATE SET
                             last_seen = EXCLUDED.last_seen,
                             raw_data = EXCLUDED.raw_data""",
                        (record["source_name"], record["ioc_value"]),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            logger.warning("Provenance persistence unavailable", exc_info=True)
        finally:
            self._pool.putconn(conn)

    def count_iocs(self) -> int:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM cti_iocs.iocs")
                return cur.fetchone()[0]
        finally:
            self._pool.putconn(conn)

    def filter_existing(self, values: list[str]) -> set[str]:
        """Return the subset of ioc_values already present in the database."""
        if not values:
            return set()
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT ioc_value FROM cti_iocs.iocs WHERE ioc_value = ANY(%s)",
                    (list(values),),
                )
                return {row[0] for row in cur.fetchall()}
        finally:
            self._pool.putconn(conn)

    def list_cves(self) -> list[str]:
        """Return all CVE ioc_values currently stored (for CVSS backfill)."""
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT DISTINCT ioc_value FROM cti_iocs.iocs "
                    "WHERE ioc_type = 'CVE'"
                )
                return [row[0] for row in cur.fetchall()]
        finally:
            self._pool.putconn(conn)

    def list_values(self, ioc_type: str | None = None) -> set[str]:
        """Return stored ioc_values, optionally filtered by ioc_type."""
        sql = "SELECT ioc_value FROM cti_iocs.iocs"
        params: tuple[Any, ...] = ()
        if ioc_type:
            sql += " WHERE ioc_type = %s"
            params = (ioc_type,)
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return {row[0] for row in cur.fetchall()}
        finally:
            self._pool.putconn(conn)

    def list_pending_cvss(self, limit: int | None = None) -> list[str]:
        """Return stored CVEs that have no CVSS lookup cached yet."""
        sql = (
            "SELECT ioc_value FROM cti_iocs.iocs i "
            "WHERE ioc_type = 'CVE' "
            "AND NOT EXISTS ("
            "    SELECT 1 FROM cti_iocs.cvss_cache c "
            "    WHERE c.cve_id = i.ioc_value"
            ") ORDER BY ioc_value"
        )
        params: tuple[Any, ...] = ()
        if limit is not None:
            sql += " LIMIT %s"
            params = (limit,)
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return [row[0] for row in cur.fetchall()]
        finally:
            self._pool.putconn(conn)

    def get_cached_cvss(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Return cached CVSS metadata for the requested CVE IDs."""
        if not cve_ids:
            return {}
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT cve_id, cvss_score, cvss_severity, cvss_vector, source
                    FROM cti_iocs.cvss_cache
                    WHERE cve_id = ANY(%s)
                    """,
                    (list(cve_ids),),
                )
                return {
                    row[0]: {
                        "cvss_score": float(row[1]) if row[1] is not None else None,
                        "cvss_severity": row[2],
                        "cvss_vector": row[3],
                        "cvss_source": row[4],
                    }
                    for row in cur.fetchall()
                }
        finally:
            self._pool.putconn(conn)

    def store_cvss_cache(self, rows: list[dict[str, Any]]) -> None:
        """Upsert CVSS lookup results for later reuse."""
        if not rows:
            return
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                psycopg2.extras.execute_batch(
                    cur,
                    """
                    INSERT INTO cti_iocs.cvss_cache
                        (cve_id, cvss_score, cvss_severity, cvss_vector, source)
                    VALUES (%(cve_id)s, %(cvss_score)s, %(cvss_severity)s,
                            %(cvss_vector)s, %(cvss_source)s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        cvss_score    = EXCLUDED.cvss_score,
                        cvss_severity = EXCLUDED.cvss_severity,
                        cvss_vector   = EXCLUDED.cvss_vector,
                        source        = EXCLUDED.source,
                        fetched_at    = NOW()
                    """,
                    rows,
                    page_size=self._config.sources.batch_size,
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def merge_metadata(self, updates: list[tuple[str, dict[str, Any]]]) -> int:
        """Merge metadata into normalized_data of existing rows (used for CVSS)."""
        if not updates:
            return 0
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                for ioc_value, meta in updates:
                    cur.execute(
                        """
                        UPDATE cti_iocs.iocs
                        SET normalized_data = normalized_data || %s::jsonb,
                            last_enriched   = NOW(),
                            updated_at      = NOW()
                        WHERE ioc_value = %s
                        """,
                        (json.dumps(meta, default=str), ioc_value),
                    )
            conn.commit()
            return len(updates)
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def fetch_all(self, limit: int = 20000) -> list[dict[str, Any]]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT ioc_value, ioc_type, source_name,
                           raw_data, normalized_data,
                           first_seen, last_seen, last_enriched
                    FROM cti_iocs.iocs
                    ORDER BY id DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                cols = [d.name for d in cur.description]
                rows = []
                for row in cur.fetchall():
                    rec = dict(zip(cols, row))
                    for key in ("raw_data", "normalized_data"):
                        value = rec[key]
                        if isinstance(value, (str, bytes)):
                            rec[key] = json.loads(value)
                        elif value is None:
                            rec[key] = {}
                    rows.append(rec)
                return rows
        finally:
            self._pool.putconn(conn)

    def fetch_ioc(self, value: str) -> dict[str, Any] | None:
        """Fetch one IOC using the existing database schema."""
        records = self.fetch_all(limit=20000)
        return next((record for record in records if record.get("ioc_value") == value), None)

    def update_ioc_metadata(self, value: str, metadata: dict[str, Any]) -> bool:
        """Merge lifecycle metadata into the existing normalized JSONB column."""
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                if set(metadata) == {"metadata"}:
                    expression = "normalized_data || jsonb_build_object('metadata', COALESCE(normalized_data->'metadata', '{}'::jsonb) || %s::jsonb)"
                    payload = json.dumps(metadata["metadata"], default=str)
                else:
                    expression = "normalized_data || %s::jsonb"
                    payload = json.dumps(metadata, default=str)
                cur.execute(
                    f"""UPDATE cti_iocs.iocs
                       SET normalized_data = {expression},
                           last_enriched = NOW(), updated_at = NOW()
                       WHERE ioc_value = %s""",
                    (payload, value),
                )
                changed = cur.rowcount > 0
            conn.commit()
            return changed
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def source_status(self) -> list[dict[str, Any]]:
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT source_name, COUNT(*) AS total, MAX(last_seen) AS last_seen
                       FROM cti_iocs.iocs GROUP BY source_name ORDER BY source_name"""
                )
                return [
                    {"source": row[0], "records": row[1], "last_seen": row[2]}
                    for row in cur.fetchall()
                ]
        finally:
            self._pool.putconn(conn)

    def records_with_scores(self, limit: int = 20000) -> list[dict[str, Any]]:
        records = self.fetch_all(limit)
        for record in records:
            record["severity_score"] = calculate_severity(record)
            record["expired"] = is_expired(record)
        return records
