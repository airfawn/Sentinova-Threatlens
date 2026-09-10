from __future__ import annotations

import json
import logging
from typing import Any

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

from sentinova_threatlens.config import AppConfig

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
            return len(serialised)
        except Exception:
            conn.rollback()
            raise
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
