from __future__ import annotations

import logging
import time
from typing import Any, Callable

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.normalizer import Normalizer
from sentinova_threatlens.sources import ALL_SOURCES
from sentinova_threatlens.validation import ImportRuleValidator

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, str, float, dict[str, Any] | None], None]

_RULE_LABELS = [
    "Required fields",
    "JSON validation",
    "Indicator structure",
    "Duplicate detection",
    "Severity validation",
    "Source validation",
    "Database compatibility",
]


class IngestionPipeline:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._db = DatabaseEngine(config)
        self._normalizer = Normalizer()
        self._validator = ImportRuleValidator()

    def run(
        self, progress: ProgressCallback | None = None
    ) -> dict[str, Any]:
        def emit(stage: str, message: str, fraction: float, extra: dict[str, Any] | None = None) -> None:
            if progress:
                progress(stage, message, fraction, extra)
            logger.info("[%s] %s", stage, message)

        t0 = time.monotonic()
        stats: dict[str, Any] = {}

        # ── Step 1 — Database initialization ──────────────────────────────
        emit("db_init", "Initializing database…", 3.0)
        self._db.connect()
        self._db.init_schema()
        emit("db_init", "Database initialized", 8.0)

        # ── Step 2 — Import threat intelligence ───────────────────────────
        all_normalised: list[dict[str, Any]] = []
        source_stats: dict[str, Any] = {}
        for idx, source_cls in enumerate(ALL_SOURCES):
            source = source_cls(self._config.sources)
            src_name = source.name
            fraction = 8.0 + (idx / len(ALL_SOURCES)) * 47.0
            emit("import", f"Importing {src_name}…", fraction,
                 {"source": src_name, "phase": "fetch"})
            t_src = time.monotonic()

            try:
                raw_items = source.fetch()
            except Exception:
                logger.exception("[%s] Fetch failed", src_name)
                source_stats[src_name] = {"error": "fetch_failed"}
                continue
            finally:
                source.close()

            normalised: list[dict[str, Any]] = []
            for raw in raw_items:
                normalised.extend(self._normalizer.normalize(src_name, raw))
            all_normalised.extend(normalised)

            source_stats[src_name] = {
                "raw_items": len(raw_items),
                "normalised": len(normalised),
                "elapsed_s": round(time.monotonic() - t_src, 2),
            }
            emit(
                "import",
                f"Importing indicators — {len(all_normalised)} collected",
                fraction + 2.0,
                {"source": src_name, "count": len(all_normalised)},
            )

        # ── Step 3 — Import rule check ────────────────────────────────────
        emit("rules", "Checking import rules…", 55.0)
        validation = self._validator.validate(all_normalised)
        detail_lines = []
        for label, ok, detail in validation.checks:
            status = "✓" if ok else f"⚠ {detail}"
            detail_lines.append(f"{status} {label}")
        emit(
            "rules",
            "Checking import rules…",
            70.0,
            {
                "checks": [c[0] for c in validation.checks],
                "valid": len(validation.valid),
                "skipped": validation.skipped,
                "reasons": validation.reasons,
                "detail": "\n".join(detail_lines),
            },
        )

        # ── Step 4 — Process indicators ───────────────────────────────────
        emit("process", "Processing indicators…", 78.0)
        for i in range(0, max(len(validation.valid), 1), max(1, len(validation.valid) // 5)):
            emit(
                "process",
                f"Processing indicators — {min(i, len(validation.valid))} / {len(validation.valid)}",
                78.0 + 12.0 * (i / max(len(validation.valid), 1)),
            )
        emit("process", f"Processing {len(validation.valid)} indicators", 90.0)

        # ── Store valid records ───────────────────────────────────────────
        upserted = self._db.upsert_batch(validation.valid) if validation.valid else 0

        # ── Step 5 — Final database verification ──────────────────────────
        emit("verify", "Verifying database…", 95.0)
        total_iocs = self._db.count_iocs()
        emit("verify", f"Verified {total_iocs:,} records", 98.0)

        # ── Step 6 — Complete ─────────────────────────────────────────────
        valid_by_source: dict[str, int] = {}
        for rec in validation.valid:
            valid_by_source[rec["source"]] = valid_by_source.get(rec["source"], 0) + 1
        for name, val in source_stats.items():
            val["upserted"] = valid_by_source.get(name, 0)
            stats[name] = val
        stats["_total_collected"] = len(all_normalised)
        stats["_total_valid"] = len(validation.valid)
        stats["_total_skipped"] = validation.skipped
        stats["_skip_reasons"] = validation.reasons
        stats["_upserted"] = upserted
        stats["_total_iocs_in_db"] = total_iocs
        stats["_elapsed_s"] = round(time.monotonic() - t0, 2)
        stats["_rule_details"] = detail_lines

        self._db.close()
        emit("complete", "Initialization complete", 100.0, {
            "valid": len(validation.valid),
            "skipped": validation.skipped,
            "total": total_iocs,
        })
        logger.info("─── Pipeline complete — %d IOCs in DB, %d skipped (%.2fs) ───",
                     total_iocs, validation.skipped, stats["_elapsed_s"])
        return stats