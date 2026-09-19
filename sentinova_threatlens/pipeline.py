from __future__ import annotations

import logging
import time
from typing import Any, Callable

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.db.engine import DatabaseEngine
from sentinova_threatlens.enrichment import CVEEnricher
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
        self, progress: ProgressCallback | None = None,
        enrich_cvss: bool = False,
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
        existing_ips: set[str] = set()
        for idx, source_cls in enumerate(ALL_SOURCES):
            source = source_cls(self._config.sources)
            src_name = source.name
            if src_name in self._config.disabled_sources:
                source_stats[src_name] = {"status": "skipped_by_user", "raw_items": 0, "normalised": 0}
                emit("import", f"Skipping {src_name} by user choice", 8.0 + (idx / len(ALL_SOURCES)) * 47.0, {"source": src_name, "skipped": True})
                source.close()
                continue
            fraction = 8.0 + (idx / len(ALL_SOURCES)) * 47.0
            emit("import", f"Importing {src_name}…", fraction,
                 {"source": src_name, "phase": "fetch"})

            if src_name == "AbuseIPDB" and self._config.sources.abuseipdb_api_key:
                if not existing_ips:
                    existing_ips = self._db.list_values(ioc_type="IP")
                source.skip_ips = existing_ips
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

        # ── Enrich CVEs with CVSS severity (NVD) ──────────────────────────
        # Inline enrichment is opt-in (`enrich_cvss=True`, e.g. the CLI flag).
        # The GUI never blocks on this: severity is fetched in the background
        # after the window opens, so startup stays fast regardless of NVD.
        cve_records = [rec for rec in validation.valid if rec["ioc_type"] == "CVE"]
        cvss_lookup: dict[str, Any] = {}
        cvss_stats = {
            "mode": "inline" if enrich_cvss else "deferred",
            "cached": 0, "fetched": 0, "unresolved": 0, "backfilled": 0,
        }

        if enrich_cvss and cve_records and self._config.sources.cvss_enabled:
            cvss_lookup = self._db.get_cached_cvss(
                [rec["ioc_value"] for rec in cve_records])
            cvss_stats["cached"] = len(cvss_lookup)

            missing = [
                rec["ioc_value"] for rec in cve_records
                if rec["ioc_value"] not in cvss_lookup
            ]
            if missing:
                emit("enrich", f"Enriching severity — 0/{len(missing)} CVEs",
                     90.5, {"cvss": "start", "total": len(missing)})
                enricher = CVEEnricher(self._config.sources)

                def on_progress(done: int, total: int) -> None:
                    emit(
                        "enrich",
                        f"Enriching severity — {done}/{total} CVEs",
                        90.5 + 8.0 * (done / max(total, 1)),
                        {"cvss": "progress", "done": done, "total": total},
                    )

                fetched = enricher.fetch_cvss(missing, progress=on_progress)
                enricher.close()
                if fetched:
                    self._db.store_cvss_cache([
                        {
                            "cve_id": cid,
                            "cvss_score": info.get("cvss_score"),
                            "cvss_severity": info.get("cvss_severity"),
                            "cvss_vector": info.get("cvss_vector"),
                            "cvss_source": info.get("cvss_source", "NVD"),
                        }
                        for cid, info in fetched.items()
                    ])
                    cvss_lookup.update(fetched)
                    cvss_stats["fetched"] = len(fetched)
                cvss_stats["unresolved"] = len(missing) - len(fetched)
                emit("enrich",
                     f"Severity enriched — {cvss_stats['fetched']} resolved, "
                     f"{cvss_stats['unresolved']} unresolved",
                     98.5, {"cvss": "done", **cvss_stats})

        # ── Merge CVSS into normalized metadata ───────────────────────────
        cvss_with_score = {
            cid: info for cid, info in cvss_lookup.items()
            if info.get("cvss_score") is not None
        }
        for rec in cve_records:
            info = cvss_with_score.get(rec["ioc_value"])
            if info:
                rec["metadata"] = {**rec.get("metadata", {}), **info}

        # ── Store only NEW records (incremental import) ───────────────────
        existing = self._db.filter_existing(
            [rec["ioc_value"] for rec in validation.valid]
        )
        new_records = [
            rec for rec in validation.valid if rec["ioc_value"] not in existing
        ]
        already_present = len(validation.valid) - len(new_records)
        emit(
            "process",
            f"Importing {len(new_records):,} new — {already_present:,} already present",
            93.0,
            {"new": len(new_records), "already": already_present},
        )
        upserted = self._db.upsert_batch(new_records) if new_records else 0

        # ── Inline mode: refresh CVSS metadata on CVEs already stored ─────
        if enrich_cvss and cvss_with_score:
            db_cve_ids = set(self._db.list_cves())
            existing_cve_updates = [
                (cve_id, meta)
                for cve_id, meta in cvss_with_score.items()
                if cve_id in db_cve_ids
            ]
            if existing_cve_updates:
                cvss_stats["backfilled"] = self._db.merge_metadata(
                    existing_cve_updates)
                emit("process",
                     f"Updated severity for {cvss_stats['backfilled']:,} "
                     f"existing CVEs", 94.0)

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
        stats["_new_imported"] = len(new_records)
        stats["_already_present"] = already_present
        stats["_upserted"] = upserted
        stats["_cvss_enrichment"] = cvss_stats
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