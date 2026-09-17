from __future__ import annotations

import logging
import time
from typing import Any, Callable

import requests

from sentinova_threatlens.config import SourceConfig

logger = logging.getLogger(__name__)

ProgressFn = Callable[[int, int], None]

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

# NVD unauthenticated access tolerates roughly 50 req/30s, but is burst
# sensitive: parallel bursts and rapid retries trigger 429 "Too Many Requests"
# and each backoff then makes things orders of magnitude slower. We therefore
# pace requests slowly and sequentially, and adaptively slow down further the
# moment NVD throttles us, so sustained runs never hit the 429 spiral.
_INITIAL_INTERVAL = 0.70       # seconds between requests (~1.4 req/s)
_MIN_INTERVAL = 0.45
_MAX_INTERVAL = 3.00


class _Pacer:
    """Adaptive, thread-safe pace timer (sequential use, lock kept for safety)."""

    def __init__(self, initial: float) -> None:
        self._interval = initial
        self._next = 0.0
        self._stable = 0
        self._lock_ = __import__("threading").Lock()

    def wait(self) -> None:
        with self._lock_:
            now = time.monotonic()
            if now < self._next:
                time.sleep(self._next - now)
            self._next = time.monotonic() + self._interval

    def on_429(self) -> None:
        with self._lock_:
            self._interval = min(self._interval * 1.6, _MAX_INTERVAL)
            self._next = time.monotonic() + 5.0
            self._stable = 0
            logger.info("NVD throttled us (HTTP 429) — slowing to %.2fs/req",
                        self._interval)

    def on_success(self) -> None:
        # Gently relax back toward the minimum after a long clean streak.
        self._stable += 1
        if self._stable >= 60 and self._interval > _MIN_INTERVAL:
            self._stable = 0
            self._interval = max(self._interval * 0.9, _MIN_INTERVAL)

    @property
    def interval(self) -> float:
        return self._interval


class CVEEnricher:
    """Fetches CVSS severity metadata for CVEs and caches results per CVE.

    Queries NVD's CVE API (the authoritative source for scored CVEs) using a
    single sequential, adaptively-paced worker — deliberately slow and calm so
    it never trips NVD's burst protection. Definitively-missing CVEs (HTTP 404)
    are stored as empty cache rows so they are never fetched twice.
    """

    def __init__(self, config: SourceConfig) -> None:
        self._config = config
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "SentinovaThreatlens/1.0 (CYBERSHIELD-LENS research)",
            "Accept": "application/json",
        })
        self._pacer = _Pacer(_INITIAL_INTERVAL)

    def fetch_cvss(
        self, cve_ids: list[str], progress: ProgressFn | None = None
    ) -> dict[str, dict[str, Any]]:
        """Sequentially resolve CVSS data; returns {cve_id: info} for results.

        Entries are included both for CVEs that have a score and for CVEs that
        definitively have none (HTTP 404 / no metric) — the caller can cache
        both. CVEs that only failed transiently (network error, repeated 429)
        are omitted so they may be retried on a later run.
        """
        if not cve_ids or not self._config.cvss_enabled:
            return {}

        results: dict[str, dict[str, Any]] = {}
        total = len(cve_ids)
        logger.info("Enriching %d CVEs (adaptive NVD pacing, ~%.2fs each)",
                    total, self._pacer.interval)

        for done, cve_id in enumerate(cve_ids, 1):
            self._pacer.wait()
            info = self._resolve(cve_id)
            if info is not None:
                results[cve_id] = info
                if info.get("cvss_score") is not None:
                    self._pacer.on_success()
            if progress and done % 25 == 0:
                progress(done, total)
            if done % 100 == 0:
                scored = sum(
                    1 for v in results.values() if v.get("cvss_score") is not None
                )
                logger.info("CVSS %d/%d (%.0f%% resolved)",
                            done, total, 100.0 * scored / max(done, 1))

        if progress:
            progress(total, total)
        scored = sum(1 for v in results.values() if v.get("cvss_score") is not None)
        logger.info("CVSS enrichment complete: %d scored, %d empty, %d skipped",
                    scored,
                    len(results) - scored,
                    total - len(results))
        return results

    def _resolve(self, cve_id: str) -> dict[str, Any] | None:
        """One looked-up CVE. Returns dict (even empty) or None if transient."""
        url = self._config.cvss_url.format(cve=cve_id)
        resp = self._get(url)
        if resp is None:
            return None
        if resp.status_code == 200:
            data = resp.json()
            if not data.get("vulnerabilities"):
                return {}
            return self._extract(data["vulnerabilities"][0]["cve"])
        if resp.status_code in (404, 400):
            return {}  # definitive: cached as "no score"
        if resp.status_code == 429:
            self._pacer.on_429()
            resp = self._get(url)  # single calm retry
            if resp is not None and resp.status_code == 200:
                data = resp.json()
                if data.get("vulnerabilities"):
                    return self._extract(data["vulnerabilities"][0]["cve"])
                return {}
            return None  # throttled again — leave for a later run
        logger.warning("[%s] unexpected HTTP %d (transient skip)", cve_id,
                       resp.status_code)
        return None

    def _get(self, url: str) -> requests.Response | None:
        try:
            return self._session.get(url, timeout=15)
        except requests.RequestException:
            logger.debug("request error for %s", url, exc_info=True)
            time.sleep(1.0)
            return None

    @staticmethod
    def _extract(cve: dict[str, Any]) -> dict[str, Any]:
        """Pull the best CVSS metric (v3.1 → v3.0 → v2, Primary preferred)."""
        metrics = cve.get("metrics") or {}
        ordered = []
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            ordered.extend(metrics.get(key, []) or [])
        if not ordered:
            return {}

        def prefer_key(item: dict[str, Any]) -> tuple[int, str]:
            rank = {
                "cvssMetricV31": 0, "cvssMetricV30": 1, "cvssMetricV2": 2,
            }.get(item.get("cvssData", {}).get("version"), 3)
            is_primary = 0 if item.get("type") == "Primary" else 1
            return (is_primary, rank)

        metric = sorted(ordered, key=prefer_key)[0]
        data = metric.get("cvssData") or {}
        score = data.get("baseScore")
        vector = data.get("vectorString")
        severity = data.get("baseSeverity") or data.get("severity")

        if score is None and severity is None and not vector:
            return {}
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None

        return {
            "cvss_score": score,
            "cvss_severity": (severity or "").upper() or None,
            "cvss_vector": vector or None,
            "cvss_source": "NVD",
        }

    def close(self) -> None:
        self._session.close()