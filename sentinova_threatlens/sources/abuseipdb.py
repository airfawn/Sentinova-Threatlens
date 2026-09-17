from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any

from sentinova_threatlens.sources.base import BaseSource

logger = logging.getLogger(__name__)

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_PACE_SEC = 0.9

# Fallback seed list used when the reputation feed is unreachable. These are
# IPs that frequently appear on public abuse/blocklists.
_SEED_IPS = [
    "45.33.32.156",
    "104.244.72.115",
    "91.240.118.80",
    "178.128.164.16",
    "185.220.101.29",
    "103.105.199.130",
    "103.27.110.201",
    "185.141.61.87",
    "183.6.19.135",
    "193.169.255.68",
]


class AbuseIPDBSource(BaseSource):
    name = "AbuseIPDB"

    def fetch(self) -> list[dict[str, Any]]:
        api_key = self._config.abuseipdb_api_key
        if not api_key:
            logger.warning("[%s] No API key configured — skipping", self.name)
            return []

        candidates = self._collect_candidates()
        candidates = [ip for ip in candidates if ip not in self.skip_ips]
        if not candidates:
            logger.info("[%s] No new candidate IPs to check", self.name)
            return []

        cap = max(1, self._config.abuseipdb_max_ips)
        targets = candidates[:cap]
        self._session.headers.update({
            "Key": api_key,
            "Accept": "application/json",
        })

        data: list[dict[str, Any]] = []
        t0 = time.monotonic()
        for ip in targets:
            info = self._check_ip(ip)
            if info is None:
                break  # auth/quota failure — stop
            if info:
                data.append(info)
            time.sleep(_PACE_SEC)

        logger.info("[%s] Checked %d IPs → %d reported (%.1fs)",
                    self.name, len(targets), len(data), time.monotonic() - t0)
        return [{"data": data}] if data else []

    # ── Internals ─────────────────────────────────────────────────────────

    def _collect_candidates(self) -> list[str]:
        feed = self._fetch_text(self._config.abuseipdb_feed_url)
        if feed:
            ips: list[str] = []
            for line in feed.splitlines():
                candidate = line.strip().rstrip("\r")
                if not candidate:
                    continue
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                ips.append(candidate)
            if ips:
                logger.info("[%s] Seed feed provided %d candidate IPs",
                            self.name, len(ips))
                return list(dict.fromkeys(ips))
            logger.warning("[%s] Feed empty — using embedded seed list", self.name)
        else:
            logger.warning("[%s] Feed unavailable — using embedded seed list",
                           self.name)
        return [ip for ip in _SEED_IPS if self._is_ip(ip)]

    def _check_ip(self, ip: str) -> dict[str, Any] | None:
        """Return reputation payload for one IP, or None to abort the run."""
        try:
            resp = self._session.get(
                _API_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=self._config.request_timeout,
            )
        except Exception:
            logger.warning("[%s] Check %s raised — skipping", self.name, ip)
            return None

        if resp.status_code == 401 or resp.status_code == 403:
            logger.error("[%s] Key rejected (%d) — disabling source",
                         self.name, resp.status_code)
            return None
        if resp.status_code == 404:
            return {}
        if resp.status_code == 429:
            logger.warning("[%s] Quota exhausted (429) — stopping check loop",
                           self.name)
            return None
        if resp.status_code != 200:
            logger.warning("[%s] Check %s returned %d — skipped",
                           self.name, ip, resp.status_code)
            return {}

        payload = resp.json().get("data") or {}
        score = int(payload.get("abuseConfidenceScore") or 0)
        reports = int(payload.get("totalReports") or 0)
        if score <= 0 and reports <= 0:
            return {}
        return payload

    def _fetch_text(self, url: str) -> str:
        try:
            resp = self._session.get(url, timeout=self._config.request_timeout)
            resp.raise_for_status()
            return resp.text
        except Exception:
            return ""

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False