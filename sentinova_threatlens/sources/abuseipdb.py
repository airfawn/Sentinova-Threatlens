from __future__ import annotations

import ipaddress
import logging
from typing import Any

from sentinova_threatlens.sources.base import BaseSource

logger = logging.getLogger(__name__)

_API_URL = "https://api.abuseipdb.com/api/v2/check-block"

_SUBNET_CANDIDATES = [
    "103.224.182.0/24",
    "45.33.32.0/20",
    "198.51.100.0/24",
    "203.0.113.0/24",
]


class AbuseIPDBSource(BaseSource):
    name = "AbuseIPDB"

    def fetch(self) -> list[dict[str, Any]]:
        api_key = self._config.abuseipdb_api_key
        if not api_key:
            logger.warning("[%s] No API key configured — skipping", self.name)
            return []

        self._session.headers.update({
            "Key": api_key,
            "Accept": "application/json",
        })

        all_data: dict[str, Any] = {"data": []}
        for subnet in _SUBNET_CANDIDATES:
            result = self._get(_API_URL, params={"network": subnet, "maxAgeInDays": "90"})
            entries = result.get("data", [])
            if entries:
                all_data["data"].extend(entries)
                logger.info("[%s] Subnet %s: %d IPs", self.name, subnet, len(entries))

        logger.info("[%s] Total IPs fetched: %d", self.name, len(all_data["data"]))
        return [all_data] if all_data["data"] else []
