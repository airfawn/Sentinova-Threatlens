from __future__ import annotations

import logging
from typing import Any

from sentinova_threatlens.sources.base import BaseSource

logger = logging.getLogger(__name__)

_COMMUNITY_URL = "https://api.greynoise.io/v3/community/"
_IPS_URL = "https://api.greynoise.io/v3/community/{ip}"

_COMMUNITY_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "104.16.132.229",
    "142.250.80.46",
    "198.41.0.4",
]


class GreyNoiseSource(BaseSource):
    name = "GreyNoise"

    def fetch(self) -> list[dict[str, Any]]:
        api_key = self._config.greynoise_api_key
        if not api_key:
            logger.warning("[%s] No API key configured — skipping", self.name)
            return []

        self._session.headers.update({
            "key": api_key,
            "Accept": "application/json",
        })

        results: list[dict[str, Any]] = []
        for ip in _COMMUNITY_IPS:
            url = _IPS_URL.format(ip=ip)
            data = self._get(url)
            if data and data.get("ip"):
                results.append(data)
                logger.debug("[%s] %s → %s", self.name, ip, data.get("classification"))

        logger.info("[%s] Fetched %d IPs", self.name, len(results))
        return results
