from __future__ import annotations

import logging
from typing import Any

from sentinova_threatlens.sources.base import BaseSource

logger = logging.getLogger(__name__)

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class CISAKeVSource(BaseSource):
    name = "CISA_KEV"

    def fetch(self) -> list[dict[str, Any]]:
        data = self._get(_KEV_URL)
        vulns = data.get("vulnerabilities", [])
        logger.info("[%s] Fetched %d CVEs", self.name, len(vulns))
        return [data] if vulns else []
