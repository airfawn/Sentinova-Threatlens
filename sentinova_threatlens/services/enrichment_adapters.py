from __future__ import annotations

import logging
from typing import Any

import requests

from sentinova_threatlens.config import SourceConfig

logger = logging.getLogger(__name__)


class VirusTotalEnricher:
    """VirusTotal v3 adapter with deterministic offline fallback."""

    def __init__(self, config: SourceConfig) -> None:
        self._key = getattr(config, "virustotal_api_key", "")

    def lookup(self, value: str) -> dict[str, Any]:
        if not self._key:
            return {"provider": "VirusTotal", "mode": "mock", "reputation": 0, "note": "API key not configured"}
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/search?query={value}",
                headers={"x-apikey": self._key},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json().get("data", [])
            return {"provider": "VirusTotal", "mode": "live", "matches": len(data), "data": data[:3]}
        except (requests.RequestException, ValueError) as exc:
            logger.warning("VirusTotal lookup failed: %s", exc)
            return {"provider": "VirusTotal", "mode": "mock", "reputation": 0, "error": "lookup_failed"}


class GeoASNEnricher:
    """IP geolocation adapter; returns a safe mock result when offline."""

    def lookup(self, value: str) -> dict[str, Any]:
        try:
            response = requests.get(f"https://ipwho.is/{value}", timeout=5)
            response.raise_for_status()
            data = response.json()
            return {
                "provider": "ipwho.is",
                "mode": "live",
                "country": data.get("country"),
                "city": data.get("city"),
                "asn": (data.get("connection") or {}).get("asn"),
                "organization": (data.get("connection") or {}).get("org"),
            }
        except (requests.RequestException, ValueError):
            return {"provider": "GeoIP/ASN", "mode": "mock", "country": "ZZ", "city": "Offline", "asn": None}
