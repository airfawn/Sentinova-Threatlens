from __future__ import annotations

from sentinova_threatlens.sources.abuseipdb import AbuseIPDBSource
from sentinova_threatlens.sources.cisa_kev import CISAKeVSource
from sentinova_threatlens.sources.greynoise import GreyNoiseSource
from sentinova_threatlens.sources.malwarebazaar import MalwareBazaarSource
from sentinova_threatlens.sources.threatfox import ThreatFoxSource

ALL_SOURCES = [
    MalwareBazaarSource,
    AbuseIPDBSource,
    ThreatFoxSource,
    GreyNoiseSource,
    CISAKeVSource,
]

__all__ = ["ALL_SOURCES"]
