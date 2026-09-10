from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def classify_ioc(value: str) -> str:
    v = value.strip()
    if _SHA256_RE.match(v):
        return "HASH_SHA256"
    if _MD5_RE.match(v):
        return "HASH_MD5"
    if _CVE_RE.match(v):
        return "CVE"
    if _URL_RE.match(v):
        return "URL"
    if _IPV4_RE.match(v):
        return "IP"
    if _DOMAIN_RE.match(v):
        return "DOMAIN"
    return "UNKNOWN"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(raw: Any) -> str:
    if raw is None:
        return _now_iso()
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc).isoformat()
        except (OSError, ValueError):
            return _now_iso()
    if isinstance(raw, str):
        return raw
    return _now_iso()


def _clamp_score(val: Any) -> int:
    try:
        return max(0, min(100, int(val)))
    except (TypeError, ValueError):
        return 0


class Normalizer:
    """Transforms heterogeneous source payloads into the canonical IOC schema."""

    def normalize(self, source: str, raw: dict[str, Any]) -> list[dict[str, Any]]:
        handler = {
            "MalwareBazaar": self._normalize_malwarebazaar,
            "AbuseIPDB": self._normalize_abuseipdb,
            "ThreatFox": self._normalize_threatfox,
            "GreyNoise": self._normalize_greynoise,
            "CISA_KEV": self._normalize_cisa_kev,
        }.get(source)

        if handler is None:
            logger.warning("No normalizer for source %s", source)
            return []

        try:
            return handler(raw)
        except Exception:
            logger.exception("Normalization failed for source=%s", source)
            return []

    # ── MalwareBazaar ────────────────────────────────────────────────────

    def _normalize_malwarebazaar(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for entry in raw.get("data", []):
            sha256 = entry.get("sha256_hash", "")
            md5 = entry.get("md5_hash", "")
            tags = [t for t in (entry.get("tags") or []) if isinstance(t, str)]

            first_seen = _parse_ts(entry.get("first_seen"))
            last_seen = _parse_ts(entry.get("last_seen") or entry.get("first_seen"))

            base_meta: dict[str, Any] = {
                "file_type": entry.get("file_type", ""),
                "file_size": entry.get("file_size", 0),
                "delivery_method": entry.get("delivery_method", ""),
                "signature": entry.get("signature", ""),
                "ssdeep": entry.get("ssdeep", ""),
            }

            if sha256:
                results.append(self._build(
                    ioc_value=sha256,
                    ioc_type="HASH_SHA256",
                    source="MalwareBazaar",
                    threat_type=self._infer_threat_type(tags, "malware"),
                    confidence=85,
                    tags=tags,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    raw_data=entry,
                    metadata={**base_meta, "hash_variant": "sha256"},
                ))
            if md5:
                results.append(self._build(
                    ioc_value=md5,
                    ioc_type="HASH_MD5",
                    source="MalwareBazaar",
                    threat_type=self._infer_threat_type(tags, "malware"),
                    confidence=80,
                    tags=tags,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    raw_data=entry,
                    metadata={**base_meta, "hash_variant": "md5"},
                ))
        return results

    # ── AbuseIPDB ─────────────────────────────────────────────────────────

    def _normalize_abuseipdb(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for item in raw.get("data", []):
            ip = item.get("ipAddress", "")
            if not ip:
                continue

            score = _clamp_score(item.get("abuseConfidenceScore", 0))
            tags_raw = []
            if item.get("isPublic"):
                tags_raw.append("public")
            if item.get("isWhitelisted"):
                tags_raw.append("whitelisted")
            country = item.get("countryCode", "")
            if country:
                tags_raw.append(f"country:{country}")
            usage = item.get("usageType", "")
            if usage:
                tags_raw.append(f"usage:{usage}")

            first_seen = _parse_ts(item.get("firstReportedAt"))
            last_seen = _parse_ts(item.get("lastReportedAt") or item.get("lastCheckedAt"))

            metadata: dict[str, Any] = {
                "isp": item.get("isp", ""),
                "domain": item.get("domain", ""),
                "country_code": country,
                "usage_type": usage,
                "total_reports": item.get("totalReports", 0),
                "num_distinct_users": item.get("numDistinctUsers", 0),
                "is_public": item.get("isPublic", False),
                "is_whitelisted": item.get("isWhitelisted", False),
                "tor": item.get("isTor", False),
            }

            threat_type = "scanner"
            if score >= 75:
                threat_type = "malware"
            elif score >= 40:
                threat_type = "C2"

            results.append(self._build(
                ioc_value=ip,
                ioc_type="IP",
                source="AbuseIPDB",
                threat_type=threat_type,
                confidence=score,
                tags=tags_raw,
                first_seen=first_seen,
                last_seen=last_seen,
                raw_data=item,
                metadata=metadata,
            ))
        return results

    # ── ThreatFox ─────────────────────────────────────────────────────────

    def _normalize_threatfox(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for entry in raw.get("data", []):
            ioc_val = entry.get("ioc", "")
            ioc_type_raw = entry.get("ioc_type", "").upper()
            ioc_type = {
                "IP:PORT": "IP",
                "URL": "URL",
                "DOMAIN": "DOMAIN",
                "EMAIL": "DOMAIN",
                "HOSTNAME": "DOMAIN",
                "MD5": "HASH_MD5",
                "SHA256": "HASH_SHA256",
            }.get(ioc_type_raw, classify_ioc(ioc_val))

            if ioc_type == "IP" and ":" in ioc_val:
                ioc_val = ioc_val.split(":")[0]
                ioc_type = "IP"

            tags_raw = [t.strip() for t in entry.get("tags", "").split(",") if t.strip()]
            malware = entry.get("malware", "")
            if malware:
                tags_raw.append(f"malware:{malware}")

            threat_type_map = {
                "botnet_cc": "C2",
                "malware_download": "malware",
                "phishing": "phishing",
                "c2": "C2",
                "payload_delivery": "malware",
            }
            threat_type = "unknown"
            for tag in tags_raw:
                mapped = threat_type_map.get(tag.lower())
                if mapped:
                    threat_type = mapped
                    break

            first_seen = _parse_ts(entry.get("first_seen_utc"))
            last_seen = _parse_ts(entry.get("last_seen_utc") or entry.get("first_seen_utc"))

            metadata: dict[str, Any] = {
                "malware": malware,
                "confidence_level": entry.get("confidence_level", 0),
                "reporter": entry.get("reporter", ""),
                "reference": entry.get("reference", ""),
                "malware_alias": entry.get("malware_alias", ""),
                "threat_type_raw": entry.get("threat_type", ""),
            }

            results.append(self._build(
                ioc_value=ioc_val,
                ioc_type=ioc_type,
                source="ThreatFox",
                threat_type=threat_type,
                confidence=_clamp_score(entry.get("confidence_level", 50)),
                tags=tags_raw,
                first_seen=first_seen,
                last_seen=last_seen,
                raw_data=entry,
                metadata=metadata,
            ))
        return results

    # ── GreyNoise ─────────────────────────────────────────────────────────

    def _normalize_greynoise(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        ip = raw.get("ip", "")
        if not ip:
            return []

        classification = raw.get("classification", "unknown")
        noise = raw.get("noise", False)
        riot = raw.get("riot", False)
        score = _clamp_score(raw.get("score", 0))

        tags_raw: list[str] = []
        if noise:
            tags_raw.append("noise")
        if riot:
            tags_raw.append("riot")
        tags_raw.append(f"classification:{classification}")

        for tag in raw.get("tags", []):
            if isinstance(tag, str):
                tags_raw.append(tag.lower())

        threat_type_map = {
            "malicious": "malware",
            "benign": "scanner",
            "unknown": "unknown",
        }
        threat_type = threat_type_map.get(classification.lower(), "unknown")

        first_seen = _parse_ts(raw.get("first_seen"))
        last_seen = _parse_ts(raw.get("last_seen") or raw.get("last_updated"))

        metadata: dict[str, Any] = {
            "classification": classification,
            "noise": noise,
            "riot": riot,
            "rdns": raw.get("rdns", ""),
            "asn": raw.get("asn", ""),
            "organization": raw.get("organization", ""),
            "country": raw.get("country", ""),
            "city": raw.get("city", ""),
            "tor": raw.get("tor", False),
            "vpn": raw.get("vpn", False),
            "spyware": raw.get("spyware", False),
            "protocols": raw.get("protocols", []),
        }

        return [self._build(
            ioc_value=ip,
            ioc_type="IP",
            source="GreyNoise",
            threat_type=threat_type,
            confidence=score,
            tags=tags_raw,
            first_seen=first_seen,
            last_seen=last_seen,
            raw_data=raw,
            metadata=metadata,
        )]

    # ── CISA KEV ──────────────────────────────────────────────────────────

    def _normalize_cisa_kev(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for vuln in raw.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue

            first_seen = _parse_ts(vuln.get("dateAdded"))
            last_seen = _parse_ts(
                vuln.get("dueDate") or vuln.get("dateAdded")
            )

            tags: list[str] = []
            product = vuln.get("product", "")
            if product:
                tags.append(f"product:{product}")
            vendor = vuln.get("vendorProject", "")
            if vendor:
                tags.append(f"vendor:{vendor}")
            kw = vuln.get("knownRansomwareCampaignUse", "Unknown")
            if kw != "Unknown":
                tags.append(f"ransomware:{kw.lower()}")
            for k in (vuln.get("vulnerabilityNotes") or []):
                if isinstance(k, dict) and k.get("title"):
                    tags.append(k["title"][:60])

            metadata: dict[str, Any] = {
                "vendor_project": vendor,
                "product": product,
                "vulnerability_name": vuln.get("vulnerabilityName", ""),
                "date_added": vuln.get("dateAdded", ""),
                "due_date": vuln.get("dueDate", ""),
                "required_action": vuln.get("requiredAction", ""),
                "known_ransomware_use": kw,
                "notes": vuln.get("notes", ""),
                "cwes": vuln.get("cwes", []),
            }

            results.append(self._build(
                ioc_value=cve_id,
                ioc_type="CVE",
                source="CISA_KEV",
                threat_type="exploit",
                confidence=95,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                raw_data=vuln,
                metadata=metadata,
            ))
        return results

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _build(
        *,
        ioc_value: str,
        ioc_type: str,
        source: str,
        threat_type: str,
        confidence: int,
        tags: list[str],
        first_seen: str,
        last_seen: str,
        raw_data: dict[str, Any],
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "ioc_value": ioc_value.strip(),
            "ioc_type": ioc_type,
            "source": source,
            "threat_type": threat_type,
            "confidence_score": confidence,
            "tags": tags,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "metadata": metadata,
            "raw_data": raw_data,
        }

    @staticmethod
    def _infer_threat_type(tags: list[str], default: str = "unknown") -> str:
        lower = " ".join(tags).lower()
        if any(t in lower for t in ("trojan", "rat", "backdoor", "stealer", "infostealer")):
            return "malware"
        if any(t in lower for t in ("c2", "command-and-control")):
            return "C2"
        if any(t in lower for t in ("phishing", "credential")):
            return "phishing"
        return default
