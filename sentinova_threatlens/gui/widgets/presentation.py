from __future__ import annotations

"""Shared presentation helpers producing human-readable values."""

from typing import Any

from sentinova_threatlens.severity import calculate_severity


def defang(value: str) -> str:
    """Defang a URL/domain so it is safe to display."""
    v = value
    v = v.replace("https://", "hxxps://").replace("http://", "hxxp://")
    v = v.replace(".", "[.]").replace("/", "[/]").replace("@", "[@]")
    return v


def clamp_score(score: Any) -> int:
    try:
        return max(0, min(100, int(score)))
    except (TypeError, ValueError):
        return 0


THREAT_BASE = {
    "malware": 70,
    "C2": 85,
    "exploit": 90,
    "phishing": 60,
    "scanner": 40,
    "unknown": 30,
}


def severity_score(record: dict[str, Any]) -> int:
    """Calculate the shared weighted IOC priority score."""
    return calculate_severity(record)


def severity_tier(score: int) -> tuple[str, str]:
    if score >= 75:
        return "CRITICAL", "#F0435B"
    if score >= 50:
        return "HIGH", "#F08A3C"
    if score >= 25:
        return "MEDIUM", "#E8B93C"
    return "LOW", "#3FD68B"


def display_name(record: dict[str, Any]) -> str:
    """Human-readable name: vulnerability name, malware signature/family, or value."""
    norm = record.get("normalized_data", record)
    value = str(norm.get("ioc_value", ""))
    ioc_type = norm.get("ioc_type", "")
    meta = norm.get("metadata", {}) or {}

    if ioc_type == "CVE":
        name = meta.get("vulnerability_name")
        if name:
            return str(name)
        return value

    if ioc_type.startswith("HASH"):
        for key in ("signature", "malware", "signature_name"):
            if meta.get(key):
                return str(meta[key])
        return _shorten_hash(value)

    if ioc_type == "IP":
        domain = meta.get("domain")
        return f"{value}" + (f" ({defang(str(domain))})" if domain else "")

    if ioc_type in ("URL", "DOMAIN"):
        return _host_of(value)

    return value


def display_c2(record: dict[str, Any]) -> str:
    """Website/C2 column: related infrastructure for the indicator."""
    norm = record.get("normalized_data", record)
    value = str(norm.get("ioc_value", ""))
    ioc_type = norm.get("ioc_type", "")
    meta = norm.get("metadata", {}) or {}

    if ioc_type in ("URL", "DOMAIN"):
        return defang(value)
    if ioc_type == "IP":
        dom = meta.get("domain")
        return f"{value} ({defang(str(dom))})" if dom else value
    if ioc_type == "CVE":
        vendor = meta.get("vendor_project", "")
        product = meta.get("product", "")
        return f"{vendor} {product}".strip() or "Known exploited vulnerability"
    if ioc_type.startswith("HASH"):
        ref = meta.get("reference") or meta.get("delivery_method")
        if ref:
            return defang(str(ref))
        ftype = meta.get("file_type")
        return str(ftype) if ftype else "—"
    return value


def display_indicator(record: dict[str, Any]) -> str:
    """Raw indicator value: the IP, CVE id, hash or defanged URL/domain."""
    norm = record.get("normalized_data", record)
    value = str(norm.get("ioc_value", ""))
    ioc_type = norm.get("ioc_type", "")
    if ioc_type in ("URL", "DOMAIN"):
        return defang(value)
    if ioc_type.startswith("HASH"):
        return _shorten_hash(value)
    return value


def display_details(record: dict[str, Any]) -> str:
    """Short human-readable description for the Details column."""
    norm = record.get("normalized_data", record)
    ioc_type = norm.get("ioc_type", "")
    value = str(norm.get("ioc_value", ""))
    meta = norm.get("metadata", {}) or {}

    if ioc_type == "IP":
        parts: list[str] = []
        usage = meta.get("usage_type") or meta.get("isp")
        if usage:
            parts.append(str(usage))
        if meta.get("country_code"):
            parts.append(f"{meta['country_code']}")
        reports = meta.get("total_reports")
        users = meta.get("num_distinct_users")
        if reports:
            bits = f"{reports:,} reports"
            if users:
                bits += f" / {users:,} users"
            parts.append(bits)
        if meta.get("domain"):
            parts.append(defang(str(meta["domain"])))
        if meta.get("tor"):
            parts.append("TOR")
        hostnames = meta.get("hostnames")
        if isinstance(hostnames, list) and hostnames:
            parts.append(f"↳ {defang(str(hostnames[0]))}")
        return " · ".join(parts) or value

    if ioc_type == "CVE":
        action = " ".join(str(meta.get("required_action", "")).split())
        if action:
            return (action[:150] + "…") if len(action) > 150 else action
        vendor = meta.get("vendor_project", "")
        product = meta.get("product", "")
        return " ".join(x for x in (vendor, product) if x) or "Known exploited"

    if ioc_type.startswith("HASH"):
        sig = meta.get("signature") or meta.get("malware")
        ftype = meta.get("file_type")
        delivery = meta.get("delivery_method")
        return " · ".join(
            x for x in (str(sig) if sig else "", str(ftype) if ftype else "",
                        str(delivery) if delivery else "") if x
        ) or "Hash indicator"

    if ioc_type in ("URL", "DOMAIN"):
        malware = meta.get("malware")
        if malware:
            return f"{defang(_host_of(value))} ({str(malware)})"
        return defang(value)

    return value


def source_label(record: dict[str, Any]) -> str:
    src = record.get("source_name", record.get("normalized_data", {}).get("source", ""))
    return str(src).replace("_", " ") if src else "—"


def _host_of(value: str) -> str:
    if "://" in value:
        value = value.split("://", 1)[1]
    return value.split("/", 1)[0]


def _shorten_hash(value: str) -> str:
    if len(value) > 20:
        return f"{value[:18]}…"
    return value


def cell_key(record: dict[str, Any], column: str) -> str:
    """Sort/filter key for a given column."""
    if column == "severity":
        return severity_score(record)
    if column == "indicator":
        return str(record.get("ioc_value", "")).lower()
    if column == "details":
        return display_details(record)
    if column == "source":
        return source_label(record)
    if column in ("name", "c2"):
        return display_name(record) if column == "name" else display_c2(record)
    return str(record.get("ioc_value", ""))