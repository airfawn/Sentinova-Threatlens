from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path = _PROJECT_ROOT / ".env") -> None:
    try:
        if not path.exists():
            return
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)
    except OSError:
        pass


_load_dotenv()


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def save_env_values(values: dict[str, str]) -> None:
    """Persist selected local settings without rewriting unrelated .env lines."""
    path = _PROJECT_ROOT / ".env"
    try:
        lines = path.read_text().splitlines() if path.exists() else []
        remaining = dict(values)
        updated: list[str] = []
        for line in lines:
            stripped = line.lstrip()
            key = stripped.split("=", 1)[0].strip() if "=" in stripped and not stripped.startswith("#") else ""
            if key in remaining:
                updated.append(f"{key}={remaining.pop(key)}")
            else:
                updated.append(line)
        if remaining:
            if updated and updated[-1] != "":
                updated.append("")
            updated.extend(f"{key}={value}" for key, value in remaining.items())
        path.write_text("\n".join(updated) + "\n")
        for key, value in values.items():
            if value:
                os.environ[key] = value
    except OSError:
        logging.getLogger(__name__).warning("Could not persist local environment settings", exc_info=True)


@dataclass(frozen=True)
class DatabaseConfig:
    host: str = field(default_factory=lambda: _env("CTI_DB_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(_env("CTI_DB_PORT", "5432")))
    name: str = field(default_factory=lambda: _env("CTI_DB_NAME", "sentinova"))
    user: str = field(default_factory=lambda: _env("CTI_DB_USER", "cti_user"))
    password: str = field(default_factory=lambda: _env("CTI_DB_PASSWORD", ""))
    schema: str = field(default_factory=lambda: _env("CTI_DB_SCHEMA", "cti_iocs"))
    pool_min: int = field(default_factory=lambda: int(_env("CTI_DB_POOL_MIN", "2")))
    pool_max: int = field(default_factory=lambda: int(_env("CTI_DB_POOL_MAX", "10")))
    connect_timeout: int = field(
        default_factory=lambda: int(_env("CTI_DB_CONNECT_TIMEOUT", "5"))
    )

    @property
    def dsn(self) -> str:
        return (
            f"host={self.host} port={self.port} dbname={self.name} "
            f"user={self.user} password={self.password} connect_timeout={self.connect_timeout}"
        )


@dataclass(frozen=True)
class SourceConfig:
    virustotal_api_key: str = field(
        default_factory=lambda: _env("VIRUSTOTAL_API_KEY", "")
    )
    abusech_api_key: str = field(
        default_factory=lambda: _env("ABUSE_CH_API_KEY", "")
    )
    abuseipdb_api_key: str = field(
        default_factory=lambda: _env("ABUSEIPDB_API_KEY", "")
    )
    abuseipdb_max_ips: int = field(
        default_factory=lambda: int(_env("ABUSEIPDB_MAX_IPS", "25"))
    )
    abuseipdb_feed_url: str = field(
        default_factory=lambda: _env(
            "ABUSEIPDB_FEED_URL",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        )
    )
    greynoise_api_key: str = field(
        default_factory=lambda: _env("GREYNOISE_API_KEY", "")
    )
    request_timeout: int = field(
        default_factory=lambda: int(_env("CTI_REQUEST_TIMEOUT", "30"))
    )
    batch_size: int = field(
        default_factory=lambda: int(_env("CTI_BATCH_SIZE", "100"))
    )
    cvss_enabled: bool = field(
        default_factory=lambda: _env("CTI_CVSS_ENABLED", "1") != "0"
    )
    cvss_url: str = field(
        default_factory=lambda: _env(
            "CVSS_ENRICHMENT_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        )
    )
    cvss_workers: int = field(
        default_factory=lambda: int(_env("CVSS_ENRICHMENT_WORKERS", "3"))
    )


@dataclass(frozen=True)
class RedisConfig:
    url: str = field(
        default_factory=lambda: _env("CTI_REDIS_URL", "redis://localhost:6379/0")
    )
    enabled: bool = field(
        default_factory=lambda: _env("CTI_REDIS_ENABLED", "1") != "0"
    )
    ttl_seconds: int = field(
        default_factory=lambda: int(_env("CTI_REDIS_TTL", "300"))
    )


@dataclass(frozen=True)
class ApiConfig:
    host: str = field(default_factory=lambda: _env("CTI_API_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("CTI_API_PORT", "8765")))
    role: str = field(default_factory=lambda: _env("CTI_API_ROLE", "Analyst"))
    token_secret: str = field(default_factory=lambda: _env("CTI_API_TOKEN_SECRET", "change-me"))
    rate_limit_per_minute: int = field(default_factory=lambda: int(_env("CTI_API_RATE_LIMIT", "120")))
    webhook_secret: str = field(default_factory=lambda: _env("CTI_WEBHOOK_SECRET", "change-me"))
    bootstrap_admin: str = field(default_factory=lambda: _env("CTI_BOOTSTRAP_ADMIN", ""))
    bootstrap_password: str = field(default_factory=lambda: _env("CTI_BOOTSTRAP_PASSWORD", ""))


@dataclass(frozen=True)
class AppConfig:
    db: DatabaseConfig = field(default_factory=DatabaseConfig)
    sources: SourceConfig = field(default_factory=SourceConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    disabled_sources: tuple[str, ...] = ()
    log_level: str = field(default_factory=lambda: _env("CTI_LOG_LEVEL", "INFO"))
    schema_ddl: Path = field(
        default_factory=lambda: Path(__file__).parent / "db" / "schema.sql"
    )
