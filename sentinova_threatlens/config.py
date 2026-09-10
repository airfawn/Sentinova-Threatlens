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

    @property
    def dsn(self) -> str:
        return (
            f"host={self.host} port={self.port} dbname={self.name} "
            f"user={self.user} password={self.password}"
        )


@dataclass(frozen=True)
class SourceConfig:
    abusech_api_key: str = field(
        default_factory=lambda: _env("ABUSE_CH_API_KEY", "")
    )
    abuseipdb_api_key: str = field(
        default_factory=lambda: _env("ABUSEIPDB_API_KEY", "")
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


@dataclass(frozen=True)
class AppConfig:
    db: DatabaseConfig = field(default_factory=DatabaseConfig)
    sources: SourceConfig = field(default_factory=SourceConfig)
    log_level: str = field(default_factory=lambda: _env("CTI_LOG_LEVEL", "INFO"))
    schema_ddl: Path = field(
        default_factory=lambda: Path(__file__).parent / "db" / "schema.sql"
    )
