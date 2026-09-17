from __future__ import annotations

from sentinova_threatlens.api.app import create_app
from sentinova_threatlens.config import AppConfig


def main() -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit("Install requirements.txt to run the API") from exc
    config = AppConfig()
    uvicorn.run(create_app(config), host=config.api.host, port=config.api.port)


if __name__ == "__main__":
    main()