from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import requests

from sentinova_threatlens.config import SourceConfig

logger = logging.getLogger(__name__)


class BaseSource(ABC):
    name: str = "BaseSource"

    def __init__(self, config: SourceConfig) -> None:
        self._config = config
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "SentinovaThreatlens/1.0"})

    @abstractmethod
    def fetch(self) -> list[dict[str, Any]]:
        """Return a list of raw response dicts suitable for normalisation."""

    def _post(self, url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            resp = self._session.post(
                url,
                json=payload or {},
                timeout=self._config.request_timeout,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.error("[%s] POST %s failed: %s", self.name, url, exc)
            return {}

    def _get(self, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            resp = self._session.get(
                url,
                timeout=self._config.request_timeout,
                **kwargs,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.error("[%s] GET %s failed: %s", self.name, url, exc)
            return {}

    def close(self) -> None:
        self._session.close()
