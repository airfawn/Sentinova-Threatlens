from __future__ import annotations

from typing import Any

from sentinova_threatlens.sources.base import BaseSource


class OpenPhishSource(BaseSource):
    name = "OpenPhish"
    _URL = "https://openphish.com/feed.txt"

    def fetch(self) -> list[dict[str, Any]]:
        response = self._session.get(self._URL, timeout=self._config.request_timeout)
        response.raise_for_status()
        return [{"url": line.strip(), "source": self.name} for line in response.text.splitlines() if line.strip()]
