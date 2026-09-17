from __future__ import annotations

from typing import Any

import requests


class Taxii21Client:
    """TAXII 2.1 discovery and paginated collection poller."""

    MEDIA = "application/taxii+json;version=2.1"

    def __init__(self, endpoint: str, username: str = "", password: str = "", timeout: int = 15) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (username, password) if username else None
        self.timeout = timeout

    def discovery(self) -> dict[str, Any]:
        response = self.session.get(self.endpoint + "/taxii2/", headers={"Accept": self.MEDIA}, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def collections(self, api_root: str) -> list[dict[str, Any]]:
        response = self.session.get(api_root.rstrip("/") + "/collections/", headers={"Accept": self.MEDIA}, timeout=self.timeout)
        response.raise_for_status()
        return response.json().get("collections", [])

    def poll(self, collection_url: str, added_after: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        url = collection_url.rstrip("/") + "/objects/"
        params = {"added_after": added_after} if added_after else {}
        objects: list[dict[str, Any]] = []
        while url:
            response = self.session.get(url, params=params, headers={"Accept": self.MEDIA}, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
            objects.extend(payload.get("objects", []))
            next_link = payload.get("more") and payload.get("next")
            url = next_link or ""
            params = {}
        return objects, payload.get("next") if objects else added_after
