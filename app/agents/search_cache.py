from __future__ import annotations

import re
from typing import Any


class SearchCache:
    """Task-scoped shared cache for web_search results."""

    def __init__(self) -> None:
        self._cache: dict[str, list[dict[str, Any]]] = {}

    def normalize(self, query: str) -> str:
        words = query.lower().split()
        words = [re.sub(r"[^a-z0-9]", "", w) for w in words]
        words = sorted(set(w for w in words if w))
        return " ".join(words)

    def get(self, query: str) -> list[dict[str, Any]] | None:
        key = self.normalize(query)
        return self._cache.get(key)

    def set(self, query: str, results: list[dict[str, Any]]) -> None:
        key = self.normalize(query)
        self._cache[key] = results

    async def get_or_fetch(self, query: str, fetcher) -> list[dict[str, Any]]:
        cached = self.get(query)
        if cached is not None:
            return cached
        results = await fetcher(query)
        self.set(query, results)
        return results

    def __len__(self) -> int:
        return len(self._cache)
