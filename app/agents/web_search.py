"""Simple web search using DuckDuckGo Lite HTML endpoint (no API key required)."""
from __future__ import annotations

import re
from typing import Any

import httpx
import structlog
from aiolimiter import AsyncLimiter

from app.agents.enrichment.base import make_proxied_client

logger = structlog.get_logger()

_DDG_URL = "https://lite.duckduckgo.com/lite/"
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

# Global rate limiter: max 10 requests per second across all concurrent searches
_rate_limiter = AsyncLimiter(max_rate=10, time_period=1.0)


async def web_search(query: str, max_results: int = 5) -> list[dict[str, Any]]:
    """Search DuckDuckGo and return structured results.

    Returns list of dicts with keys: title, url, snippet.
    Rate-limited to 10 req/s globally.
    """
    try:
        async with _rate_limiter:
            async with make_proxied_client(timeout=10, follow_redirects=True) as client:
                resp = await client.post(
                    _DDG_URL,
                    data={"q": query, "kl": ""},
                    headers=_HEADERS,
                )
                resp.raise_for_status()
                return _parse_results(resp.text, max_results)
    except Exception as e:
        logger.warning("web_search_failed", query=query[:80], error=str(e))
        return []


def _parse_results(html: str, max_results: int) -> list[dict[str, Any]]:
    """Parse DuckDuckGo Lite HTML into structured results.

    DDG Lite format uses <a rel="nofollow" href="URL">TITLE</a> for result links
    and <td class="result-snippet"> for snippets.
    """
    results = []

    # Extract result links: <a rel="nofollow" href="URL">TITLE</a>
    link_pattern = re.compile(
        r'<a\s+rel="nofollow"\s+href="([^"]+)"[^>]*>(.*?)</a>',
        re.DOTALL | re.IGNORECASE,
    )

    # Extract snippets: <td class="result-snippet">TEXT</td>
    snippet_pattern = re.compile(
        r'<td\s+class="result-snippet"[^>]*>(.*?)</td>',
        re.DOTALL | re.IGNORECASE,
    )

    links = link_pattern.findall(html)
    snippets = snippet_pattern.findall(html)

    for i, (url, title) in enumerate(links[:max_results]):
        # Clean HTML tags from title
        title = re.sub(r'<[^>]+>', '', title).strip()
        snippet = ""
        if i < len(snippets):
            snippet = re.sub(r'<[^>]+>', '', snippets[i]).strip()

        # Skip DDG internal links
        if not url or "duckduckgo.com" in url:
            continue
        if not title:
            continue

        results.append({"title": title, "url": url, "snippet": snippet})

    return results
