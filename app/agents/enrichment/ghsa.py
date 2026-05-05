from __future__ import annotations

import time

import httpx
import structlog
from aiolimiter import AsyncLimiter

from app.agents.enrichment.base import EnrichmentSource, SourceResult
from app.config import settings

logger = structlog.get_logger()

GHSA_GRAPHQL = "https://api.github.com/graphql"
_RATE_LIMIT = AsyncLimiter(5, 1)

QUERY = """
query($cveId: String!) {
  securityVulnerabilities(first: 10, ecosystem: UNKNOWN, vulnerability: { cveId: $cveId }) {
    nodes {
      advisory { publishedAt, summary, severity, identifiers { type, value } }
      package { name, ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""


class GhsaSource(EnrichmentSource):
    name = "ghsa"
    base_url = GHSA_GRAPHQL
    cache_ttl = 86400

    def __init__(self, client: httpx.AsyncClient | None = None, limiter: AsyncLimiter | None = None):
        super().__init__(client, limiter or _RATE_LIMIT)
        self._token = settings.github_token

    async def fetch(self, entity: str) -> SourceResult:
        if not self._token:
            return SourceResult(source=self.name, success=False, error="GITHUB_TOKEN not configured")

        t0 = time.monotonic()
        headers = {"Authorization": f"bearer {self._token}"}
        async with self._limiter:
            try:
                resp = await self._client.post(
                    GHSA_GRAPHQL,
                    json={"query": QUERY, "variables": {"cveId": entity}},
                    headers=headers,
                    timeout=15,
                )
                resp.raise_for_status()
                data = resp.json()
                elapsed = int((time.monotonic() - t0) * 1000)
                vulns = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
                return SourceResult(source=self.name, success=True, data={"advisories": vulns}, response_time_ms=elapsed)
            except Exception as e:
                elapsed = int((time.monotonic() - t0) * 1000)
                logger.warning("ghsa_fetch_error", entity=entity, error=str(e))
                return SourceResult(source=self.name, success=False, error=str(e), response_time_ms=elapsed)

    async def health_check(self) -> bool:
        if not self._token:
            return False
        try:
            resp = await self._client.post(
                GHSA_GRAPHQL,
                json={"query": "{ viewer { login } }"},
                headers={"Authorization": f"bearer {self._token}"},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False
