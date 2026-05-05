from __future__ import annotations

import time

import httpx
import structlog
from aiolimiter import AsyncLimiter
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.agents.enrichment.base import EnrichmentSource, SourceResult
from app.config import settings

logger = structlog.get_logger()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RATE_LIMIT_NVD_KEY = AsyncLimiter(40, 30)
_RATE_LIMIT_NVD_NO_KEY = AsyncLimiter(4, 30)


class NvdSource(EnrichmentSource):
    name = "nvd"
    base_url = NVD_BASE
    cache_ttl = 86400  # 24 hours

    def __init__(self, client: httpx.AsyncClient | None = None, limiter: AsyncLimiter | None = None):
        super().__init__(client, limiter or (_RATE_LIMIT_NVD_KEY if settings.nvd_api_key else _RATE_LIMIT_NVD_NO_KEY))
        self._api_key = settings.nvd_api_key

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
    )
    async def fetch(self, entity: str) -> SourceResult:
        t0 = time.monotonic()
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        async with self._limiter:
            try:
                resp = await self._client.get(
                    f"{NVD_BASE}",
                    params={"cveId": entity},
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                elapsed = int((time.monotonic() - t0) * 1000)
                return SourceResult(source=self.name, success=True, data=data, response_time_ms=elapsed)
            except httpx.HTTPStatusError as e:
                elapsed = int((time.monotonic() - t0) * 1000)
                logger.warning("nvd_fetch_error", entity=entity, status=e.response.status_code)
                return SourceResult(source=self.name, success=False, error=str(e), response_time_ms=elapsed)
            except Exception as e:
                elapsed = int((time.monotonic() - t0) * 1000)
                logger.warning("nvd_fetch_error", entity=entity, error=str(e))
                return SourceResult(source=self.name, success=False, error=str(e), response_time_ms=elapsed)

    def extract_fields(self, raw: dict) -> dict:
        """Extract normalized fields from NVD API response."""
        vulns = raw.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})
        cvss31 = metrics.get("cvssMetricV31", [{}])
        cvss_data = cvss31[0].get("cvssData", {}) if cvss31 else {}

        descriptions = cve.get("descriptions", [])
        en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])

        configs = cve.get("configurations", [])
        cpe_matches = []
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_matches.append(match.get("criteria", ""))

        return {
            "cvss_v3_score": cvss_data.get("baseScore"),
            "cvss_v3_vector": cvss_data.get("vectorString"),
            "cwe_ids": cwe_ids,
            "cpe_matches": cpe_matches,
            "description": en_desc,
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "references": [r.get("url") for r in cve.get("references", [])],
        }

    async def health_check(self) -> bool:
        try:
            async with self._limiter:
                resp = await self._client.get(f"{NVD_BASE}", params={"cveId": "CVE-2024-21413"})
                return resp.status_code == 200
        except Exception:
            return False
