from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.agents.enrichment.nvd import NvdSource
from app.agents.enrichment.epss import EpssSource
from app.agents.enrichment.base import SourceResult


NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-21413",
                "descriptions": [{"lang": "en", "value": "Microsoft Outlook remote code execution"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-20"}]}],
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:microsoft:outlook:*"}]}]}],
                "published": "2024-02-13T00:00:00",
                "lastModified": "2024-02-15T00:00:00",
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21413"}],
            }
        }
    ]
}

EPSS_RESPONSE = {
    "data": [{"cve": "CVE-2024-21413", "epss": "0.94567", "percentile": "0.96", "date": "2024-02-15"}]
}


class TestNvdSource:
    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_success(self):
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(200, json=NVD_RESPONSE)
        )
        async with httpx.AsyncClient() as client:
            src = NvdSource(client=client)
            result = await src.fetch("CVE-2024-21413")
            assert result.success is True
            assert result.source == "nvd"

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_error(self):
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(503)
        )
        async with httpx.AsyncClient() as client:
            src = NvdSource(client=client)
            result = await src.fetch("CVE-2024-21413")
            assert result.success is False

    def test_extract_fields(self):
        src = NvdSource.__new__(NvdSource)
        fields = src.extract_fields(NVD_RESPONSE)
        assert fields["cvss_v3_score"] == 9.8
        assert "CWE-20" in fields["cwe_ids"]
        assert "cpe:2.3:a:microsoft:outlook:*" in fields["cpe_matches"]
        assert "Microsoft Outlook" in fields["description"]


class TestEpssSource:
    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_success(self):
        respx.get("https://api.first.org/data/v1/epss").mock(
            return_value=httpx.Response(200, json=EPSS_RESPONSE)
        )
        async with httpx.AsyncClient() as client:
            src = EpssSource(client=client)
            result = await src.fetch("CVE-2024-21413")
            assert result.success is True
            assert result.data["epss"] == "0.94567"
            assert result.data["percentile"] == "0.96"


class TestAttckLoader:
    def test_load_and_get_technique(self):
        from app.utils.attck_loader import get_technique, load_attck

        data = load_attck()
        assert "objects" in data
        # T1566 should exist in the ATT&CK bundle
        tech = get_technique("T1566")
        assert tech is not None
        assert tech["type"] == "attack-pattern"

    def test_validate_technique(self):
        from app.utils.attck_loader import validate_technique_id

        assert validate_technique_id("T1566") is True
        assert validate_technique_id("T9999") is False
