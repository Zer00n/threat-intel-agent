import pytest

from app.agents.ioc_extractor import IOCExtractorAgent
from app.agents.memory import Finding, Memory
from app.utils.ioc_regex import extract_all_iocs
from app.utils.defang import defang, refang


class TestIOCRegex:
    def test_ipv4(self):
        results = extract_all_iocs("The C2 server is 192.0.2.100")
        assert any(r["type"] == "ipv4" and r["value"] == "192.0.2.100" for r in results)

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        results = extract_all_iocs(f"Hash: {h}")
        assert any(r["type"] == "sha256" for r in results)

    def test_md5(self):
        results = extract_all_iocs("MD5: 5d41402abc4b2a76b9719d911017c592")
        assert any(r["type"] == "md5" for r in results)

    def test_domain(self):
        results = extract_all_iocs("C2: malicious.example.com")
        assert any(r["type"] == "domain" and "malicious.example.com" in r["value"] for r in results)

    def test_url(self):
        results = extract_all_iocs("Visit https://evil.example.com/payload")
        assert any(r["type"] == "url" for r in results)

    def test_email(self):
        results = extract_all_iocs("Contact: admin@example.com")
        assert any(r["type"] == "email" for r in results)

    def test_deduplication(self):
        text = "IP 1.2.3.4 appears twice: 1.2.3.4 and 1.2.3.4"
        results = extract_all_iocs(text)
        ipv4_results = [r for r in results if r["type"] == "ipv4"]
        assert len(ipv4_results) == 1


class TestDefangRefang:
    def test_defang_ip(self):
        assert defang("1.2.3.4", "ipv4") == "1[.]2[.]3[.]4"

    def test_defang_domain(self):
        assert defang("evil.com", "domain") == "evil[.]com"

    def test_defang_url(self):
        result = defang("http://evil.com/path", "url")
        assert "hxxp" in result

    def test_refang(self):
        assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
        assert refang("hxxp://evil.com") == "http://evil.com"


class TestIOCExtractorAgent:
    def setup_method(self):
        self.agent = IOCExtractorAgent()
        self.memory = Memory()
        self.memory.findings = [
            Finding(
                id="f1",
                claim="C2 server at 192.0.2.100 was observed",
                detail="The malware communicates with 192.0.2.100 on port 443",
                source_url="https://example.com/report",
                confidence="High",
            ),
            Finding(
                id="f2",
                claim="Dropper hash is 5d41402abc4b2a76b9719d911017c592",
                detail="SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                source_url="https://example.com/analysis",
                confidence="Medium",
            ),
        ]

    @pytest.mark.asyncio
    async def test_regex_extraction(self):
        result = await self.agent.run(self.memory)
        assert result.success is True
        assert len(self.memory.iocs) >= 3  # IP + MD5 + SHA256

    @pytest.mark.asyncio
    async def test_ioc_types(self):
        await self.agent.run(self.memory)
        types = {ioc.ioc_type for ioc in self.memory.iocs}
        assert "ipv4" in types
        assert "md5" in types
        assert "sha256" in types
