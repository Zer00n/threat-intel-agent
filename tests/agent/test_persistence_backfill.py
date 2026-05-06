from app.agents.memory import Memory
from app.agents.persistence import _extract_attck_from_text, _extract_iocs_from_text


def test_backfill_iocs_and_attck_from_report_text():
    memory = Memory()
    memory.report_md = """
## IOC 清单
- C2 域名: malicious.example.cn
- C2 IP: 203.0.113.10
- SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

## ATT&CK 映射
- T1566 Phishing
"""

    _extract_iocs_from_text(memory)
    _extract_attck_from_text(memory)

    ioc_values = {ioc.value for ioc in memory.iocs}
    technique_ids = {tech.technique_id for tech in memory.attck_techniques}

    assert "malicious.example.cn" in ioc_values
    assert "203.0.113.10" in ioc_values
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in ioc_values
    assert "T1566" in technique_ids

