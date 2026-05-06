"""Sigma rule export - uses LLM-generated rules from memory, falls back to template-based."""
from __future__ import annotations

import uuid

import yaml

from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso


async def export_sigma(analysis: Analysis) -> tuple[bytes, str]:
    report = analysis.report_md or ""

    # Try to extract LLM-generated sigma rules from report
    rules_text = _extract_sigma_from_report(report)

    if rules_text:
        content = rules_text.encode("utf-8")
    else:
        # Fallback: template-based rules
        rules = _generate_template_rules(report, analysis.id)
        output = ""
        for rule in rules:
            output += yaml.dump(rule, default_flow_style=False, allow_unicode=True)
            output += "---\n"
        content = output.encode("utf-8")

    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.sigma.yml"
    return content, filename


def _extract_sigma_from_report(report: str) -> str:
    """Extract sigma rules section from the markdown report."""
    # Look for sigma section markers
    markers = ["## 检测规则建议", "## Sigma", "## Detection Rules", "## 检测规则"]
    for marker in markers:
        start = report.find(marker)
        if start == -1:
            continue
        # Find the section content
        end = len(report)
        for next_marker in ["## ", "---\n\n"]:
            next_pos = report.find(next_marker, start + len(marker))
            if next_pos > 0:
                end = min(end, next_pos)
        section = report[start:end].strip()
        # Check if it contains YAML-like sigma content
        if "title:" in section or "detection:" in section:
            # Extract just the YAML parts
            lines = []
            in_yaml = False
            for line in section.split("\n"):
                if line.strip().startswith("```yaml"):
                    in_yaml = True
                    continue
                if line.strip().startswith("```") and in_yaml:
                    in_yaml = False
                    continue
                if in_yaml or (line.strip().startswith("title:") or line.strip().startswith("detection:")):
                    lines.append(line)
            if lines:
                return "\n".join(lines)
    return ""


def _generate_template_rules(report: str, analysis_id: str) -> list[dict]:
    """Generate fallback sigma rules based on keyword matching."""
    rules = []
    report_lower = report.lower()

    if "powershell" in report_lower:
        rules.append(_make_sigma_rule(
            title="可疑 PowerShell 执行",
            logsource={"product": "windows", "category": "process_creation"},
            detection={
                "selection": {
                    "Image|endswith": "\\powershell.exe",
                    "CommandLine|contains": ["-EncodedCommand", "IEX"],
                },
                "condition": "selection",
            },
            tags=["attack.execution", "attack.t1059.001"],
            analysis_id=analysis_id,
        ))

    if "wget" in report_lower or "curl" in report_lower:
        rules.append(_make_sigma_rule(
            title="通过命令行下载可疑文件",
            logsource={"product": "linux", "category": "process_creation"},
            detection={
                "selection": {
                    "CommandLine|contains": ["wget", "curl"],
                    "CommandLine|re": "http[s]?://",
                },
                "condition": "selection",
            },
            tags=["attack.command_and_control", "attack.t1105"],
            analysis_id=analysis_id,
        ))

    if "ssh" in report_lower or "brute" in report_lower:
        rules.append(_make_sigma_rule(
            title="SSH 暴力破解尝试",
            logsource={"product": "linux", "category": "authentication"},
            detection={
                "selection": {
                    "action": "failed",
                    "service": "sshd",
                },
                "condition": "selection",
            },
            tags=["attack.credential_access", "attack.t1110"],
            analysis_id=analysis_id,
        ))

    if not rules:
        rules.append(_make_sigma_rule(
            title="威胁情报生成的检测规则（占位）",
            logsource={"product": "windows", "category": "process_creation"},
            detection={"condition": "selection"},
            tags=[],
            analysis_id=analysis_id,
        ))

    return rules


def _make_sigma_rule(
    title: str,
    logsource: dict,
    detection: dict,
    tags: list[str],
    analysis_id: str,
) -> dict:
    return {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": (
            "AI-GENERATED DRAFT - REQUIRES HUMAN REVIEW.\n"
            f"Detection logic derived from threat intel analysis.\n"
            f"Source analysis: {analysis_id}"
        ),
        "author": "Threat Intel Agent (AI-generated)",
        "date": now_iso()[:10].replace("-", "/"),
        "logsource": logsource,
        "detection": detection,
        "falsepositives": ["Legitimate administrative activity"],
        "level": "high",
        "tags": tags,
    }
