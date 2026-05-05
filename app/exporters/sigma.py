from __future__ import annotations

import uuid

import yaml

from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso


async def export_sigma(analysis: Analysis) -> tuple[bytes, str]:
    report = analysis.report_md or ""

    # Generate placeholder sigma rules based on findings
    rules = []
    if "powershell" in report.lower():
        rules.append(_make_sigma_rule(
            title="Suspicious PowerShell Execution",
            logsource={"product": "windows", "category": "process_creation"},
            detection={
                "selection": {
                    "Image|endswith": "\\powershell.exe",
                    "CommandLine|contains": ["-EncodedCommand", "IEX"],
                },
                "condition": "selection",
            },
            tags=["attack.execution", "attack.t1059.001"],
            analysis_id=analysis.id,
        ))

    if "wget" in report.lower() or "curl" in report.lower():
        rules.append(_make_sigma_rule(
            title="Suspicious Download via Command Line",
            logsource={"product": "linux", "category": "process_creation"},
            detection={
                "selection": {
                    "CommandLine|contains": ["wget", "curl"],
                    "CommandLine|re": "http[s]?://",
                },
                "condition": "selection",
            },
            tags=["attack.command_and_control", "attack.t1105"],
            analysis_id=analysis.id,
        ))

    if not rules:
        rules.append(_make_sigma_rule(
            title="Threat Intel Generated Rule Placeholder",
            logsource={"product": "windows", "category": "process_creation"},
            detection={"condition": "selection"},
            tags=[],
            analysis_id=analysis.id,
        ))

    # Serialize as multi-document YAML
    output = ""
    for rule in rules:
        output += yaml.dump(rule, default_flow_style=False, allow_unicode=True)
        output += "---\n"

    content = output.encode("utf-8")
    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.sigma.yml"
    return content, filename


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
