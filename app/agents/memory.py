from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IntentResult:
    intent: str = "generic"
    entities: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    reasoning_brief: str = ""


@dataclass
class ResearchPlan:
    research_questions: list[str] = field(default_factory=list)
    authoritative_sources: list[str] = field(default_factory=list)
    rationale: str = ""


@dataclass
class Finding:
    id: str = ""
    claim: str = ""
    detail: str = ""
    source_url: str = ""
    source_name: str = ""
    source_type: str = "open"  # authoritative | open | llm_inference
    confidence: str = "Medium"  # High | Medium | Low


@dataclass
class IOC:
    id: str = ""
    ioc_type: str = ""  # ipv4|ipv6|domain|url|md5|sha1|sha256|email|filepath
    value: str = ""
    value_defanged: str = ""
    context: str = ""
    source_finding_id: str = ""
    confidence: str = "Medium"
    is_extracted_by: str = "regex"  # regex | llm


@dataclass
class CVERef:
    id: str = ""
    cve_id: str = ""
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    cpe_matches: list[str] = field(default_factory=list)
    description: str = ""
    is_in_kev: bool = False
    kev_added_date: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None
    source_payload: dict = field(default_factory=dict)


@dataclass
class AttckMapping:
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    confidence: str = "Medium"
    rationale: str = ""


@dataclass
class CriticAction:
    action: str = ""  # drop | downgrade_confidence | flag_in_report
    target_id: str = ""
    reason: str = ""


@dataclass
class CriticResult:
    issues: list[dict[str, Any]] = field(default_factory=list)
    actions: list[CriticAction] = field(default_factory=list)
    overall_assessment: str = "Medium"


@dataclass
class Memory:
    intent: IntentResult = field(default_factory=IntentResult)
    plan: ResearchPlan = field(default_factory=ResearchPlan)
    enrichment: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    cve_refs: list[CVERef] = field(default_factory=list)
    attck_techniques: list[AttckMapping] = field(default_factory=list)
    sources_used: set[str] = field(default_factory=set)
    critic_result: CriticResult | None = None
    report_md: str = ""
    sigma_rules: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_synthesis_context(self) -> str:
        parts = []
        parts.append(f"Intent: {self.intent.intent}")
        parts.append(f"Entities: {self.intent.entities}")

        if self.enrichment:
            parts.append("\n## Authoritative Source Data")
            for src, data in self.enrichment.items():
                if isinstance(data, dict):
                    parts.append(f"\n### {src}")
                    for k, v in data.items():
                        parts.append(f"- {k}: {v}")

        if self.cve_refs:
            parts.append("\n## CVE References")
            for cve in self.cve_refs:
                parts.append(f"- {cve.cve_id}: CVSS={cve.cvss_v3_score}, KEV={cve.is_in_kev}, EPSS={cve.epss_score}")

        if self.findings:
            parts.append("\n## Findings")
            for f in self.findings:
                parts.append(f"- [{f.confidence}] {f.claim} (source: {f.source_name or f.source_url})")

        if self.iocs:
            parts.append(f"\n## IOCs ({len(self.iocs)} total)")
            for ioc in self.iocs[:20]:
                parts.append(f"- {ioc.ioc_type}: {ioc.value_defanged} [{ioc.confidence}]")

        if self.attck_techniques:
            parts.append("\n## ATT&CK Techniques")
            for t in self.attck_techniques:
                parts.append(f"- {t.technique_id} ({t.technique_name}) - {t.tactic} [{t.confidence}]")

        if self.critic_result:
            parts.append(f"\n## Critic Assessment: {self.critic_result.overall_assessment}")
            if self.critic_result.issues:
                parts.append("Issues found:")
                for issue in self.critic_result.issues:
                    parts.append(f"- {issue.get('type', 'unknown')}: {issue.get('description', '')}")

        return "\n".join(parts)
