from __future__ import annotations

import json
import uuid

from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso


async def export_stix(analysis: Analysis) -> tuple[bytes, str]:
    bundle_id = f"bundle--{uuid.uuid4()}"
    now = now_iso()
    objects = []
    relationships = []

    # TLP marking (must be first)
    tlp_map = {
        "WHITE": "tlp:white",
        "GREEN": "tlp:green",
        "AMBER": "tlp:amber",
        "AMBER+STRICT": "tlp:amber+strict",
        "RED": "tlp:red",
    }
    marking_id = f"marking-definition--{uuid.uuid4()}"
    objects.append({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": now,
        "definition_type": "tlp",
        "definition": {"tlp": tlp_map.get(analysis.tlp, "tlp:green")},
    })

    # Collect related IDs for report
    object_refs = []

    from app.db.engine import async_session_factory
    from sqlalchemy import select
    from app.db.models import IOC, CVERef, AttackTechnique

    async with async_session_factory() as db:
        # Add IOC indicators
        iocs = (await db.execute(select(IOC).where(IOC.analysis_id == analysis.id))).scalars().all()
        for ioc in iocs:
            ind_id = f"indicator--{uuid.uuid4()}"
            pattern = _ioc_to_stix_pattern(ioc.ioc_type, ioc.value)
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now,
                "modified": now,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "labels": [ioc.ioc_type],
                "indicator_types": ["malicious-activity"],
            })
            object_refs.append(ind_id)

        # Add CVE vulnerabilities
        cve_ids_map = {}  # cve_id -> stix_id
        cves = (await db.execute(select(CVERef).where(CVERef.analysis_id == analysis.id))).scalars().all()
        for cve in cves:
            vuln_id = f"vulnerability--{uuid.uuid4()}"
            cve_ids_map[cve.cve_id] = vuln_id
            objects.append({
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vuln_id,
                "created": now,
                "modified": now,
                "name": cve.cve_id,
                "description": cve.description or "",
                "external_references": [{"source_name": "cve", "external_id": cve.cve_id}],
            })
            object_refs.append(vuln_id)

        # Add ATT&CK attack patterns
        tech_ids_map = {}  # technique_id -> stix_id
        techniques = (await db.execute(select(AttackTechnique).where(AttackTechnique.analysis_id == analysis.id))).scalars().all()
        for tech in techniques:
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            tech_ids_map[tech.technique_id] = ap_id
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": tech.technique_name or tech.technique_id,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": tech.technique_id}
                ],
            })
            object_refs.append(ap_id)

        # Add threat-actor if intent is threat_actor (PRD §FR-29)
        if analysis.intent == "threat_actor" and analysis.query:
            actor_id = f"threat-actor--{uuid.uuid4()}"
            objects.append({
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": now,
                "modified": now,
                "name": analysis.query,
                "threat_actor_types": ["crime-syndicate", "nation-state"],
                "description": f"Threat actor identified in analysis {analysis.id}",
            })
            object_refs.append(actor_id)

            # Relationship: threat-actor uses attack-patterns
            for tech_id, ap_stix_id in tech_ids_map.items():
                rel_id = f"relationship--{uuid.uuid4()}"
                relationships.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": actor_id,
                    "target_ref": ap_stix_id,
                })

        # Relationships: indicators indicate vulnerabilities
        for ind_obj in [o for o in objects if o["type"] == "indicator"]:
            for vuln_obj in [o for o in objects if o["type"] == "vulnerability"]:
                rel_id = f"relationship--{uuid.uuid4()}"
                relationships.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": ind_obj["id"],
                    "target_ref": vuln_obj["id"],
                })

        # Relationships: attack-patterns related-to vulnerabilities
        for ap_obj in [o for o in objects if o["type"] == "attack-pattern"]:
            for vuln_obj in [o for o in objects if o["type"] == "vulnerability"]:
                rel_id = f"relationship--{uuid.uuid4()}"
                relationships.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "related-to",
                    "source_ref": ap_obj["id"],
                    "target_ref": vuln_obj["id"],
                })

    # Add all relationships to objects
    objects.extend(relationships)

    # Report SDO (last, references all other objects)
    report_id = f"report--{uuid.uuid4()}"
    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "name": f"{analysis.query} Threat Intel Report",
        "report_types": ["threat-report"],
        "object_refs": object_refs,
        "lang": "en",
    })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }

    content = json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8")
    now_str = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now_str}.stix.json"
    return content, filename


def _ioc_to_stix_pattern(ioc_type: str, value: str) -> str:
    type_map = {
        "ipv4": "ipv4-addr",
        "ipv6": "ipv6-addr",
        "domain": "domain-name",
        "url": "url",
        "md5": "file:hashes.MD5",
        "sha1": "file:hashes.'SHA-1'",
        "sha256": "file:hashes.'SHA-256'",
        "email": "email-addr",
    }
    stix_type = type_map.get(ioc_type, "artifact")
    if ioc_type in ("md5", "sha1", "sha256"):
        hash_name = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}[ioc_type]
        return f"[file:hashes.'{hash_name}' = '{value}']"
    return f"[{stix_type}:value = '{value}']"
