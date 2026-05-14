from __future__ import annotations

import csv
import io

from sqlalchemy import select

from app.db.models import Analysis, IOC, Finding
from app.utils.slug import slugify
from app.utils.time import now_iso


async def export_ioc_csv(
    analysis: Analysis,
    defanged: bool = True,
    min_confidence: str = "Medium",
) -> tuple[bytes, str]:
    from app.db.engine import async_session_factory

    confidence_order = {"High": 3, "Medium": 2, "Low": 1}
    min_level = confidence_order.get(min_confidence, 2)

    async with async_session_factory() as db:
        iocs = (await db.execute(
            select(IOC).where(IOC.analysis_id == analysis.id)
        )).scalars().all()

        # Batch-fetch source_findings for all IOCs in this analysis
        finding_ids = [ioc.source_finding_id for ioc in iocs if ioc.source_finding_id]
        source_url_map: dict[str, str] = {}
        if finding_ids:
            findings = (await db.execute(
                select(Finding).where(Finding.id.in_(finding_ids))
            )).scalars().all()
            source_url_map = {f.id: (f.source_url or "") for f in findings}

    output = io.StringIO()
    output.write("﻿")  # UTF-8 BOM
    writer = csv.writer(output)
    writer.writerow([
        "type", "value", "value_defanged",
        "confidence", "context", "source_url", "first_seen",
    ])

    for ioc in iocs:
        if confidence_order.get(ioc.confidence, 0) < min_level:
            continue

        # When defanged=True (default): value column shows defanged form for
        # safe use in emails / documents.  When defanged=False: value column
        # shows the raw IOC value, suitable for feeding detection systems.
        display_value = ioc.value_defanged if defanged else ioc.value
        source_url = source_url_map.get(ioc.source_finding_id, "")

        writer.writerow([
            ioc.ioc_type,
            display_value,
            ioc.value_defanged,
            ioc.confidence,
            ioc.context or "",
            source_url,
            "",  # first_seen — placeholder, data not yet available
        ])

    content = output.getvalue().encode("utf-8")
    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.iocs.csv"
    return content, filename
