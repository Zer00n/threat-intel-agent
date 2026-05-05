from __future__ import annotations

import csv
import io

from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso


async def export_ioc_csv(
    analysis: Analysis,
    defanged: bool = True,
    min_confidence: str = "Medium",
) -> tuple[bytes, str]:
    from app.db.engine import async_session_factory
    from sqlalchemy import select
    from app.db.models import IOC

    confidence_order = {"High": 3, "Medium": 2, "Low": 1}
    min_level = confidence_order.get(min_confidence, 2)

    async with async_session_factory() as db:
        iocs = (await db.execute(
            select(IOC).where(IOC.analysis_id == analysis.id)
        )).scalars().all()

    output = io.StringIO()
    output.write("﻿")  # UTF-8 BOM
    writer = csv.writer(output)
    writer.writerow(["type", "value", "value_defanged", "confidence", "context", "source_url"])

    for ioc in iocs:
        if confidence_order.get(ioc.confidence, 0) < min_level:
            continue
        value = ioc.value_defanged if defanged else ioc.value
        writer.writerow([
            ioc.ioc_type,
            ioc.value,
            ioc.value_defanged,
            ioc.confidence,
            ioc.context or "",
            "",
        ])

    content = output.getvalue().encode("utf-8")
    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.iocs.csv"
    return content, filename
