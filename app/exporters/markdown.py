from __future__ import annotations

import re

from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso


async def export_markdown(analysis: Analysis) -> tuple[bytes, str]:
    report = analysis.report_md or "# No report generated"

    # Add YAML frontmatter
    frontmatter = f"""---
title: "{analysis.query} Threat Intelligence Report"
query: "{analysis.query}"
intent: "{analysis.intent or 'unknown'}"
generated_at: "{analysis.updated_at}"
tlp: "{analysis.tlp}"
overall_confidence: "{analysis.overall_confidence or 'N/A'}"
analysis_id: "{analysis.id}"
token_input: {analysis.token_input}
token_output: {analysis.token_output}
cost_usd: {analysis.cost_usd}
generator: "Threat Intel Agent v0.9.1"
---

"""
    content = frontmatter + report
    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.md"
    return content.encode("utf-8"), filename
