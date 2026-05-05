from __future__ import annotations

import io
import zipfile

from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso


async def export_zip(analysis: Analysis) -> tuple[bytes, str]:
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Markdown
        from app.exporters.markdown import export_markdown
        md_content, md_name = await export_markdown(analysis)
        zf.writestr(md_name, md_content)

        # STIX
        from app.exporters.stix import export_stix
        stix_content, stix_name = await export_stix(analysis)
        zf.writestr(stix_name, stix_content)

        # IOC CSV
        from app.exporters.ioc_csv import export_ioc_csv
        csv_content, csv_name = await export_ioc_csv(analysis)
        zf.writestr(csv_name, csv_content)

        # Sigma
        from app.exporters.sigma import export_sigma
        sigma_content, sigma_name = await export_sigma(analysis)
        zf.writestr(sigma_name, sigma_content)

    content = buf.getvalue()
    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.zip"
    return content, filename
