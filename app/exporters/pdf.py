from __future__ import annotations

from pathlib import Path

from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso

TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates" / "pdf"


async def export_pdf(analysis: Analysis) -> tuple[bytes, str]:
    report_html = _md_to_html(analysis.report_md or "")

    tlp_colors = {
        "WHITE": "#cccccc",
        "GREEN": "#4CAF50",
        "AMBER": "#FF9800",
        "AMBER+STRICT": "#FF5722",
        "RED": "#F44336",
    }
    tlp_color = tlp_colors.get(analysis.tlp, "#4CAF50")

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
@page {{ size: A4; margin: 2cm; @bottom-center {{ content: counter(page); }} }}
body {{ font-family: "Noto Sans CJK SC", "Noto Sans SC", sans-serif; font-size: 11pt; line-height: 1.6; color: #333; }}
.cover {{ text-align: center; padding-top: 120px; page-break-after: always; }}
.cover h1 {{ font-size: 24pt; margin-bottom: 20px; }}
.tlp-badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; background: {tlp_color}; }}
.meta {{ color: #666; font-size: 10pt; margin-top: 30px; }}
h1 {{ font-size: 18pt; border-bottom: 2px solid #333; padding-bottom: 6px; }}
h2 {{ font-size: 14pt; margin-top: 24px; }}
h3 {{ font-size: 12pt; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; font-weight: bold; }}
code {{ background: #f0f0f0; padding: 2px 4px; border-radius: 3px; font-family: "JetBrains Mono", monospace; font-size: 10pt; }}
pre {{ background: #f5f5f5; padding: 12px; border-radius: 4px; overflow-x: auto; }}
blockquote {{ border-left: 4px solid #ddd; margin: 12px 0; padding: 8px 16px; color: #666; }}
details {{ border: 1px solid #ddd; border-radius: 4px; padding: 8px; margin: 8px 0; }}
details summary {{ cursor: pointer; font-weight: bold; }}
</style>
</head>
<body>
<div class="cover">
<h1>Threat Intelligence Report</h1>
<p style="font-size: 16pt;">{analysis.query}</p>
<p><span class="tlp-badge">TLP: {analysis.tlp}</span></p>
<div class="meta">
<p>Generated: {analysis.updated_at}</p>
<p>Intent: {analysis.intent or 'N/A'}</p>
<p>Confidence: {analysis.overall_confidence or 'N/A'}</p>
<p>Generator: Threat Intel Agent v0.1</p>
</div>
</div>
{report_html}
</body>
</html>"""

    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html).write_pdf()
    except Exception:
        # Fallback: return HTML as PDF placeholder
        pdf_bytes = html.encode("utf-8")

    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.pdf"
    return pdf_bytes, filename


def _md_to_html(md: str) -> str:
    try:
        from markdown_it import MarkdownIt
        md_parser = MarkdownIt("commonmark", {"html": True}).enable("table")
        return md_parser.render(md)
    except Exception:
        return f"<pre>{md}</pre>"
