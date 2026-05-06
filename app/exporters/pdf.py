"""PDF export using xhtml2pdf (pure Python, no system dependencies)."""
from __future__ import annotations

import re

from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso


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
@page {{
    size: A4;
    margin: 2cm 2.5cm;
}}
body {{
    font-family: Helvetica, "Noto Sans CJK SC", "SimSun", sans-serif;
    font-size: 10pt;
    line-height: 1.6;
    color: #1a1a1a;
}}
.cover {{
    text-align: center;
    padding-top: 100px;
    page-break-after: always;
}}
.cover h1 {{
    font-size: 22pt;
    color: #cc785c;
    margin-bottom: 16px;
    border: none;
}}
.cover .query {{
    font-size: 14pt;
    color: #333;
    margin-bottom: 24px;
}}
.tlp-badge {{
    display: inline-block;
    padding: 4px 16px;
    border-radius: 4px;
    color: white;
    font-weight: bold;
    background: {tlp_color};
    font-size: 10pt;
}}
.confidence-badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 10pt;
    margin-left: 8px;
}}
.confidence-High {{ background: #4CAF50; color: white; }}
.confidence-Medium {{ background: #FF9800; color: white; }}
.confidence-Low {{ background: #F44336; color: white; }}
.meta {{
    color: #666;
    font-size: 9pt;
    margin-top: 30px;
    line-height: 1.8;
}}
.meta strong {{ color: #333; }}
h1 {{
    font-size: 16pt;
    color: #cc785c;
    border-bottom: 2px solid #cc785c;
    padding-bottom: 6px;
    margin-top: 24px;
}}
h2 {{
    font-size: 13pt;
    color: #333;
    margin-top: 20px;
    border-bottom: 1px solid #e0e0e0;
    padding-bottom: 4px;
}}
h3 {{
    font-size: 11pt;
    color: #555;
    margin-top: 16px;
}}
table {{
    border-collapse: collapse;
    width: 100%;
    margin: 10px 0;
    font-size: 9pt;
}}
th, td {{
    border: 1px solid #ddd;
    padding: 6px 8px;
    text-align: left;
}}
th {{
    background: #f5f0e8;
    font-weight: bold;
    color: #333;
}}
tr:nth-child(even) td {{
    background: #fafafa;
}}
code {{
    background: #f5f0e8;
    padding: 1px 5px;
    border-radius: 3px;
    font-family: "Courier New", monospace;
    font-size: 9pt;
    color: #c0392b;
}}
pre {{
    background: #1a1a2e;
    color: #e0e0e0;
    padding: 12px;
    border-radius: 4px;
    font-family: "Courier New", monospace;
    font-size: 8.5pt;
    line-height: 1.5;
    margin: 10px 0;
}}
pre code {{
    background: transparent;
    color: inherit;
    padding: 0;
}}
blockquote {{
    border-left: 3px solid #cc785c;
    margin: 10px 0;
    padding: 6px 12px;
    color: #666;
    background: #faf9f5;
}}
ul, ol {{
    margin: 8px 0;
    padding-left: 20px;
}}
li {{
    margin-bottom: 4px;
}}
hr {{
    border: none;
    border-top: 1px solid #e0e0e0;
    margin: 16px 0;
}}
strong {{ color: #1a1a1a; }}
details {{
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 8px;
    margin: 8px 0;
}}
details summary {{
    font-weight: bold;
    cursor: pointer;
}}
</style>
</head>
<body>
<div class="cover">
<h1>威胁情报分析报告</h1>
<p class="query">{analysis.query}</p>
<p>
<span class="tlp-badge">TLP: {analysis.tlp}</span>
{f'<span class="confidence-badge confidence-{analysis.overall_confidence}">{analysis.overall_confidence}</span>' if analysis.overall_confidence else ''}
</p>
<div class="meta">
<p><strong>生成时间：</strong>{analysis.updated_at}</p>
<p><strong>意图分类：</strong>{analysis.intent or 'N/A'}</p>
<p><strong>耗时：</strong>{analysis.duration_s or 0} 秒</p>
<p><strong>令牌消耗：</strong>{analysis.token_input or 0} 输入 / {analysis.token_output or 0} 输出</p>
<p><strong>费用：</strong>${analysis.cost_usd or 0:.4f}</p>
<p><strong>生成器：</strong>Threat Intel Agent v0.1</p>
</div>
</div>
{report_html}
</body>
</html>"""

    from xhtml2pdf import pisa
    pdf_bytes = io.BytesIO()
    pisa.CreatePDF(html, dest=pdf_bytes, encoding="utf-8")
    content = pdf_bytes.getvalue()

    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.pdf"
    return content, filename


def _md_to_html(md: str) -> str:
    """Convert markdown to HTML using simple regex-based parser."""
    if not md:
        return "<p>无报告内容</p>"

    lines = md.split("\n")
    html_lines = []
    in_code_block = False
    in_table = False
    table_header_done = False

    for line in lines:
        stripped = line.strip()

        # Code blocks
        if stripped.startswith("```"):
            if in_code_block:
                html_lines.append("</code></pre>")
                in_code_block = False
            else:
                lang = stripped[3:].strip()
                html_lines.append(f'<pre><code class="language-{lang}">')
                in_code_block = True
            continue

        if in_code_block:
            html_lines.append(_escape_html(line))
            continue

        # Tables
        if "|" in stripped and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(set(c) <= set("- :") for c in cells):
                # Separator row
                table_header_done = True
                continue
            if not in_table:
                html_lines.append("<table>")
                in_table = True
            if not table_header_done:
                html_lines.append("<tr>" + "".join(f"<th>{_inline_md(c)}</th>" for c in cells) + "</tr>")
            else:
                html_lines.append("<tr>" + "".join(f"<td>{_inline_md(c)}</td>" for c in cells) + "</tr>")
            continue
        elif in_table:
            html_lines.append("</table>")
            in_table = False
            table_header_done = False

        # Headers
        if stripped.startswith("# "):
            html_lines.append(f"<h1>{_inline_md(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            html_lines.append(f"<h2>{_inline_md(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            html_lines.append(f"<h3>{_inline_md(stripped[4:])}</h3>")
        elif stripped.startswith("#### "):
            html_lines.append(f"<h3>{_inline_md(stripped[5:])}</h3>")
        # Horizontal rule
        elif stripped in ("---", "***", "___"):
            html_lines.append("<hr>")
        # Blockquote
        elif stripped.startswith("> "):
            html_lines.append(f"<blockquote><p>{_inline_md(stripped[2:])}</p></blockquote>")
        # Unordered list
        elif stripped.startswith("- ") or stripped.startswith("* "):
            html_lines.append(f"<li>{_inline_md(stripped[2:])}</li>")
        # Ordered list
        elif len(stripped) > 2 and stripped[0].isdigit() and ". " in stripped[:5]:
            content = stripped.split(". ", 1)[1] if ". " in stripped else stripped
            html_lines.append(f"<li>{_inline_md(content)}</li>")
        # Details/summary
        elif stripped.startswith("<details"):
            html_lines.append(stripped)
        elif stripped.startswith("</details"):
            html_lines.append(stripped)
        elif stripped.startswith("<summary"):
            html_lines.append(stripped)
        elif stripped.startswith("</summary"):
            html_lines.append(stripped)
        # Empty line
        elif not stripped:
            html_lines.append("<br>")
        # Paragraph
        else:
            html_lines.append(f"<p>{_inline_md(stripped)}</p>")

    if in_table:
        html_lines.append("</table>")
    if in_code_block:
        html_lines.append("</code></pre>")

    return "\n".join(html_lines)


def _inline_md(text: str) -> str:
    """Convert inline markdown (bold, italic, code, links) to HTML."""
    text = _escape_html(text)
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"__(.+?)__", r"<strong>\1</strong>", text)
    # Italic
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    text = re.sub(r"_(.+?)_", r"<em>\1</em>", text)
    # Inline code
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    # Links
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2">\1</a>', text)
    return text


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


import io
