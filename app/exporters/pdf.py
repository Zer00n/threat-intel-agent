"""PDF export using reportlab with Noto Sans SC CJK font."""
from __future__ import annotations

import os
import re
import urllib.request

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from app.config import settings
from app.db.models import Analysis
from app.utils.slug import slugify
from app.utils.time import now_iso

# CJK font path and download URL
_FONT_DIR = os.path.join(settings.data_dir, "fonts")
_FONT_FILE = os.path.join(_FONT_DIR, "NotoSansSC-Regular.ttf")
_FONT_URL = "https://fonts.gstatic.com/s/notosanssc/v40/k3kCo84MPvpLmixcA63oeAL7Iqp5IZJF9bmaG9_FnYw.ttf"
_FONT_NAME = "NotoSansSC"


def _ensure_font() -> str:
    """Download CJK font on first use if not present."""
    if os.path.exists(_FONT_FILE):
        return _FONT_FILE
    os.makedirs(_FONT_DIR, exist_ok=True)
    proxy_url = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if proxy_url:
        proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = urllib.request.build_opener(proxy_handler)
    else:
        opener = urllib.request.build_opener()
    resp = opener.open(_FONT_URL)
    with open(_FONT_FILE, "wb") as f:
        f.write(resp.read())
    resp.close()
    return _FONT_FILE


# Register CJK font
_font_path = _ensure_font()
pdfmetrics.registerFont(TTFont(_FONT_NAME, _font_path))

_CJK = _FONT_NAME


def _h(r: int, g: int, b: int) -> colors.Color:
    return colors.Color(r / 255, g / 255, b / 255)


async def export_pdf(analysis: Analysis) -> tuple[bytes, str]:
    import io

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2.5 * cm,
        rightMargin=2.5 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    story = []
    styles = _build_styles()

    # --- Cover page ---
    story.append(Spacer(1, 60))
    story.append(Paragraph("威胁情报分析报告", styles["cover_title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(_esc(analysis.query or ""), styles["cover_query"]))
    story.append(Spacer(1, 10))

    # TLP + confidence badges
    badge_parts = [f'<font color="white"><b>TLP: {analysis.tlp or "GREEN"}</b></font>']
    if analysis.overall_confidence:
        badge_parts.append(
            f'<font color="white"><b>{analysis.overall_confidence}</b></font>'
        )
    story.append(Paragraph("  ".join(badge_parts), styles["badges"]))
    story.append(Spacer(1, 30))

    # Meta info
    meta_lines = [
        f"生成时间：{analysis.updated_at or 'N/A'}",
        f"意图分类：{analysis.intent or 'N/A'}",
        f"耗时：{analysis.duration_s or 0} 秒",
        f"令牌消耗：{analysis.token_input or 0} 输入 / {analysis.token_output or 0} 输出",
        f"费用：￥{analysis.cost_usd or 0:.4f}",
        "生成器：Threat Intel Agent v0.9.1",
    ]
    for line in meta_lines:
        story.append(Paragraph(_esc(line), styles["meta"]))

    # --- Report body ---
    story.append(PageBreak())
    _render_report(story, analysis.report_md or "", styles)

    doc.build(story)
    content = buf.getvalue()

    now = now_iso().replace(":", "").replace("-", "").replace("T", "-")[:13]
    filename = f"ti-{analysis.intent or 'unknown'}-{slugify(analysis.query)}-{now}.pdf"
    return content, filename


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title",
            parent=base["Title"],
            fontName=_CJK,
            fontSize=22,
            textColor=_h(204, 120, 92),
            alignment=1,
            spaceAfter=12,
        ),
        "cover_query": ParagraphStyle(
            "cover_query",
            parent=base["Normal"],
            fontName=_CJK,
            fontSize=14,
            textColor=_h(51, 51, 51),
            alignment=1,
            spaceAfter=10,
        ),
        "badges": ParagraphStyle(
            "badges",
            parent=base["Normal"],
            fontName=_CJK,
            fontSize=10,
            alignment=1,
            spaceAfter=10,
            backColor=_h(76, 175, 80),
            borderPadding=4,
        ),
        "meta": ParagraphStyle(
            "meta",
            parent=base["Normal"],
            fontName=_CJK,
            fontSize=9,
            textColor=_h(102, 102, 102),
            leading=14,
        ),
        "h1": ParagraphStyle(
            "h1",
            parent=base["Heading1"],
            fontName=_CJK,
            fontSize=16,
            textColor=_h(204, 120, 92),
            spaceBefore=20,
            spaceAfter=8,
            borderWidth=0,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontName=_CJK,
            fontSize=13,
            textColor=_h(51, 51, 51),
            spaceBefore=16,
            spaceAfter=6,
            borderWidth=0,
        ),
        "h3": ParagraphStyle(
            "h3",
            parent=base["Heading3"],
            fontName=_CJK,
            fontSize=11,
            textColor=_h(85, 85, 85),
            spaceBefore=12,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontName=_CJK,
            fontSize=10,
            textColor=_h(26, 26, 26),
            leading=16,
            spaceBefore=2,
            spaceAfter=4,
        ),
        "code_block": ParagraphStyle(
            "code_block",
            parent=base["Code"],
            fontName=_CJK,
            fontSize=8.5,
            textColor=_h(51, 51, 51),
            backColor=_h(245, 245, 245),
            borderWidth=0.5,
            borderColor=_h(200, 200, 200),
            borderPadding=6,
            spaceBefore=6,
            spaceAfter=6,
            leading=12,
        ),
        "blockquote": ParagraphStyle(
            "blockquote",
            parent=base["Normal"],
            fontName=_CJK,
            fontSize=10,
            textColor=_h(102, 102, 102),
            leftIndent=16,
            borderWidth=0,
            borderPadding=4,
            spaceBefore=4,
            spaceAfter=4,
        ),
    }


def _render_report(story: list, md: str, styles: dict) -> None:
    if not md:
        story.append(Paragraph("无报告内容", styles["body"]))
        return

    lines = md.split("\n")
    in_code = False
    code_buf: list[str] = []
    in_table = False
    table_rows: list[list[str]] = []
    table_header_done = False

    def flush_table():
        nonlocal in_table, table_rows, table_header_done
        if not table_rows:
            return
        ncols = max(len(r) for r in table_rows)
        padded = [r + [""] * (ncols - len(r)) for r in table_rows]
        t = Table(padded, colWidths=[doc_width / ncols] * ncols)
        ts = TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), _CJK),
            ("FONTNAME", (0, 1), (-1, -1), _CJK),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), _h(245, 240, 232)),
            ("TEXTCOLOR", (0, 0), (-1, 0), _h(51, 51, 51)),
            ("GRID", (0, 0), (-1, -1), 0.5, _h(221, 221, 221)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ])
        for i in range(1, len(padded), 2):
            ts.add("BACKGROUND", (0, i), (-1, i), _h(250, 250, 250))
        t.setStyle(ts)
        story.append(t)
        story.append(Spacer(1, 6))
        table_rows = []
        in_table = False
        table_header_done = False

    doc_width = A4[0] - 5 * cm  # usable width

    for line in lines:
        stripped = line.strip()

        # Code blocks
        if stripped.startswith("```"):
            if in_code:
                code_text = _esc("\n".join(code_buf))
                story.append(Paragraph(code_text.replace("\n", "<br/>"), styles["code_block"]))
                code_buf = []
                in_code = False
            else:
                flush_table()
                in_code = True
            continue

        if in_code:
            code_buf.append(line)
            continue

        # Tables
        if "|" in stripped and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(set(c) <= set("- :") for c in cells):
                table_header_done = True
                continue
            if not in_table:
                in_table = True
            if not table_header_done:
                table_rows.append([_inline_to_para(c, styles) for c in cells])
            else:
                table_rows.append([_inline_to_para(c, styles) for c in cells])
            continue
        else:
            flush_table()

        # Headers
        if stripped.startswith("# "):
            story.append(Paragraph(_inline_md(stripped[2:]), styles["h1"]))
        elif stripped.startswith("## "):
            story.append(Paragraph(_inline_md(stripped[3:]), styles["h2"]))
        elif stripped.startswith("### "):
            story.append(Paragraph(_inline_md(stripped[4:]), styles["h3"]))
        elif stripped.startswith("#### "):
            story.append(Paragraph(_inline_md(stripped[5:]), styles["h3"]))
        # HR
        elif stripped in ("---", "***", "___"):
            story.append(Spacer(1, 8))
        # Blockquote
        elif stripped.startswith("> "):
            story.append(Paragraph(_inline_md(stripped[2:]), styles["blockquote"]))
        # List items
        elif stripped.startswith("- ") or stripped.startswith("* "):
            story.append(Paragraph(f"&bull; {_inline_md(stripped[2:])}", styles["body"]))
        elif len(stripped) > 2 and stripped[0].isdigit() and ". " in stripped[:5]:
            content = stripped.split(". ", 1)[1] if ". " in stripped else stripped
            story.append(Paragraph(f"{_inline_md(content)}", styles["body"]))
        # Skip empty lines
        elif not stripped:
            pass
        # Details/summary (render as text)
        elif stripped.startswith("<details") or stripped.startswith("</details"):
            continue
        elif stripped.startswith("<summary"):
            text = re.sub(r"</?summary[^>]*>", "", stripped)
            if text.strip():
                story.append(Paragraph(_inline_md(text.strip()), styles["h3"]))
        elif stripped.startswith("</summary"):
            continue
        # Paragraph
        else:
            story.append(Paragraph(_inline_md(stripped), styles["body"]))

    flush_table()
    if in_code:
        code_text = _esc("\n".join(code_buf))
        story.append(Paragraph(code_text.replace("\n", "<br/>"), styles["code_block"]))


def _inline_to_para(text: str, styles: dict) -> Paragraph:
    return Paragraph(_inline_md(text), styles["body"])


def _inline_md(text: str) -> str:
    text = _esc(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"__(.+?)__", r"<b>\1</b>", text)
    text = re.sub(r"\*(.+?)\*", r"<i>\1</i>", text)
    text = re.sub(r"_(.+?)_", r"<i>\1</i>", text)
    text = re.sub(r"`(.+?)`", r'<font color="#c0392b">\1</font>', text)
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2" color="#2563EB">\1</a>', text)
    return text


def _esc(text: str) -> str:
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )
