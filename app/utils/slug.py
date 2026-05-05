from __future__ import annotations

import re
import unicodedata


_SLUG_SAFE = re.compile(r"[^a-z0-9\-]")


def slugify(text: str, max_len: int = 30) -> str:
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.lower()
    text = _SLUG_SAFE.sub("-", text)
    text = re.sub(r"-{2,}", "-", text)
    text = text.strip("-")
    if len(text) > max_len:
        text = text[:max_len].rstrip("-")
    return text or "query"


def safe_filename(intent: str, query: str, date_str: str, ext: str) -> str:
    s = slugify(query)
    return f"ti-{intent}-{s}-{date_str}.{ext}"
