from __future__ import annotations

import re

IPv4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

IPv6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
)

MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")

SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")

SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b"
)

URL = re.compile(r"https?://[^\s<>\"']+")

EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

FILEPATH_WIN = re.compile(r"[A-Z]:\\(?:[^\\/:*?\"<>|\s]+\\)*[^\\/:*?\"<>|\s]+", re.IGNORECASE)
FILEPATH_UNIX = re.compile(r"/(?:[^/\s]+/)*[^/\s]+")

# RFC1918 private ranges to optionally filter
PRIVATE_IP = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
)

KNOWN_FALSE_POSITIVES = {
    "example.com", "example.org", "example.net",
    "localhost", "schema.org", "www.w3.org",
}


def extract_all_iocs(text: str) -> list[dict[str, str]]:
    results = []
    seen = set()

    for m in SHA256.finditer(text):
        v = m.group().lower()
        if v not in seen:
            seen.add(v)
            results.append({"type": "sha256", "value": v})

    for m in SHA1.finditer(text):
        v = m.group().lower()
        if v not in seen:
            seen.add(v)
            results.append({"type": "sha1", "value": v})

    for m in MD5.finditer(text):
        v = m.group().lower()
        if v not in seen and v not in {r["value"] for r in results if r["type"] == "sha256"}:
            seen.add(v)
            results.append({"type": "md5", "value": v})

    for m in IPv4.finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            results.append({"type": "ipv4", "value": v})

    for m in IPv6.finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            results.append({"type": "ipv6", "value": v})

    for m in EMAIL.finditer(text):
        v = m.group().lower()
        if v not in seen:
            seen.add(v)
            results.append({"type": "email", "value": v})

    for m in URL.finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            results.append({"type": "url", "value": v})

    for m in DOMAIN.finditer(text):
        v = m.group().lower()
        if v not in seen and v not in KNOWN_FALSE_POSITIVES:
            seen.add(v)
            results.append({"type": "domain", "value": v})

    return results
