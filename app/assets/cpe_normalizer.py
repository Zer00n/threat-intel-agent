from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import CpeDictionary


@dataclass
class CpeNormalization:
    cpe: str | None
    confidence: str
    vendor: str | None = None


_VENDOR_ALIASES = {
    "nginx": "nginx",
    "openssh": "openbsd",
    "ssh": "openbsd",
    "mysql": "oracle",
    "apache": "apache",
    "httpd": "apache",
    "tomcat": "apache",
    "redis": "redis",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "php": "php",
    "jenkins": "jenkins",
}

_PRODUCT_ALIASES = {
    "httpd": "http_server",
    "apache": "http_server",
    "ssh": "openssh",
    "postgres": "postgresql",
}


async def normalize_cpe(
    db: AsyncSession,
    product: str,
    version: str | None = None,
    vendor: str | None = None,
    provided_cpe: str | None = None,
) -> CpeNormalization:
    if provided_cpe:
        return CpeNormalization(_to_cpe23(provided_cpe), "high", vendor)

    product_norm = _norm(product)
    version_norm = _clean_version(version)
    vendor_norm = _norm(vendor) if vendor else _VENDOR_ALIASES.get(product_norm, product_norm)

    exact = await _lookup_dictionary(db, product_norm, version_norm, vendor_norm)
    if exact:
        return CpeNormalization(exact.cpe, "high", exact.vendor)

    product_cpe = _PRODUCT_ALIASES.get(product_norm, product_norm)
    generated = _make_cpe(vendor_norm, product_cpe, version_norm)
    confidence = "medium" if version_norm else "low"
    return CpeNormalization(generated, confidence, vendor_norm)


async def _lookup_dictionary(
    db: AsyncSession,
    product: str,
    version: str | None,
    vendor: str | None,
) -> CpeDictionary | None:
    if not product:
        return None

    stmt = select(CpeDictionary).where(
        CpeDictionary.deprecated == False,  # noqa: E712
        or_(
            CpeDictionary.product == product,
            CpeDictionary.product == _PRODUCT_ALIASES.get(product, product),
        ),
    )
    if vendor:
        stmt = stmt.where(CpeDictionary.vendor == vendor)
    if version:
        stmt = stmt.where(CpeDictionary.version == version)
    result = await db.execute(stmt.limit(1))
    return result.scalar_one_or_none()


def _make_cpe(vendor: str, product: str, version: str | None) -> str:
    version_part = version or "*"
    return f"cpe:2.3:a:{vendor or '*'}:{product}:{version_part}:*:*:*:*:*:*:*"


def _to_cpe23(cpe: str) -> str:
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if cpe.startswith("cpe:/"):
        # Best-effort conversion for nmap CPE 2.2 values, e.g. cpe:/a:nginx:nginx:1.18.0
        parts = cpe[5:].split(":")
        while len(parts) < 5:
            parts.append("*")
        part, vendor, product, version = parts[:4]
        return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return cpe


def _norm(value: str | None) -> str:
    if not value:
        return ""
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "_", value)
    return value.strip("_")


def _clean_version(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    value = re.sub(r"^[vV]", "", value)
    return value or None

