from __future__ import annotations

import csv
import io

from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.repository import AssetRepository

REQUIRED_COLUMNS = {"product"}


async def import_csv_assets(
    db: AsyncSession,
    space_id: str,
    content: str,
    filename: str | None = None,
) -> dict:
    repo = AssetRepository(db)
    summary = {
        "hosts_created": 0,
        "hosts_updated": 0,
        "services_created": 0,
        "services_updated": 0,
        "exposures_created": 0,
        "exposures_updated": 0,
        "failed_rows": 0,
        "failed_reasons": [],
        "cpe_normalization": {"high": 0, "medium": 0, "low": 0, "unknown": 0},
    }

    stream = io.StringIO(content.lstrip("\ufeff"))
    reader = csv.DictReader(stream)
    if not reader.fieldnames:
        summary["failed_rows"] = 1
        summary["failed_reasons"].append({"row": 1, "reason": "CSV 为空或缺少表头"})
        return summary

    missing = sorted(REQUIRED_COLUMNS - set(reader.fieldnames))
    if missing:
        summary["failed_rows"] = 1
        summary["failed_reasons"].append({"row": 1, "reason": f"缺少必填列: {', '.join(missing)}"})
        return summary

    for row_no, row in enumerate(reader, start=2):
        ip = _clean(row.get("ip"))
        hostname = _clean(row.get("hostname"))
        product = _clean(row.get("product"))
        if not ip and not hostname:
            _fail(summary, row_no, "ip 和 hostname 至少填写一个")
            continue
        if not product:
            _fail(summary, row_no, "product 不能为空")
            continue
        try:
            port = int(_clean(row.get("port")) or 0)
            if port <= 0 or port > 65535:
                raise ValueError
        except ValueError:
            _fail(summary, row_no, "端口必须是 1-65535 的整数")
            continue

        result = await repo.upsert_asset_row(
            space_id=space_id,
            row={
                "ip": ip,
                "hostname": hostname,
                "os_name": _clean(row.get("os_name")),
                "os_version": _clean(row.get("os_version")),
                "environment": _clean(row.get("environment")) or "unknown",
                "criticality": _clean(row.get("criticality")) or "medium",
                "owner": _clean(row.get("owner")),
                "tags": _parse_tags(row.get("tags")),
                "product": product,
                "version": _clean(row.get("version")),
                "vendor": _clean(row.get("vendor")),
                "port": port,
                "protocol": (_clean(row.get("protocol")) or "tcp").lower(),
                "exposure_scope": _clean(row.get("exposure_scope")) or "unknown",
                "notes": _clean(row.get("notes")),
                "source": "csv",
                "source_filename": filename,
            },
        )
        for key in ("hosts_created", "hosts_updated", "services_created", "services_updated", "exposures_created", "exposures_updated"):
            summary[key] += result.get(key, 0)
        conf = result.get("cpe_confidence") or "unknown"
        summary["cpe_normalization"][conf] = summary["cpe_normalization"].get(conf, 0) + 1

    await db.commit()
    return summary


def _fail(summary: dict, row: int, reason: str) -> None:
    summary["failed_rows"] += 1
    if len(summary["failed_reasons"]) < 5:
        summary["failed_reasons"].append({"row": row, "reason": reason})


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _parse_tags(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]

