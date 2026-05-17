from __future__ import annotations

import json

from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.repository import AssetRepository


async def import_json_assets(
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

    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        _fail(summary, 1, f"JSON 格式错误: {exc.msg}")
        return summary

    hosts = payload.get("hosts") if isinstance(payload, dict) else None
    if not isinstance(hosts, list):
        _fail(summary, 1, "JSON 顶层必须包含 hosts 数组")
        return summary

    row_no = 1
    for host in hosts:
        row_no += 1
        if not isinstance(host, dict):
            _fail(summary, row_no, "host 必须是对象")
            continue
        ip = _clean(host.get("ip"))
        hostname = _clean(host.get("hostname"))
        if not ip and not hostname:
            _fail(summary, row_no, "ip 和 hostname 至少填写一个")
            continue

        services = host.get("services", [])
        if not isinstance(services, list) or not services:
            _fail(summary, row_no, "host.services 必须是非空数组")
            continue

        os_info = host.get("os") if isinstance(host.get("os"), dict) else {}
        for service in services:
            row_no += 1
            if not isinstance(service, dict):
                _fail(summary, row_no, "service 必须是对象")
                continue
            product = _clean(service.get("product"))
            if not product:
                _fail(summary, row_no, "service.product 不能为空")
                continue
            exposures = service.get("exposures", [])
            if not isinstance(exposures, list) or not exposures:
                exposures = [{"port": 0, "protocol": "tcp", "scope": "unknown"}]
            for exposure in exposures:
                row_no += 1
                if not isinstance(exposure, dict):
                    _fail(summary, row_no, "exposure 必须是对象")
                    continue
                try:
                    port = int(exposure.get("port") or 0)
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
                        "os_name": _clean(os_info.get("name")) or _clean(host.get("os_name")),
                        "os_version": _clean(os_info.get("version")) or _clean(host.get("os_version")),
                        "environment": _clean(host.get("environment")) or "unknown",
                        "criticality": _clean(host.get("criticality")) or "medium",
                        "owner": _clean(host.get("owner")),
                        "tags": host.get("tags") if isinstance(host.get("tags"), list) else [],
                        "product": product,
                        "version": _clean(service.get("version")),
                        "vendor": _clean(service.get("vendor")),
                        "provided_cpe": _clean(service.get("cpe")),
                        "port": port,
                        "protocol": (_clean(exposure.get("protocol")) or "tcp").lower(),
                        "exposure_scope": _clean(exposure.get("scope")) or _clean(exposure.get("exposure_scope")) or "unknown",
                        "notes": _clean(exposure.get("notes")) or _clean(host.get("notes")),
                        "source": _clean(payload.get("source")) or "json",
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


def _clean(value: object) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None
