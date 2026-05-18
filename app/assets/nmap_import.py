from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.repository import AssetRepository


async def import_nmap_assets(
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
        root = ET.fromstring(content.lstrip("\ufeff"))
    except ET.ParseError as exc:
        _fail(summary, 1, f"XML 格式错误: {exc}")
        return summary

    hosts = root.findall(".//host")
    if not hosts:
        _fail(summary, 1, "未找到 nmap host 节点")
        return summary

    row_no = 1
    for host_el in hosts:
        row_no += 1
        ip = _host_ip(host_el)
        hostname = _host_name(host_el)
        if not ip and not hostname:
            _fail(summary, row_no, "host 缺少 address 和 hostname")
            continue

        os_name, os_version = _host_os(host_el)
        port_els = host_el.findall("./ports/port")
        if not port_els:
            _fail(summary, row_no, "host 缺少开放端口")
            continue

        for port_el in port_els:
            row_no += 1
            state = port_el.find("./state")
            if state is not None and state.get("state") not in (None, "open"):
                continue
            service_el = port_el.find("./service")
            product = _service_product(service_el, port_el)
            if not product:
                _fail(summary, row_no, "port 缺少 service name/product")
                continue
            try:
                port = int(port_el.get("portid") or 0)
                if port <= 0 or port > 65535:
                    raise ValueError
            except ValueError:
                _fail(summary, row_no, "portid 必须是 1-65535 的整数")
                continue

            cpe = _first_cpe(service_el)
            result = await repo.upsert_asset_row(
                space_id=space_id,
                row={
                    "ip": ip,
                    "hostname": hostname,
                    "os_name": os_name,
                    "os_version": os_version,
                    "environment": "unknown",
                    "criticality": "medium",
                    "owner": None,
                    "tags": [],
                    "product": product,
                    "version": _clean(service_el.get("version") if service_el is not None else None),
                    "vendor": _clean(service_el.get("vendor") if service_el is not None else None),
                    "provided_cpe": cpe,
                    "port": port,
                    "protocol": (_clean(port_el.get("protocol")) or "tcp").lower(),
                    "exposure_scope": "unknown",
                    "notes": _clean(service_el.get("extrainfo") if service_el is not None else None),
                    "source": "nmap",
                    "source_filename": filename,
                    "detection_method": "nmap_banner",
                    "raw_banner": _raw_banner(service_el),
                },
            )
            for key in ("hosts_created", "hosts_updated", "services_created", "services_updated", "exposures_created", "exposures_updated"):
                summary[key] += result.get(key, 0)
            conf = result.get("cpe_confidence") or "unknown"
            summary["cpe_normalization"][conf] = summary["cpe_normalization"].get(conf, 0) + 1

    await db.commit()
    return summary


def _host_ip(host_el: ET.Element) -> str | None:
    for address in host_el.findall("./address"):
        if address.get("addrtype") in (None, "ipv4", "ipv6"):
            return _clean(address.get("addr"))
    return None


def _host_name(host_el: ET.Element) -> str | None:
    hostname = host_el.find("./hostnames/hostname")
    return _clean(hostname.get("name") if hostname is not None else None)


def _host_os(host_el: ET.Element) -> tuple[str | None, str | None]:
    osmatch = host_el.find("./os/osmatch")
    if osmatch is None:
        return None, None
    name = _clean(osmatch.get("name"))
    if not name:
        return None, None
    m = re.match(r"([A-Za-z][A-Za-z0-9_.+\- ]*?)(?:\s+([0-9][A-Za-z0-9_.+\- ]*))?$", name)
    if not m:
        return name, None
    return _clean(m.group(1)), _clean(m.group(2))


def _service_product(service_el: ET.Element | None, port_el: ET.Element) -> str | None:
    if service_el is None:
        return None
    return _clean(service_el.get("product")) or _clean(service_el.get("name")) or _clean(port_el.get("protocol"))


def _first_cpe(service_el: ET.Element | None) -> str | None:
    if service_el is None:
        return None
    cpe = service_el.find("./cpe")
    return _clean(cpe.text if cpe is not None else None)


def _raw_banner(service_el: ET.Element | None) -> str | None:
    if service_el is None:
        return None
    parts = []
    for key in ("name", "product", "version", "extrainfo"):
        value = _clean(service_el.get(key))
        if value:
            parts.append(f"{key}={value}")
    return "; ".join(parts) or None


def _fail(summary: dict, row: int, reason: str) -> None:
    summary["failed_rows"] += 1
    if len(summary["failed_reasons"]) < 5:
        summary["failed_reasons"].append({"row": row, "reason": reason})


def _clean(value: object) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None
