from __future__ import annotations

import json
import time
import uuid
from collections import Counter, defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.matcher import identify_service_risks
from app.assets.repository import AssetRepository
from app.db.models import Analysis, AssetService, AssetSpace, CVERef, Host
from app.utils.time import now_iso


async def analyze_asset_space(db: AsyncSession, space_id: str) -> dict:
    """Run deterministic space-level asset risk analysis and persist a report."""
    started = time.monotonic()
    space = await db.get(AssetSpace, space_id)
    if not space:
        raise KeyError(space_id)

    service_ids = (await db.execute(
        select(AssetService.id)
        .join(Host, Host.id == AssetService.host_id)
        .where(Host.space_id == space_id)
        .order_by(AssetService.product)
    )).scalars().all()

    for service_id in service_ids:
        await identify_service_risks(db, service_id)

    hosts = (await db.execute(
        select(Host).where(Host.space_id == space_id).order_by(Host.updated_at.desc())
    )).scalars().all()
    repo = AssetRepository(db)
    details = [await repo.host_detail(host.id) for host in hosts]
    summary = _build_summary(space, details)
    report_md = _render_report(space, summary)

    now = now_iso()
    analysis_id = str(uuid.uuid4())
    analysis = Analysis(
        id=analysis_id,
        query=f"资产空间风险综合分析：{space.name}",
        intent="asset_space_analysis",
        intent_entities=json.dumps({"asset_space_id": space.id, "asset_space_name": space.name}, ensure_ascii=False),
        status="completed",
        report_md=report_md,
        report_meta=json.dumps({"asset_space_id": space.id, "asset_summary": summary}, ensure_ascii=False),
        tlp="GREEN",
        overall_confidence="High",
        token_input=0,
        token_output=0,
        cost_usd=0,
        duration_s=max(1, int(time.monotonic() - started)),
        created_at=now,
        updated_at=now,
    )
    db.add(analysis)
    for cve in summary["top_cves"]:
        db.add(CVERef(
            id=str(uuid.uuid4()),
            analysis_id=analysis_id,
            cve_id=cve["cve_id"],
            cvss_v3_score=cve["cvss_score"],
            is_in_kev=cve["kev_flag"],
            epss_score=cve["epss_score"],
            description=cve["summary"],
            created_at=now,
        ))
    await db.commit()

    return {
        "analysis_id": analysis_id,
        "status": "completed",
        "space_id": space.id,
        "summary": summary,
    }


def _build_summary(space: AssetSpace, hosts: list[dict]) -> dict:
    env_counts = Counter()
    criticality_counts = Counter()
    exposure_counts = Counter()
    tech_stack = Counter()
    unknown_services = []
    host_rows = []
    cve_map = {}

    service_count = 0
    public_hosts = set()
    public_high_hosts = set()

    for host in hosts:
        env_counts[host.get("environment") or "unknown"] += 1
        criticality_counts[host.get("criticality") or "unknown"] += 1
        host_open_matches = []
        host_public = False

        for service in host.get("services", []):
            service_count += 1
            product = service.get("product") or "unknown"
            tech_stack[product] += 1
            if not service.get("cpe") or service.get("cpe_confidence") == "unknown":
                unknown_services.append({
                    "host": _host_label(host),
                    "service": _service_label(service),
                    "reason": "missing_cpe" if not service.get("cpe") else "unknown_confidence",
                })

            for exposure in service.get("exposures", []):
                scope = exposure.get("exposure_scope") or "unknown"
                exposure_counts[scope] += 1
                if scope == "public":
                    host_public = True

            for match in service.get("cve_matches", []):
                if match.get("status") != "open":
                    continue
                item = {
                    **match,
                    "host_id": host.get("id"),
                    "host": _host_label(host),
                    "service": _service_label(service),
                    "public": any(e.get("exposure_scope") == "public" for e in service.get("exposures", [])),
                }
                host_open_matches.append(item)
                cve = cve_map.setdefault(match["cve_id"], {
                    "cve_id": match["cve_id"],
                    "affected_hosts": set(),
                    "affected_services": 0,
                    "max_risk_score": 0,
                    "cvss_score": match.get("cvss_score"),
                    "kev_flag": bool(match.get("kev_flag")),
                    "epss_score": match.get("epss_score"),
                    "summary": match.get("summary"),
                })
                cve["affected_hosts"].add(host.get("id"))
                cve["affected_services"] += 1
                cve["max_risk_score"] = max(cve["max_risk_score"], match.get("risk_score") or 0)
                cve["kev_flag"] = cve["kev_flag"] or bool(match.get("kev_flag"))

        if host_public:
            public_hosts.add(host.get("id"))
        max_score = max([m.get("risk_score") or 0 for m in host_open_matches] or [0])
        if host_public and host.get("criticality") == "high" and max_score >= 12:
            public_high_hosts.add(host.get("id"))
        host_rows.append({
            "host": _host_label(host),
            "ip": host.get("ip") or "",
            "hostname": host.get("hostname") or "",
            "environment": host.get("environment") or "unknown",
            "criticality": host.get("criticality") or "unknown",
            "services": len(host.get("services", [])),
            "open_cves": len(host_open_matches),
            "high": sum(1 for m in host_open_matches if m.get("risk_level") == "high"),
            "medium": sum(1 for m in host_open_matches if m.get("risk_level") == "medium"),
            "max_risk_score": max_score,
            "top_service": host_open_matches[0]["service"] if host_open_matches else "-",
        })

    open_matches = [
        match
        for host in hosts
        for service in host.get("services", [])
        for match in service.get("cve_matches", [])
        if match.get("status") == "open"
    ]
    risk_counts = Counter(match.get("risk_level") or "unknown" for match in open_matches)
    top_assets = sorted(host_rows, key=lambda item: (item["max_risk_score"], item["open_cves"]), reverse=True)[:10]
    top_cves = sorted(cve_map.values(), key=lambda item: (item["max_risk_score"], item["affected_services"]), reverse=True)[:10]
    for cve in top_cves:
        cve["affected_hosts"] = len(cve["affected_hosts"])

    return {
        "space": {"id": space.id, "name": space.name, "type": space.type},
        "asset_count": {"hosts": len(hosts), "services": service_count},
        "environment": _counter_out(env_counts, ["prod", "test", "dev", "unknown"]),
        "criticality": _counter_out(criticality_counts, ["high", "medium", "low", "unknown"]),
        "exposure": _counter_out(exposure_counts, ["public", "internal", "isolated", "unknown"]),
        "risk": {
            "open_cves": len(open_matches),
            "unique_cves": len(cve_map),
            "high": risk_counts.get("high", 0),
            "medium": risk_counts.get("medium", 0),
            "low": risk_counts.get("low", 0),
            "kev": sum(1 for item in cve_map.values() if item["kev_flag"]),
            "public_hosts": len(public_hosts),
            "public_high_hosts": len(public_high_hosts),
            "unknown_services": len(unknown_services),
        },
        "tech_stack": [{"product": name, "count": count} for name, count in tech_stack.most_common(10)],
        "top_assets": top_assets,
        "top_cves": top_cves,
        "unknown_services": unknown_services[:20],
        "generated_at": now_iso(),
    }


def _render_report(space: AssetSpace, summary: dict) -> str:
    risk = summary["risk"]
    asset_count = summary["asset_count"]
    return "\n\n".join([
        f"# 资产空间风险综合分析报告\n\n**空间**：{space.name}\n**分析时间**：{summary['generated_at']}\n**TLP**：GREEN",
        "## 1. 概览\n\n"
        "| 指标 | 数值 |\n|---|---|\n"
        f"| 资产规模 | {asset_count['hosts']} 主机 / {asset_count['services']} 服务 |\n"
        f"| 未处置 CVE 命中 | {risk['open_cves']} 个（去重 {risk['unique_cves']} 个唯一 CVE） |\n"
        f"| 高危 / 中危 / 低危 | {risk['high']} / {risk['medium']} / {risk['low']} |\n"
        f"| KEV 命中 | {risk['kev']} |\n"
        f"| 公网暴露主机 | {risk['public_hosts']} |\n"
        f"| 公网暴露高危主机 | {risk['public_high_hosts']} |\n"
        f"| 待确认服务 | {risk['unknown_services']} |",
        "## 2. 整体安全态势\n\n" + _posture_text(summary),
        "## 3. Top 10 高风险资产\n\n" + _top_assets_table(summary["top_assets"]),
        "## 4. Top 10 高频 CVE\n\n" + _top_cves_table(summary["top_cves"]),
        "## 5. 暴露面分析\n\n" + _exposure_section(summary),
        "## 6. 处置优先级\n\n" + _priority_section(summary),
        "## 7. 改进方向\n\n" + _improvement_section(summary),
        "## 8. 待确认资产\n\n" + _unknown_section(summary["unknown_services"]),
    ])


def _posture_text(summary: dict) -> str:
    risk = summary["risk"]
    if risk["open_cves"] == 0:
        return "当前空间没有未处置 CVE 命中。建议继续维护资产版本、暴露面和 CPE 识别质量，确保后续新增 CVE 能准确匹配。"
    if risk["public_high_hosts"] > 0:
        return f"当前空间存在 {risk['public_high_hosts']} 台公网暴露且高风险的资产，应优先进入补丁、隔离或访问控制收敛流程。"
    if risk["high"] > 0:
        return f"当前空间存在 {risk['high']} 个高危未处置命中，但公网暴露高危资产暂未出现，应优先核实关键业务资产的版本和补丁状态。"
    return "当前风险以中低危为主，处置重点是减少待确认服务、完善 CPE，并按业务窗口推进补丁。"


def _top_assets_table(rows: list[dict]) -> str:
    if not rows:
        return "暂无未处置 CVE 命中的资产。"
    lines = ["| 排名 | IP | 主机名 | 环境 | 关键性 | 服务 | CVE 数 | 最高风险分 |", "|---|---|---|---|---|---|---:|---:|"]
    for idx, row in enumerate(rows, 1):
        lines.append(
            f"| {idx} | {row['ip'] or '-'} | {row['hostname'] or '-'} | {row['environment']} | {row['criticality']} | "
            f"{row['top_service']} | {row['open_cves']} | {row['max_risk_score']} |"
        )
    return "\n".join(lines)


def _top_cves_table(rows: list[dict]) -> str:
    if not rows:
        return "暂无未处置 CVE。"
    lines = ["| CVE | CVSS | KEV | 影响主机 | 影响服务 | 最高风险分 |", "|---|---:|---|---:|---:|---:|"]
    for row in rows:
        lines.append(
            f"| {row['cve_id']} | {row['cvss_score'] if row['cvss_score'] is not None else '-'} | "
            f"{'是' if row['kev_flag'] else '否'} | {row['affected_hosts']} | {row['affected_services']} | {row['max_risk_score']} |"
        )
    return "\n".join(lines)


def _exposure_section(summary: dict) -> str:
    exposure = summary["exposure"]
    return (
        f"- 公网暴露服务：{exposure.get('public', 0)}\n"
        f"- 内网暴露服务：{exposure.get('internal', 0)}\n"
        f"- 隔离网服务：{exposure.get('isolated', 0)}\n"
        f"- 暴露范围未知服务：{exposure.get('unknown', 0)}\n\n"
        "公网暴露服务会放大 CVSS、KEV 和 EPSS 带来的实际处置优先级，建议优先核查公网资产的访问控制和补丁窗口。"
    )


def _priority_section(summary: dict) -> str:
    assets = summary["top_assets"][:5]
    if not assets:
        return "当前没有需要按 CVE 命中排序的资产。"
    lines = []
    for idx, asset in enumerate(assets, 1):
        lines.append(
            f"{idx}. 优先处理 `{asset['ip'] or asset['hostname']}`：最高风险分 {asset['max_risk_score']}，"
            f"未处置 CVE {asset['open_cves']} 个，重点服务 `{asset['top_service']}`。"
        )
    return "\n".join(lines)


def _improvement_section(summary: dict) -> str:
    unknown = summary["risk"]["unknown_services"]
    public = summary["risk"]["public_hosts"]
    return (
        f"1. 资产管理：补齐 {unknown} 个待确认服务的 CPE，降低漏报和误报。\n"
        "2. 补丁管理：按 Top 高风险资产顺序安排维护窗口，优先处理 KEV 和公网暴露命中。\n"
        f"3. 暴露面收敛：复核 {public} 台公网暴露主机，确认是否需要公网访问、源 IP 限制或临时隔离。"
    )


def _unknown_section(rows: list[dict]) -> str:
    if not rows:
        return "当前没有 CPE 待确认服务。"
    lines = ["| 主机 | 服务 | 原因 |", "|---|---|---|"]
    for row in rows:
        lines.append(f"| {row['host']} | {row['service']} | {row['reason']} |")
    return "\n".join(lines)


def _counter_out(counter: Counter, keys: list[str]) -> dict:
    return {key: counter.get(key, 0) for key in keys}


def _host_label(host: dict) -> str:
    return host.get("ip") or host.get("hostname") or host.get("id") or "-"


def _service_label(service: dict) -> str:
    version = service.get("version")
    return f"{service.get('product') or 'unknown'} {version}".strip()
