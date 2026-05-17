"""Integration tests for API routes (analyze, history, export, settings).

Uses httpx.AsyncClient with ASGI transport — no real server needed.
All LLM and external HTTP calls are mocked.
"""
import asyncio
import json
import uuid
import pytest
import pytest_asyncio

from httpx import ASGITransport, AsyncClient

from app.main import app
from app.db.engine import init_db, close_db, async_session_factory
from app.db.models import Analysis, AssetService, IOC, CVERef, AttackTechnique, Finding, AgentLog, NvdCVECache, NvdCpeMatch
from app.utils.time import now_iso
from app.utils.slug import slugify


@pytest_asyncio.fixture
async def db():
    await init_db()
    async with async_session_factory() as session:
        yield session
    await close_db()


@pytest_asyncio.fixture
async def client(db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _uid() -> str:
    return f"test-{uuid.uuid4().hex[:12]}"


def _make_analysis(task_id=None, **kwargs):
    now = now_iso()
    tid = task_id or _uid()
    return Analysis(
        id=tid,
        query=kwargs.get("query", "CVE-2024-21413"),
        intent=kwargs.get("intent", "cve"),
        intent_entities=kwargs.get("intent_entities", json.dumps({"cve_ids": ["CVE-2024-21413"]})),
        status=kwargs.get("status", "completed"),
        report_md=kwargs.get("report_md", "# Test Report\n\nContent here."),
        tlp="GREEN",
        overall_confidence="High",
        token_input=kwargs.get("token_input", 1000),
        token_output=kwargs.get("token_output", 500),
        cost_usd=kwargs.get("cost_usd", 0.05),
        duration_s=30,
        created_at=now,
        updated_at=now,
    )


# ===== Health & Stats =====

class TestHealthRoutes:
    @pytest.mark.asyncio
    async def test_health_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["db"] is True

    @pytest.mark.asyncio
    async def test_stats_returns_structure(self, client):
        resp = await client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "analyses" in data
        assert "total_cost_usd" in data
        assert "monthly_usage" in data


# ===== History Routes =====

class TestHistoryRoutes:
    @pytest.mark.asyncio
    async def test_list_history_returns_structure(self, client):
        resp = await client.get("/history")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "items" in data
        assert isinstance(data["items"], list)

    @pytest.mark.asyncio
    async def test_create_and_get_history(self, client, db):
        a = _make_analysis()
        db.add(a)
        await db.commit()

        resp = await client.get("/history")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

        resp = await client.get(f"/history/{a.id}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["query"] == "CVE-2024-21413"
        assert detail["intent"] == "cve"

    @pytest.mark.asyncio
    async def test_delete_history(self, client, db):
        a = _make_analysis()
        db.add(a)
        await db.commit()

        resp = await client.delete(f"/history/{a.id}")
        assert resp.status_code == 200

        resp = await client.get(f"/history/{a.id}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_batch_delete(self, client, db):
        ids = []
        for i in range(3):
            a = _make_analysis()
            ids.append(a.id)
            db.add(a)
        await db.commit()

        resp = await client.post("/history/batch_delete", json={"ids": ids})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_history_search(self, client, db):
        a = _make_analysis(query="SolarWinds supply chain attack")
        db.add(a)
        await db.commit()

        resp = await client.get("/history", params={"q": "SolarWinds"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    @pytest.mark.asyncio
    async def test_history_pagination(self, client, db):
        for i in range(5):
            db.add(_make_analysis(query=f"Test query {i}"))
        await db.commit()

        resp = await client.get("/history", params={"limit": 2, "offset": 0})
        assert resp.status_code == 200
        assert len(resp.json()["items"]) <= 2

    @pytest.mark.asyncio
    async def test_history_not_found(self, client):
        resp = await client.get("/history/nonexistent-id")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_history_with_iocs(self, client, db):
        a = _make_analysis()
        db.add(a)
        await db.flush()

        db.add(IOC(
            id=_uid(), analysis_id=a.id, ioc_type="ipv4",
            value="192.168.1.1", value_defanged="192.168.1[.]1",
            confidence="High", context="C2 server",
            is_extracted_by="regex", created_at=now_iso(),
        ))
        db.add(IOC(
            id=_uid(), analysis_id=a.id, ioc_type="domain",
            value="evil.example.com", value_defanged="evil[.]example[.]com",
            confidence="Medium", context="Phishing domain",
            is_extracted_by="regex", created_at=now_iso(),
        ))
        await db.commit()

        resp = await client.get(f"/history/{a.id}")
        assert resp.status_code == 200
        detail = resp.json()
        assert len(detail.get("iocs", [])) >= 2

    @pytest.mark.asyncio
    async def test_history_with_attack_techniques(self, client, db):
        a = _make_analysis()
        db.add(a)
        await db.flush()

        db.add(AttackTechnique(
            analysis_id=a.id, technique_id="T1059.001",
            technique_name="PowerShell", tactic="Execution",
            confidence="High", created_at=now_iso(),
        ))
        await db.commit()

        resp = await client.get(f"/history/{a.id}")
        assert resp.status_code == 200
        detail = resp.json()
        assert len(detail.get("attack_techniques", [])) >= 1

    @pytest.mark.asyncio
    async def test_history_diff(self, client, db):
        a1 = _make_analysis(report_md="# Original Report")
        a2 = _make_analysis(report_md="# Updated Report")
        db.add(a1)
        db.add(a2)
        await db.commit()

        resp = await client.get(f"/history/{a1.id}/diff/{a2.id}")
        assert resp.status_code == 200


# ===== Export Routes =====

class TestExportRoutes:
    @pytest.mark.asyncio
    async def test_export_markdown(self, client, db):
        a = _make_analysis(report_md="# CVE Report\n\nDetails here.")
        db.add(a)
        await db.commit()

        resp = await client.get(f"/export/md/{a.id}")
        assert resp.status_code == 200
        assert b"CVE Report" in resp.content

    @pytest.mark.asyncio
    async def test_export_ioc_csv(self, client, db):
        a = _make_analysis()
        db.add(a)
        await db.flush()

        db.add(IOC(
            id=_uid(), analysis_id=a.id, ioc_type="ipv4",
            value="10.0.0.1", value_defanged="10.0.0[.]1",
            confidence="High", context="test",
            is_extracted_by="regex", created_at=now_iso(),
        ))
        await db.commit()

        resp = await client.get(f"/export/iocs/{a.id}?defanged=true")
        assert resp.status_code == 200
        assert b"type,value" in resp.content

    @pytest.mark.asyncio
    async def test_export_stix(self, client, db):
        a = _make_analysis()
        db.add(a)
        await db.flush()

        db.add(IOC(
            id=_uid(), analysis_id=a.id, ioc_type="ipv4",
            value="10.0.0.1", value_defanged="10.0.0[.]1",
            confidence="High", context="test",
            is_extracted_by="regex", created_at=now_iso(),
        ))
        db.add(AttackTechnique(
            analysis_id=a.id, technique_id="T1059.001",
            technique_name="PowerShell", tactic="Execution",
            confidence="High", created_at=now_iso(),
        ))
        await db.commit()

        resp = await client.get(f"/export/stix/{a.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "objects" in data
        assert data["type"] == "bundle"

    @pytest.mark.asyncio
    async def test_export_sigma(self, client, db):
        a = _make_analysis(query="CVE-2024-21413 Outlook RCE")
        db.add(a)
        await db.commit()

        resp = await client.get(f"/export/sigma/{a.id}")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_export_zip(self, client, db):
        a = _make_analysis()
        db.add(a)
        await db.commit()

        resp = await client.get(f"/export/zip/{a.id}")
        assert resp.status_code == 200
        assert resp.headers.get("content-type") in ("application/zip", "application/x-zip-compressed")

    @pytest.mark.asyncio
    async def test_export_not_found(self, client):
        resp = await client.get("/export/md/nonexistent-id")
        assert resp.status_code == 404


# ===== Settings Routes =====

class TestSettingsRoutes:
    @pytest.mark.asyncio
    async def test_get_settings(self, client):
        resp = await client.get("/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert "monthly_budget_usd" in data
        assert "single_task_token_limit" in data

    @pytest.mark.asyncio
    async def test_update_settings(self, client):
        resp = await client.put("/settings", json={
            "monthly_budget_usd": 100,
            "single_task_token_limit": 300000,
        })
        assert resp.status_code == 200

        resp = await client.get("/settings")
        data = resp.json()
        assert data["monthly_budget_usd"] == 100

    @pytest.mark.asyncio
    async def test_trusted_sources_crud(self, client, db):
        domain = f"test-vendor-{uuid.uuid4().hex[:6]}.example.com"

        resp = await client.get("/settings/trusted_sources")
        assert resp.status_code == 200

        resp = await client.post("/settings/trusted_sources", json={
            "domain": domain,
            "note": "Test vendor",
        })
        assert resp.status_code == 200

        resp = await client.delete(f"/settings/trusted_sources/{domain}")
        assert resp.status_code == 200


# ===== Sources Routes =====

class TestSourcesRoutes:
    @pytest.mark.asyncio
    async def test_sources_health(self, client):
        resp = await client.get("/sources/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "sources" in data
        assert isinstance(data["sources"], list)

    @pytest.mark.asyncio
    async def test_test_source(self, client):
        resp = await client.post("/sources/test/nvd")
        assert resp.status_code == 200


# ===== Asset Routes =====

class TestAssetRoutes:
    @pytest.mark.asyncio
    async def test_asset_spaces_include_default(self, client):
        resp = await client.get("/api/asset-spaces")
        assert resp.status_code == 200
        data = resp.json()
        assert any(space["id"] == "default" for space in data)

    @pytest.mark.asyncio
    async def test_default_space_includes_demo_asset_cases(self, client):
        resp = await client.get("/api/assets", params={"space_id": "default", "search": "demo-web-prod-01"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        host = data["items"][0]
        assert host["id"] == "demo-asset-web-prod-01"
        assert host["services"][0]["cve_matches"][0]["cve_id"] == "CVE-2021-41773"

        resp = await client.get(f"/api/assets/{host['id']}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["hostname"] == "demo-web-prod-01"
        assert detail["services"][0]["exposures"][0]["exposure_scope"] == "public"

    @pytest.mark.asyncio
    async def test_patch_asset_cve_match_status_and_notes(self, client):
        resp = await client.get("/api/assets/demo-asset-web-prod-01")
        assert resp.status_code == 200
        match = resp.json()["services"][0]["cve_matches"][0]

        resp = await client.patch(f"/api/asset-cve-matches/{match['id']}", json={
            "status": "acknowledged",
            "user_notes": "Owner accepted risk until maintenance window.",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

        resp = await client.get("/api/assets/demo-asset-web-prod-01")
        assert resp.status_code == 200
        updated = resp.json()["services"][0]["cve_matches"][0]
        assert updated["status"] == "acknowledged"
        assert updated["user_notes"] == "Owner accepted risk until maintenance window."

    @pytest.mark.asyncio
    async def test_analyze_asset_space_creates_history_report(self, client):
        resp = await client.post("/api/asset-spaces/default/analyze")
        assert resp.status_code == 200
        result = resp.json()
        assert result["status"] == "completed"
        assert result["summary"]["asset_count"]["hosts"] >= 2
        assert result["summary"]["risk"]["open_cves"] >= 1

        resp = await client.get(f"/history/{result['analysis_id']}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["intent"] == "asset_space_analysis"
        assert "## 1. 概览" in detail["report_md"]
        assert "## 8. 待确认资产" in detail["report_md"]
        assert "CVE-" in detail["report_md"]
        assert detail["cve_refs"]

    @pytest.mark.asyncio
    async def test_manual_create_asset_and_detail(self, client):
        ip = f"192.168.55.{int(uuid.uuid4().hex[:2], 16)}"
        resp = await client.post("/api/assets", json={
            "space_id": "default",
            "ip": ip,
            "hostname": "manual-web",
            "os_name": "Ubuntu",
            "os_version": "22.04",
            "environment": "prod",
            "criticality": "high",
            "owner": "secops",
            "tags": ["manual", "web"],
            "notes": "Manual asset test",
            "product": "apache",
            "version": "2.4.49",
            "vendor": "apache",
            "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            "raw_banner": "Apache httpd 2.4.49",
            "port": 443,
            "protocol": "tcp",
            "exposure_scope": "public",
        })
        assert resp.status_code == 200
        host = resp.json()
        assert host["ip"] == ip
        assert host["source"] == "manual"
        assert host["services"][0]["cpe_confidence"] == "high"
        assert host["services"][0]["exposures"][0]["port"] == 443

        resp = await client.get("/api/assets", params={"space_id": "default", "search": ip})
        assert resp.status_code == 200
        assert resp.json()["items"][0]["hostname"] == "manual-web"

    @pytest.mark.asyncio
    async def test_import_csv_and_list_assets(self, client):
        ip = f"192.168.51.{int(uuid.uuid4().hex[:2], 16)}"
        csv_content = (
            "ip,hostname,os_name,os_version,environment,criticality,owner,tags,product,version,vendor,port,protocol,exposure_scope,notes\n"
            f"{ip},web-01,Ubuntu,22.04,prod,high,sec,\"web,core\",nginx,1.18.0,nginx,80,tcp,public,\n"
        )
        resp = await client.post("/api/assets/import/csv-text", json={
            "space_id": "default",
            "content": csv_content,
            "mode": "merge",
        })
        assert resp.status_code == 200
        summary = resp.json()["summary"]
        assert summary["hosts_created"] + summary["hosts_updated"] >= 1
        assert summary["services_created"] + summary["services_updated"] >= 1

        resp = await client.get("/api/assets", params={"space_id": "default", "search": ip})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert data["items"][0]["services"]

    @pytest.mark.asyncio
    async def test_import_json_and_list_assets(self, client):
        ip = f"192.168.53.{int(uuid.uuid4().hex[:2], 16)}"
        payload = {
            "version": "1.0",
            "source": "test_json",
            "hosts": [{
                "ip": ip,
                "hostname": "json-web",
                "os": {"name": "Ubuntu", "version": "22.04"},
                "environment": "prod",
                "criticality": "high",
                "tags": ["web"],
                "services": [{
                    "product": "nginx",
                    "version": "1.18.0",
                    "vendor": "nginx",
                    "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
                    "exposures": [{"port": 8080, "protocol": "tcp", "scope": "public"}],
                }],
            }],
        }
        resp = await client.post("/api/assets/import/json-text", json={
            "space_id": "default",
            "content": json.dumps(payload),
            "mode": "merge",
        })
        assert resp.status_code == 200
        assert resp.json()["summary"]["hosts_created"] + resp.json()["summary"]["hosts_updated"] >= 1

        resp = await client.get("/api/assets", params={"space_id": "default", "search": ip})
        assert resp.status_code == 200
        item = resp.json()["items"][0]
        assert item["services"][0]["cpe_confidence"] == "high"

    @pytest.mark.asyncio
    async def test_import_nmap_xml_and_list_assets(self, client):
        ip = f"192.168.54.{int(uuid.uuid4().hex[:2], 16)}"
        xml_content = f"""<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="{ip}" addrtype="ipv4"/>
    <hostnames><hostname name="nmap-web"/></hostnames>
    <os><osmatch name="Linux 5.x" accuracy="98"/></os>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""
        resp = await client.post("/api/assets/import/nmap-text", json={
            "space_id": "default",
            "content": xml_content,
            "mode": "merge",
            "filename": "scan.xml",
        })
        assert resp.status_code == 200
        summary = resp.json()["summary"]
        assert summary["hosts_created"] + summary["hosts_updated"] >= 1
        assert summary["services_created"] + summary["services_updated"] >= 1
        assert summary["cpe_normalization"]["high"] >= 1

        resp = await client.get("/api/assets", params={"space_id": "default", "search": ip})
        assert resp.status_code == 200
        item = resp.json()["items"][0]
        assert item["hostname"] == "nmap-web"
        assert item["services"][0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
        assert item["services"][0]["exposures"][0]["port"] == 443

    @pytest.mark.asyncio
    async def test_identify_service_uses_local_cve_cache(self, client, db):
        ip = f"192.168.52.{int(uuid.uuid4().hex[:2], 16)}"
        cve_id = f"CVE-2099-{int(uuid.uuid4().hex[:4], 16):04d}"
        csv_content = (
            "ip,hostname,os_name,os_version,environment,criticality,owner,tags,product,version,vendor,port,protocol,exposure_scope,notes\n"
            f"{ip},web-02,Ubuntu,22.04,prod,high,sec,web,nginx,1.18.0,nginx,443,tcp,public,\n"
        )
        resp = await client.post("/api/assets/import/csv-text", json={
            "space_id": "default",
            "content": csv_content,
            "mode": "merge",
        })
        assert resp.status_code == 200

        resp = await client.get("/api/assets", params={"space_id": "default", "search": ip})
        host = resp.json()["items"][0]
        service = host["services"][0]

        cpe = service["cpe"]
        db.add(NvdCVECache(
            cve_id=cve_id,
            description="Test nginx issue",
            cvss_v3_score=9.8,
            is_in_kev=True,
            epss_score=0.9,
            updated_at=now_iso(),
        ))
        db.add(NvdCpeMatch(
            id=_uid(),
            cve_id=cve_id,
            cpe=cpe,
            vulnerable=True,
        ))
        await db.commit()

        resp = await client.post(f"/api/assets/{host['id']}/services/{service['id']}/identify")
        assert resp.status_code == 200
        result = resp.json()
        assert result["statistics"]["high"] >= 1
        assert any(match["cve_id"] == cve_id for match in result["matches"])


# ===== Analyze Routes (mocked) =====

class TestAnalyzeRoutes:
    @pytest.mark.asyncio
    async def test_analyze_returns_409_when_task_running(self, client, db):
        from app.task_manager import task_manager

        async def _idle():
            await asyncio.sleep(300)

        fake_task = asyncio.get_event_loop().create_task(_idle())
        task_manager._tasks["fake-running"] = fake_task

        resp = await client.post("/analyze", json={"query": "CVE-2024-21413"})
        assert resp.status_code == 409

        fake_task.cancel()
        task_manager._tasks.pop("fake-running", None)

    @pytest.mark.asyncio
    async def test_analyze_returns_422_short_query(self, client):
        resp = await client.post("/analyze", json={"query": "ab"})
        assert resp.status_code in (400, 422)

    @pytest.mark.asyncio
    async def test_analyze_rejects_long_query(self, client):
        resp = await client.post("/analyze", json={"query": "x" * 1001})
        assert resp.status_code in (400, 422)

    @pytest.mark.asyncio
    async def test_switch_intent_not_running(self, client):
        resp = await client.post("/analyze/nonexistent-task/switch_intent", json={"intent": "cve"})
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_switch_intent_invalid_intent(self, client, db):
        from app.task_manager import task_manager

        async def _idle():
            await asyncio.sleep(300)

        fake_task = asyncio.get_event_loop().create_task(_idle())
        task_manager._tasks["switch-test"] = fake_task

        resp = await client.post("/analyze/switch-test/switch_intent", json={"intent": "invalid_intent"})
        assert resp.status_code == 422

        fake_task.cancel()
        task_manager._tasks.pop("switch-test", None)

    @pytest.mark.asyncio
    async def test_stop_analysis_not_running(self, client):
        resp = await client.post("/analyze/nonexistent-task/stop")
        assert resp.status_code in (200, 404, 409)


# ===== Audit Logs =====

class TestAuditLogs:
    @pytest.mark.asyncio
    async def test_get_audit_logs(self, client):
        resp = await client.get("/audit_logs")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list) or "items" in data or isinstance(data.get("logs"), list)
