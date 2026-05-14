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
from app.db.models import Analysis, IOC, CVERef, AttackTechnique, Finding, AgentLog
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
