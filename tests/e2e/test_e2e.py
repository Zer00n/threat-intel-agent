"""End-to-end test — real API call with a stable CVE.

This test requires a valid ANTHROPIC_API_KEY and internet access.
It is skipped by default; run with: pytest tests/e2e/ -v --run-e2e
"""
import os
import pytest

E2E_ENABLED = os.environ.get("RUN_E2E_TESTS", "0") == "1"

pytestmark = pytest.mark.skipif(
    not E2E_ENABLED,
    reason="E2E tests disabled. Set RUN_E2E_TESTS=1 to enable.",
)

# Use a stable, well-known CVE that won't change
TEST_CVE = "CVE-2024-21413"


@pytest.fixture
def api_base():
    return os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")


@pytest.mark.asyncio
async def test_full_cve_analysis(api_base):
    """E2E: submit CVE analysis, wait for completion, verify report."""
    import httpx

    async with httpx.AsyncClient(base_url=api_base, timeout=120) as client:
        # 1. Submit analysis
        resp = await client.post("/analyze", json={"query": TEST_CVE})
        assert resp.status_code == 200, f"Analyze failed: {resp.text}"
        data = resp.json()
        task_id = data["task_id"]
        assert task_id

        # 2. Poll SSE stream until done
        import asyncio
        async with client.stream("GET", f"/stream/{task_id}") as stream:
            events = []
            async for line in stream.aiter_lines():
                if line.startswith("data:"):
                    try:
                        event_data = __import__("json").loads(line[5:].strip())
                        events.append(event_data)
                    except Exception:
                        pass
                if line.startswith("event:") and "done" in line:
                    break
                if line.startswith("event:") and any(
                    x in line for x in ["error", "timeout", "budget_exceeded"]
                ):
                    break
                if len(events) > 500:
                    break  # Safety limit

        # 3. Verify history exists
        resp = await client.get(f"/history/{task_id}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["status"] == "completed"
        assert detail["report_md"] is not None
        assert len(detail["report_md"]) > 100

        # 4. Verify export works
        resp = await client.get(f"/export/md/{task_id}")
        assert resp.status_code == 200
        assert b"CVE" in resp.content

        # 5. Verify IOC extraction (may or may not have IOCs for this CVE)
        resp = await client.get(f"/export/iocs/{task_id}")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_health_endpoint(api_base):
    """Quick smoke test for the health endpoint."""
    import httpx
    async with httpx.AsyncClient(base_url=api_base) as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
