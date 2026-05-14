"""Shared test fixtures."""
import asyncio
import os
import pytest
import pytest_asyncio

# Set test env before importing app modules
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-test-key-for-testing")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./data/test_ti.db")
os.environ.setdefault("API_FORMAT", "openai")


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
