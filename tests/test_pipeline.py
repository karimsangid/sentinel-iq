"""Tests for the ingestion pipeline."""

import tempfile
from pathlib import Path

import pytest

from backend.ingestion.pipeline import IngestPipeline
from backend.models.log_entry import LogType
from backend.storage.database import LogDatabase

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_logs"


@pytest.fixture
def db(tmp_path):
    return LogDatabase(str(tmp_path / "test.db"))


@pytest.fixture
def pipeline(db):
    return IngestPipeline(db, vector_store=None)


@pytest.mark.asyncio
async def test_ingest_syslog_file(pipeline, db):
    result = await pipeline.ingest_file(str(SAMPLE_DIR / "sample_syslog.log"))
    assert result.parsed > 0
    assert result.log_type == LogType.SYSLOG
    assert result.errors == [] or all("Embedding" in e for e in result.errors)

    # Verify logs are in database
    logs = db.search_logs(limit=100)
    assert len(logs) == result.parsed


@pytest.mark.asyncio
async def test_ingest_windows_events(pipeline, db):
    result = await pipeline.ingest_file(str(SAMPLE_DIR / "sample_windows_events.json"))
    assert result.parsed == 15
    assert result.log_type == LogType.WINDOWS_EVENT


@pytest.mark.asyncio
async def test_ingest_csv(pipeline, db):
    result = await pipeline.ingest_file(str(SAMPLE_DIR / "sample_firewall.csv"))
    assert result.parsed == 20
    assert result.log_type == LogType.CSV


@pytest.mark.asyncio
async def test_ingest_text(pipeline, db):
    text = 'Jan 15 10:00:00 myhost myapp[1234]: Something happened\nJan 15 10:01:00 myhost myapp[1234]: Something else'
    result = await pipeline.ingest_text(text)
    assert result.parsed == 2
    logs = db.search_logs(limit=10)
    assert len(logs) == 2


@pytest.mark.asyncio
async def test_ingest_missing_file(pipeline):
    result = await pipeline.ingest_file("/nonexistent/file.log")
    assert len(result.errors) > 0


@pytest.mark.asyncio
async def test_ingest_directory(pipeline, db):
    result = await pipeline.ingest_directory(str(SAMPLE_DIR))
    assert result.parsed > 0
    total_in_db = db.count_logs()
    assert total_in_db == result.parsed


@pytest.mark.asyncio
async def test_database_filtering_after_ingest(pipeline, db):
    await pipeline.ingest_file(str(SAMPLE_DIR / "sample_syslog.log"))

    # Filter by source
    ssh_logs = db.search_logs(source="sshd")
    assert len(ssh_logs) > 0
    for log in ssh_logs:
        assert "sshd" in log.source.lower() or "sshd" in log.hostname.lower()

    # Stats
    stats = db.get_stats()
    assert stats.total_logs > 0
