"""FastAPI API routes for SentinelIQ."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel

import config
from backend.analysis.anomaly import AnomalyDetector
from backend.analysis.summarizer import generate_report, summarize_incident
from backend.api.websocket import manager as ws_manager
from backend.ingestion.pipeline import IngestPipeline
from backend.models.log_entry import (
    AnomalyResult,
    DashboardStats,
    IngestResult,
    IncidentSummary,
    NormalizedLog,
    QueryResult,
)
from backend.query.natural_language import NLQueryEngine
from backend.storage.database import LogDatabase
from backend.storage.vectors import VectorStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

# ── Dependency holders (set during app startup) ──────────────────────
_db: Optional[LogDatabase] = None
_vector_store: Optional[VectorStore] = None
_pipeline: Optional[IngestPipeline] = None
_query_engine: Optional[NLQueryEngine] = None
_anomaly_detector: Optional[AnomalyDetector] = None


def init_dependencies(db: LogDatabase, vs: Optional[VectorStore] = None) -> None:
    """Initialize route dependencies. Called from main.py on startup."""
    global _db, _vector_store, _pipeline, _query_engine, _anomaly_detector
    _db = db
    _vector_store = vs
    _pipeline = IngestPipeline(db, vs)
    _query_engine = NLQueryEngine(db, vs)
    _anomaly_detector = AnomalyDetector(db, vs)


def _get_db() -> LogDatabase:
    if _db is None:
        raise HTTPException(status_code=503, detail="Database not initialized")
    return _db


# ── Request / Response models ────────────────────────────────────────

class IngestTextRequest(BaseModel):
    content: str
    log_type: Optional[str] = None


class NLQueryRequest(BaseModel):
    query: str


class SummarizeRequest(BaseModel):
    log_ids: list[str] = []
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    severity: Optional[str] = None


# ── Health ────────────────────────────────────────────────────────────

@router.get("/health")
async def health_check() -> dict:
    return {
        "status": "healthy",
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "websocket_clients": ws_manager.connection_count,
    }


# ── Ingestion ────────────────────────────────────────────────────────

@router.post("/ingest/file", response_model=IngestResult)
async def ingest_file(file: UploadFile = File(...)) -> IngestResult:
    """Upload and ingest a log file."""
    if not _pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    content = await file.read()
    text = content.decode("utf-8", errors="replace")

    result = await _pipeline.ingest_text(text)
    result.log_type = result.log_type  # already set by pipeline

    # Broadcast to WebSocket clients
    if result.parsed > 0:
        db = _get_db()
        logs = db.search_logs(limit=result.parsed)
        for log in logs[:50]:  # Cap broadcast
            await ws_manager.broadcast_log(log)

    return result


@router.post("/ingest/text", response_model=IngestResult)
async def ingest_text(request: IngestTextRequest) -> IngestResult:
    """Ingest raw log text."""
    if not _pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    from backend.models.log_entry import LogType
    log_type = LogType(request.log_type) if request.log_type else None

    result = await _pipeline.ingest_text(request.content, log_type)

    return result


# ── Log Queries ──────────────────────────────────────────────────────

@router.get("/logs", response_model=list[NormalizedLog])
async def get_logs(
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    query: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[NormalizedLog]:
    """Query logs with filters."""
    db = _get_db()
    return db.search_logs(
        query=query,
        severity=severity,
        source=source,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )


@router.get("/logs/{log_id}", response_model=NormalizedLog)
async def get_log(log_id: str) -> NormalizedLog:
    """Get a single log entry by ID."""
    db = _get_db()
    log = db.get_log(log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log


# ── Natural Language Query ───────────────────────────────────────────

@router.post("/query", response_model=QueryResult)
async def natural_language_query(request: NLQueryRequest) -> QueryResult:
    """Query logs using natural language."""
    if not _query_engine:
        raise HTTPException(status_code=503, detail="Query engine not initialized")
    return await _query_engine.query(request.query)


# ── Anomalies ────────────────────────────────────────────────────────

@router.get("/anomalies", response_model=list[AnomalyResult])
async def get_anomalies(
    window_minutes: int = Query(60, ge=5, le=1440),
) -> list[AnomalyResult]:
    """Detect anomalies in recent logs."""
    if not _anomaly_detector:
        raise HTTPException(status_code=503, detail="Anomaly detector not initialized")
    return _anomaly_detector.detect_anomalies(time_window_minutes=window_minutes)


# ── Summarization ────────────────────────────────────────────────────

@router.post("/summarize", response_model=IncidentSummary)
async def summarize(request: SummarizeRequest) -> IncidentSummary:
    """Summarize a set of logs or a time range."""
    db = _get_db()

    if request.log_ids:
        logs = [db.get_log(lid) for lid in request.log_ids]
        logs = [l for l in logs if l is not None]
    else:
        logs = db.search_logs(
            severity=request.severity,
            start_time=request.start_time,
            end_time=request.end_time,
            limit=200,
        )

    if not logs:
        raise HTTPException(status_code=404, detail="No logs found for summarization")

    return await summarize_incident(logs)


# ── Statistics ───────────────────────────────────────────────────────

@router.get("/stats", response_model=DashboardStats)
async def get_stats() -> DashboardStats:
    """Get dashboard statistics."""
    db = _get_db()
    return db.get_stats()
