"""Pydantic models for SentinelIQ log entries and analysis results."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LogType(str, Enum):
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"
    JSON = "json"
    CSV = "csv"
    CEF = "cef"
    UNKNOWN = "unknown"


class LogEntry(BaseModel):
    """Raw log entry as received."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime
    source: str
    severity: Severity = Severity.INFO
    message: str
    raw: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_file: str = ""
    log_type: LogType = LogType.UNKNOWN


class NormalizedLog(BaseModel):
    """Normalized log entry — uniform schema across all formats."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime
    source: str = ""
    hostname: str = ""
    severity: Severity = Severity.INFO
    message: str = ""
    raw: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_file: str = ""
    log_type: LogType = LogType.UNKNOWN
    embedded: bool = False

    def to_embed_text(self) -> str:
        """Create a text representation suitable for embedding."""
        parts = [
            f"[{self.severity.value.upper()}]",
            f"source={self.source}" if self.source else "",
            f"host={self.hostname}" if self.hostname else "",
            self.message,
        ]
        return " ".join(p for p in parts if p)


class AnomalyResult(BaseModel):
    """Result of anomaly detection on a log or group of logs."""
    log_id: str = ""
    score: float = 0.0
    is_anomaly: bool = False
    explanation: str = ""
    method: str = ""
    related_log_ids: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=datetime.utcnow)


class IncidentSummary(BaseModel):
    """LLM-generated incident summary."""
    title: str
    severity: Severity = Severity.INFO
    affected_hosts: list[str] = Field(default_factory=list)
    timeline: list[dict[str, str]] = Field(default_factory=list)
    recommendation: str = ""
    log_count: int = 0
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class QueryResult(BaseModel):
    """Result from a natural-language query."""
    query: str
    translated_filter: str = ""
    logs: list[NormalizedLog] = Field(default_factory=list)
    summary: str = ""
    total_matches: int = 0


class IngestResult(BaseModel):
    """Result of a log ingestion operation."""
    total_lines: int = 0
    parsed: int = 0
    failed: int = 0
    log_type: LogType = LogType.UNKNOWN
    errors: list[str] = Field(default_factory=list)


class DashboardStats(BaseModel):
    """Aggregated statistics for the dashboard."""
    total_logs: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    anomalies_detected: int = 0
    sources: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
