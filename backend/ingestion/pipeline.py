"""Ingestion pipeline — parse, normalize, store, and embed log data."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import config
from backend.analysis.embeddings import embed_logs
from backend.ingestion.parser import detect_log_format, parse_logs
from backend.models.log_entry import IngestResult, LogType, NormalizedLog
from backend.storage.database import LogDatabase
from backend.storage.vectors import VectorStore

logger = logging.getLogger(__name__)


class IngestPipeline:
    """End-to-end ingestion: read → parse → store → embed."""

    def __init__(self, db: LogDatabase, vector_store: Optional[VectorStore] = None):
        self.db = db
        self.vector_store = vector_store

    async def ingest_file(self, path: str) -> IngestResult:
        """Ingest a single log file."""
        path_obj = Path(path)
        if not path_obj.exists():
            return IngestResult(errors=[f"File not found: {path}"])

        content = path_obj.read_text(errors="replace")
        log_type = detect_log_format(content)

        return await self._process(content, log_type, source_file=str(path_obj.name))

    async def ingest_text(self, content: str, log_type: Optional[LogType] = None) -> IngestResult:
        """Ingest raw log text."""
        if log_type is None:
            log_type = detect_log_format(content)
        return await self._process(content, log_type, source_file="<text>")

    async def ingest_directory(self, directory: str) -> IngestResult:
        """Ingest all log files in a directory."""
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return IngestResult(errors=[f"Directory not found: {directory}"])

        extensions = {".log", ".json", ".csv", ".txt", ".cef"}
        combined = IngestResult()

        for f in sorted(dir_path.iterdir()):
            if f.is_file() and f.suffix.lower() in extensions:
                result = await self.ingest_file(str(f))
                combined.total_lines += result.total_lines
                combined.parsed += result.parsed
                combined.failed += result.failed
                combined.errors.extend(result.errors)

        return combined

    async def _process(
        self,
        content: str,
        log_type: LogType,
        source_file: str = "",
    ) -> IngestResult:
        """Core processing: parse → store → embed."""
        result = IngestResult(log_type=log_type)

        # Count raw lines
        lines = content.strip().splitlines()
        result.total_lines = len(lines)

        # Parse
        try:
            logs = parse_logs(content, log_type, source_file)
        except Exception as e:
            logger.error("Parsing failed for %s: %s", source_file, e)
            result.errors.append(f"Parse error: {e}")
            result.failed = result.total_lines
            return result

        result.parsed = len(logs)
        result.failed = max(0, result.total_lines - len(logs))

        if not logs:
            return result

        # Store in SQLite
        try:
            self.db.insert_logs(logs)
            logger.info("Stored %d logs from %s", len(logs), source_file)
        except Exception as e:
            logger.error("Database insert failed: %s", e)
            result.errors.append(f"DB error: {e}")
            return result

        # Generate and store embeddings (best effort)
        if self.vector_store:
            await self._embed_and_store(logs, result)

        return result

    async def _embed_and_store(
        self,
        logs: list[NormalizedLog],
        result: IngestResult,
    ) -> None:
        """Generate embeddings and store in vector DB."""
        try:
            # Process in batches
            batch_size = config.INGEST_BATCH_SIZE
            for i in range(0, len(logs), batch_size):
                batch = logs[i : i + batch_size]
                embeddings = await embed_logs(batch)

                if embeddings and self.vector_store:
                    self.vector_store.store_embeddings(batch, embeddings)

                    # Mark as embedded in SQLite
                    self.db.mark_embedded([log.id for log in batch])

            logger.info("Embedded %d logs", len(logs))
        except Exception as e:
            logger.warning("Embedding failed (non-fatal): %s", e)
            result.errors.append(f"Embedding warning: {e}")
