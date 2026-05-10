"""Natural language query engine — converts user questions to log filters using LLM."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Optional

import httpx

import config
from backend.analysis.embeddings import embed_text
from backend.models.log_entry import NormalizedLog, QueryResult
from backend.storage.database import LogDatabase
from backend.storage.vectors import VectorStore

logger = logging.getLogger(__name__)

NL_SYSTEM = """You are a security log query assistant. Convert the user's natural language question into a JSON filter object that can be used to search security logs.

Available filter fields:
- query: text search in log messages (string, use SQL LIKE wildcards)
- severity: one of critical, high, medium, low, info
- source: source system or hostname
- hostname: specific hostname filter
- start_time: ISO 8601 datetime (e.g., "2025-01-15T10:00:00")
- end_time: ISO 8601 datetime
- limit: max results (default 50)

Relative time references:
- "last hour" → start_time = now minus 1 hour
- "today" → start_time = start of today
- "last 24 hours" → start_time = now minus 24 hours

Current time: {now}

Respond with ONLY a JSON object containing the filter fields. Examples:

User: "Show failed SSH logins from last hour"
{{"query": "%failed%SSH%", "start_time": "{one_hour_ago}", "limit": 50}}

User: "What happened on 10.0.0.5?"
{{"source": "10.0.0.5", "limit": 50}}

User: "Show all critical alerts today"
{{"severity": "critical", "start_time": "{today}", "limit": 100}}

User: "Failed logins from admin account"
{{"query": "%failed%login%admin%", "limit": 50}}"""


class NLQueryEngine:
    """Translates natural language queries into log search filters."""

    def __init__(self, db: LogDatabase, vector_store: Optional[VectorStore] = None):
        self.db = db
        self.vector_store = vector_store

    async def query(self, text: str) -> QueryResult:
        """Process a natural language query and return matching logs."""
        # First try LLM translation
        try:
            filter_params = await self._translate_to_filter(text)
            translated = json.dumps(filter_params, indent=2)
        except Exception as e:
            logger.warning("LLM query translation failed: %s — falling back to keyword search", e)
            filter_params = self._keyword_fallback(text)
            translated = f"(fallback) {json.dumps(filter_params)}"

        # Execute the search
        logs = self.db.search_logs(**filter_params)

        # If we have a vector store and few results, also do semantic search
        if self.vector_store and len(logs) < 5:
            try:
                semantic_results = await self._semantic_search(text)
                # Merge results, avoiding duplicates
                seen_ids = {l.id for l in logs}
                for log in semantic_results:
                    if log.id not in seen_ids:
                        logs.append(log)
                        seen_ids.add(log.id)
            except Exception as e:
                logger.warning("Semantic search failed: %s", e)

        # Generate a summary of results
        summary = self._summarize_results(text, logs)

        return QueryResult(
            query=text,
            translated_filter=translated,
            logs=logs[:100],
            summary=summary,
            total_matches=len(logs),
        )

    async def _translate_to_filter(self, text: str) -> dict[str, Any]:
        """Use LLM to convert natural language to filter parameters."""
        now = datetime.utcnow()
        system_prompt = NL_SYSTEM.format(
            now=now.isoformat(),
            one_hour_ago=(now - timedelta(hours=1)).isoformat(),
            today=now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat(),
        )

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{config.OLLAMA_HOST}/api/chat",
                json={
                    "model": config.OLLAMA_CHAT_MODEL,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": text},
                    ],
                    "stream": False,
                },
            )
            response.raise_for_status()
            data = response.json()

        content = data.get("message", {}).get("content", "{}")

        # Extract JSON from response (might be wrapped in code fences)
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1])

        params = json.loads(content)

        # Sanitize and validate
        allowed_keys = {"query", "severity", "source", "hostname", "start_time", "end_time", "limit", "offset", "log_type"}
        return {k: v for k, v in params.items() if k in allowed_keys}

    async def _semantic_search(self, text: str, top_k: int = 20) -> list[NormalizedLog]:
        """Use vector similarity to find relevant logs."""
        if not self.vector_store:
            return []

        query_emb = await embed_text(text)
        results = self.vector_store.search_similar(query_emb, top_k=top_k)

        logs = []
        for item in results:
            log = self.db.get_log(item["id"])
            if log:
                logs.append(log)
        return logs

    def _keyword_fallback(self, text: str) -> dict[str, Any]:
        """Simple keyword-based fallback when LLM is unavailable."""
        params: dict[str, Any] = {"limit": 50}

        text_lower = text.lower()

        # Detect severity
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in text_lower:
                params["severity"] = sev
                break

        # Detect time ranges
        if "last hour" in text_lower:
            params["start_time"] = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        elif "last 24 hours" in text_lower or "last day" in text_lower:
            params["start_time"] = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        elif "today" in text_lower:
            params["start_time"] = datetime.utcnow().replace(hour=0, minute=0, second=0).isoformat()

        # Extract IP addresses
        ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
        if ip_match:
            params["source"] = ip_match.group()

        # Build query from remaining keywords
        stop_words = {"show", "me", "the", "all", "from", "last", "hour", "today", "what", "happened", "on", "find", "get", "list"}
        keywords = [w for w in re.findall(r"\w+", text_lower) if w not in stop_words and len(w) > 2]
        if keywords:
            params["query"] = "%" + "%".join(keywords) + "%"

        return params

    @staticmethod
    def _summarize_results(query: str, logs: list[NormalizedLog]) -> str:
        """Generate a brief text summary of the search results."""
        if not logs:
            return f"No logs found matching: {query}"

        severity_counts: dict[str, int] = {}
        sources: set[str] = set()
        for log in logs:
            severity_counts[log.severity.value] = severity_counts.get(log.severity.value, 0) + 1
            if log.source:
                sources.add(log.source)

        parts = [f"Found {len(logs)} matching log(s)."]
        if severity_counts:
            breakdown = ", ".join(f"{v} {k}" for k, v in sorted(severity_counts.items()))
            parts.append(f"Severity breakdown: {breakdown}.")
        if sources:
            parts.append(f"Sources: {', '.join(sorted(sources)[:5])}.")

        return " ".join(parts)
