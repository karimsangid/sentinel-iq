"""LLM-powered incident summarization using Ollama."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Optional

import httpx

import config
from backend.models.log_entry import IncidentSummary, NormalizedLog, Severity

logger = logging.getLogger(__name__)


async def _chat(prompt: str, system: str = "") -> str:
    """Send a chat completion request to Ollama."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            f"{config.OLLAMA_HOST}/api/chat",
            json={
                "model": config.OLLAMA_CHAT_MODEL,
                "messages": messages,
                "stream": False,
            },
        )
        response.raise_for_status()
        data = response.json()

    return data.get("message", {}).get("content", "")


SUMMARIZE_SYSTEM = """You are a senior security analyst. Analyze the provided security log entries and produce a structured incident summary. Be precise and actionable. Respond in valid JSON with these fields:
- title: Brief incident title
- severity: one of critical, high, medium, low, info
- affected_hosts: list of hostnames/IPs involved
- timeline: list of objects with "time" and "event" keys
- recommendation: actionable recommendation"""

REPORT_SYSTEM = """You are a senior security analyst writing a security report. Summarize the provided log data into a professional security report covering:
1. Executive Summary
2. Key Findings
3. Threat Assessment
4. Affected Systems
5. Recommendations
Be concise but thorough."""


async def summarize_incident(logs: list[NormalizedLog]) -> IncidentSummary:
    """Use LLM to summarize a cluster of related security logs into an incident."""
    if not logs:
        return IncidentSummary(title="No logs provided", recommendation="N/A")

    # Format logs for the prompt
    log_text = "\n".join(
        f"[{log.timestamp.isoformat()}] [{log.severity.value.upper()}] "
        f"host={log.hostname or log.source} | {log.message}"
        for log in logs[:50]  # Limit to avoid context overflow
    )

    prompt = f"Analyze these {len(logs)} security log entries:\n\n{log_text}\n\nProvide a JSON incident summary."

    try:
        raw_response = await _chat(prompt, system=SUMMARIZE_SYSTEM)

        # Try to parse JSON from the response
        # The LLM might wrap it in markdown code fences
        json_str = raw_response.strip()
        if json_str.startswith("```"):
            lines = json_str.split("\n")
            json_str = "\n".join(lines[1:-1])

        data = json.loads(json_str)

        return IncidentSummary(
            title=data.get("title", "Incident detected"),
            severity=Severity(data.get("severity", "medium").lower()),
            affected_hosts=data.get("affected_hosts", []),
            timeline=data.get("timeline", []),
            recommendation=data.get("recommendation", "Investigate further."),
            log_count=len(logs),
        )
    except (json.JSONDecodeError, httpx.HTTPError, KeyError) as e:
        logger.warning("Failed to parse LLM summary response: %s", e)
        # Fallback: generate a basic summary without LLM
        return _fallback_summary(logs)


async def generate_report(
    logs: list[NormalizedLog],
    time_range: Optional[str] = None,
) -> str:
    """Generate a full security report for a set of logs."""
    if not logs:
        return "No log data available for the specified time range."

    severity_counts = {}
    hosts = set()
    for log in logs:
        severity_counts[log.severity.value] = severity_counts.get(log.severity.value, 0) + 1
        if log.hostname:
            hosts.add(log.hostname)
        if log.source:
            hosts.add(log.source)

    stats = "\n".join(f"  - {sev}: {cnt}" for sev, cnt in sorted(severity_counts.items()))
    host_list = ", ".join(sorted(hosts)[:20])

    log_text = "\n".join(
        f"[{log.timestamp.isoformat()}] [{log.severity.value.upper()}] "
        f"host={log.hostname or log.source} | {log.message}"
        for log in logs[:100]
    )

    prompt = (
        f"Security log report{' for ' + time_range if time_range else ''}.\n\n"
        f"Statistics:\n  Total logs: {len(logs)}\n{stats}\n"
        f"  Affected hosts: {host_list}\n\n"
        f"Sample logs:\n{log_text}\n\n"
        f"Generate a professional security report."
    )

    try:
        return await _chat(prompt, system=REPORT_SYSTEM)
    except httpx.HTTPError as e:
        logger.warning("LLM report generation failed: %s", e)
        return (
            f"# Security Report (auto-generated)\n\n"
            f"**Total logs:** {len(logs)}\n\n"
            f"**Severity breakdown:**\n{stats}\n\n"
            f"**Affected hosts:** {host_list}\n\n"
            f"*Note: LLM summarization unavailable — this is a basic auto-generated report.*"
        )


def _fallback_summary(logs: list[NormalizedLog]) -> IncidentSummary:
    """Generate a basic summary without LLM."""
    hosts = set()
    max_sev = Severity.INFO
    sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

    for log in logs:
        if log.hostname:
            hosts.add(log.hostname)
        if log.source:
            hosts.add(log.source)
        if sev_order.index(log.severity) > sev_order.index(max_sev):
            max_sev = log.severity

    timeline = []
    for log in sorted(logs, key=lambda l: l.timestamp)[:10]:
        timeline.append({
            "time": log.timestamp.isoformat(),
            "event": f"[{log.severity.value.upper()}] {log.message[:100]}",
        })

    return IncidentSummary(
        title=f"Security incident involving {len(hosts)} host(s) — {len(logs)} events",
        severity=max_sev,
        affected_hosts=sorted(hosts)[:20],
        timeline=timeline,
        recommendation="Review the flagged log entries and investigate affected hosts.",
        log_count=len(logs),
    )
