"""Anomaly detection using vector distance, statistical methods, and severity escalation."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Optional

import numpy as np

import config
from backend.models.log_entry import AnomalyResult, NormalizedLog, Severity
from backend.storage.database import LogDatabase
from backend.storage.vectors import VectorStore

logger = logging.getLogger(__name__)

# Severity weights for threat scoring
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.2,
    Severity.INFO: 0.0,
}

# Keywords that boost threat score
_THREAT_KEYWORDS = [
    ("brute force", 0.3),
    ("unauthorized", 0.3),
    ("failed password", 0.2),
    ("denied", 0.15),
    ("attack", 0.4),
    ("malware", 0.5),
    ("exploit", 0.4),
    ("privilege escalation", 0.5),
    ("injection", 0.4),
    ("port scan", 0.3),
    ("failed login", 0.2),
    ("invalid user", 0.2),
    ("root login", 0.25),
    ("account lockout", 0.2),
]


class AnomalyDetector:
    """Multi-method anomaly detector for security logs."""

    def __init__(self, db: LogDatabase, vector_store: Optional[VectorStore] = None):
        self.db = db
        self.vector_store = vector_store

    def get_threat_score(self, log: NormalizedLog) -> float:
        """Compute a threat score (0.0 - 1.0) for a single log entry."""
        score = _SEVERITY_WEIGHT.get(log.severity, 0.0) * 0.5

        text = log.message.lower()
        for keyword, boost in _THREAT_KEYWORDS:
            if keyword in text:
                score += boost

        return min(score, 1.0)

    def detect_anomalies(
        self,
        time_window_minutes: int = 60,
    ) -> list[AnomalyResult]:
        """Run all anomaly detection methods and return combined results."""
        now = datetime.utcnow()
        start = now - timedelta(minutes=time_window_minutes)

        logs = self.db.search_logs(
            start_time=start.isoformat(),
            end_time=now.isoformat(),
            limit=5000,
        )

        if not logs:
            return []

        results: list[AnomalyResult] = []

        # Method 1: Vector distance anomalies
        if self.vector_store:
            results.extend(self._vector_distance_anomalies(logs))

        # Method 2: Statistical frequency anomalies
        results.extend(self._frequency_anomalies(logs))

        # Method 3: Severity escalation detection
        results.extend(self._severity_escalation(logs))

        # Deduplicate by log_id, keeping highest score
        seen: dict[str, AnomalyResult] = {}
        for r in results:
            if r.log_id not in seen or r.score > seen[r.log_id].score:
                seen[r.log_id] = r

        return sorted(seen.values(), key=lambda x: x.score, reverse=True)

    def _vector_distance_anomalies(self, logs: list[NormalizedLog]) -> list[AnomalyResult]:
        """Detect anomalies based on embedding distance from cluster centroid."""
        results: list[AnomalyResult] = []
        if not self.vector_store:
            return results

        anomalous = self.vector_store.find_anomalies(threshold=config.ANOMALY_DISTANCE_THRESHOLD)
        log_ids = {log.id for log in logs}

        for item in anomalous:
            if item["id"] in log_ids:
                results.append(AnomalyResult(
                    log_id=item["id"],
                    score=min(item["distance"] / 3.0, 1.0),
                    is_anomaly=True,
                    explanation=f"Log embedding is unusually distant from cluster centroid (distance={item['distance']:.3f})",
                    method="vector_distance",
                ))
        return results

    def _frequency_anomalies(self, logs: list[NormalizedLog]) -> list[AnomalyResult]:
        """Detect unusual frequency patterns using z-score analysis."""
        results: list[AnomalyResult] = []
        if len(logs) < 5:
            return results

        # Group logs into 5-minute buckets by source
        buckets: dict[str, Counter] = defaultdict(Counter)
        for log in logs:
            bucket_key = log.timestamp.strftime("%Y-%m-%dT%H:%M")[:-1] + "0"  # 10-min buckets
            buckets[log.source][bucket_key] += 1

        for source, counts in buckets.items():
            if len(counts) < 3:
                continue

            values = list(counts.values())
            mean = np.mean(values)
            std = np.std(values)

            if std == 0:
                continue

            for bucket, count in counts.items():
                zscore = (count - mean) / std
                if zscore > config.ANOMALY_FREQUENCY_ZSCORE:
                    # Find logs in this bucket
                    for log in logs:
                        log_bucket = log.timestamp.strftime("%Y-%m-%dT%H:%M")[:-1] + "0"
                        if log.source == source and log_bucket == bucket:
                            results.append(AnomalyResult(
                                log_id=log.id,
                                score=min(zscore / 5.0, 1.0),
                                is_anomaly=True,
                                explanation=(
                                    f"Unusual frequency spike from source '{source}': "
                                    f"{count} events in bucket (mean={mean:.1f}, z-score={zscore:.2f})"
                                ),
                                method="frequency_zscore",
                            ))
                            break  # One anomaly result per bucket

        return results

    def _severity_escalation(self, logs: list[NormalizedLog]) -> list[AnomalyResult]:
        """Detect sudden increases in high-severity events."""
        results: list[AnomalyResult] = []
        if len(logs) < 10:
            return results

        # Sort by timestamp
        sorted_logs = sorted(logs, key=lambda l: l.timestamp)

        # Divide into two halves — earlier vs later
        mid = len(sorted_logs) // 2
        early = sorted_logs[:mid]
        late = sorted_logs[mid:]

        high_sev = {Severity.CRITICAL, Severity.HIGH}

        early_high = sum(1 for l in early if l.severity in high_sev)
        late_high = sum(1 for l in late if l.severity in high_sev)

        early_rate = early_high / max(len(early), 1)
        late_rate = late_high / max(len(late), 1)

        # Significant escalation: rate doubles and at least 3 high-severity events
        if late_rate > early_rate * 2 and late_high >= 3:
            escalation_score = min((late_rate - early_rate) * 2, 1.0)
            for log in late:
                if log.severity in high_sev:
                    results.append(AnomalyResult(
                        log_id=log.id,
                        score=escalation_score,
                        is_anomaly=True,
                        explanation=(
                            f"Severity escalation detected: high/critical rate jumped from "
                            f"{early_rate:.1%} to {late_rate:.1%} in recent window"
                        ),
                        method="severity_escalation",
                    ))

        return results
