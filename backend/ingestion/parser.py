"""Log parsers for various formats: syslog, Windows Event, JSON, CSV, CEF."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime
from typing import Optional

from dateutil import parser as dateutil_parser

from backend.models.log_entry import LogType, NormalizedLog, Severity

# ── Severity mapping helpers ──────────────────────────────────────────

_SYSLOG_SEVERITY_MAP: dict[int, Severity] = {
    0: Severity.CRITICAL,  # Emergency
    1: Severity.CRITICAL,  # Alert
    2: Severity.CRITICAL,  # Critical
    3: Severity.HIGH,      # Error
    4: Severity.MEDIUM,    # Warning
    5: Severity.LOW,       # Notice
    6: Severity.INFO,      # Informational
    7: Severity.INFO,      # Debug
}

_WINDOWS_LEVEL_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "information": Severity.INFO,
    "verbose": Severity.INFO,
    "1": Severity.CRITICAL,
    "2": Severity.HIGH,
    "3": Severity.MEDIUM,
    "4": Severity.INFO,
    "5": Severity.INFO,
}

_KEYWORD_SEVERITY: list[tuple[re.Pattern, Severity]] = [
    (re.compile(r"\b(critical|emerg|fatal|panic)\b", re.I), Severity.CRITICAL),
    (re.compile(r"\b(error|err|fail|failed|failure)\b", re.I), Severity.HIGH),
    (re.compile(r"\b(warn|warning)\b", re.I), Severity.MEDIUM),
    (re.compile(r"\b(notice|note)\b", re.I), Severity.LOW),
    (re.compile(r"\b(info|informational|debug|trace)\b", re.I), Severity.INFO),
]


def _guess_severity(text: str) -> Severity:
    """Guess severity from message keywords."""
    for pattern, sev in _KEYWORD_SEVERITY:
        if pattern.search(text):
            return sev
    return Severity.INFO


def _parse_timestamp(value: str) -> datetime:
    """Best-effort timestamp parsing."""
    try:
        return dateutil_parser.parse(value)
    except (ValueError, TypeError):
        return datetime.utcnow()


# ── Syslog Parser ─────────────────────────────────────────────────────

# RFC 3164: <PRI>Mmm dd HH:MM:SS hostname app[pid]: message
_SYSLOG_3164 = re.compile(
    r"^(?:<(\d{1,3})>)?"                         # optional PRI
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+" # timestamp
    r"([\w.\-]+)\s+"                              # hostname
    r"(\S+?)(?:\[(\d+)\])?:\s+"                   # app[pid]
    r"(.*)$"                                       # message
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
_SYSLOG_5424 = re.compile(
    r"^<(\d{1,3})>(\d+)\s+"                       # PRI + version
    r"(\S+)\s+"                                    # timestamp
    r"(\S+)\s+"                                    # hostname
    r"(\S+)\s+"                                    # app-name
    r"(\S+)\s+"                                    # procid
    r"(\S+)\s*"                                    # msgid
    r"(.*)$"                                       # structured-data + msg
)


class SyslogParser:
    """Parse RFC 3164 / 5424 syslog messages."""

    def parse(self, content: str, source_file: str = "") -> list[NormalizedLog]:
        logs: list[NormalizedLog] = []
        for line in content.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            log = self._parse_line(line, source_file)
            if log:
                logs.append(log)
        return logs

    def _parse_line(self, line: str, source_file: str) -> Optional[NormalizedLog]:
        # Try RFC 5424 first
        m = _SYSLOG_5424.match(line)
        if m:
            pri = int(m.group(1))
            severity_num = pri & 0x07
            return NormalizedLog(
                timestamp=_parse_timestamp(m.group(3)),
                hostname=m.group(4) if m.group(4) != "-" else "",
                source=m.group(5) if m.group(5) != "-" else "",
                severity=_SYSLOG_SEVERITY_MAP.get(severity_num, Severity.INFO),
                message=m.group(8).strip(),
                raw=line,
                log_type=LogType.SYSLOG,
                source_file=source_file,
                metadata={"facility": pri >> 3, "severity_num": severity_num, "version": m.group(2)},
            )

        # Try RFC 3164
        m = _SYSLOG_3164.match(line)
        if m:
            severity = Severity.INFO
            if m.group(1):
                pri = int(m.group(1))
                severity = _SYSLOG_SEVERITY_MAP.get(pri & 0x07, Severity.INFO)
            else:
                severity = _guess_severity(m.group(6))
            ts_str = m.group(2)
            # Syslog 3164 timestamps lack year — assume current year
            ts = _parse_timestamp(ts_str)
            if ts.year == 1900 or ts.year < 2000:
                ts = ts.replace(year=datetime.utcnow().year)
            return NormalizedLog(
                timestamp=ts,
                hostname=m.group(3),
                source=m.group(4),
                severity=severity,
                message=m.group(6),
                raw=line,
                log_type=LogType.SYSLOG,
                source_file=source_file,
                metadata={"pid": m.group(5)} if m.group(5) else {},
            )

        # Fallback — treat whole line as message
        return NormalizedLog(
            timestamp=datetime.utcnow(),
            source="syslog",
            severity=_guess_severity(line),
            message=line,
            raw=line,
            log_type=LogType.SYSLOG,
            source_file=source_file,
        )


# ── Windows Event Log Parser ─────────────────────────────────────────

class WindowsEventParser:
    """Parse JSON-formatted Windows Event Log entries."""

    def parse(self, content: str, source_file: str = "") -> list[NormalizedLog]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        events = data if isinstance(data, list) else [data]
        logs: list[NormalizedLog] = []
        for event in events:
            log = self._parse_event(event, source_file)
            if log:
                logs.append(log)
        return logs

    def _parse_event(self, event: dict, source_file: str) -> Optional[NormalizedLog]:
        # Extract timestamp from various possible fields
        ts_raw = (
            event.get("TimeCreated", {}).get("SystemTime")
            or event.get("TimeCreated")
            or event.get("timestamp")
            or event.get("@timestamp")
            or ""
        )
        if isinstance(ts_raw, dict):
            ts_raw = ts_raw.get("SystemTime", "")
        timestamp = _parse_timestamp(str(ts_raw)) if ts_raw else datetime.utcnow()

        level_raw = str(event.get("Level", event.get("level", "information"))).lower()
        severity = _WINDOWS_LEVEL_MAP.get(level_raw, Severity.INFO)

        message = event.get("Message", event.get("message", ""))
        hostname = event.get("Computer", event.get("computer", ""))
        event_id = event.get("EventID", event.get("eventId", ""))
        source = event.get("Source", event.get("ProviderName", ""))

        if isinstance(event_id, dict):
            event_id = event_id.get("Value", event_id.get("#text", ""))

        return NormalizedLog(
            timestamp=timestamp,
            hostname=hostname,
            source=str(source),
            severity=severity,
            message=str(message),
            raw=json.dumps(event),
            log_type=LogType.WINDOWS_EVENT,
            source_file=source_file,
            metadata={"event_id": str(event_id), "level": level_raw},
        )


# ── Generic JSON Log Parser ──────────────────────────────────────────

_TS_KEYS = ["timestamp", "@timestamp", "time", "datetime", "date", "ts", "created", "TimeCreated"]
_MSG_KEYS = ["message", "msg", "log", "text", "description", "Message"]
_SEV_KEYS = ["severity", "level", "priority", "sev", "Level"]
_SRC_KEYS = ["source", "host", "hostname", "src", "origin", "Computer"]


def _find_key(obj: dict, candidates: list[str]) -> Optional[str]:
    for k in candidates:
        if k in obj:
            return k
        lower = {key.lower(): key for key in obj}
        if k.lower() in lower:
            return lower[k.lower()]
    return None


class JsonLogParser:
    """Parse generic JSON log files — auto-detects field names."""

    def parse(self, content: str, source_file: str = "") -> list[NormalizedLog]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try JSON-lines
            data = []
            for line in content.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if isinstance(data, dict):
            data = [data]

        logs: list[NormalizedLog] = []
        for obj in data:
            if not isinstance(obj, dict):
                continue
            ts_key = _find_key(obj, _TS_KEYS)
            msg_key = _find_key(obj, _MSG_KEYS)
            sev_key = _find_key(obj, _SEV_KEYS)
            src_key = _find_key(obj, _SRC_KEYS)

            ts = _parse_timestamp(str(obj[ts_key])) if ts_key else datetime.utcnow()
            msg = str(obj.get(msg_key, "")) if msg_key else json.dumps(obj)
            sev_raw = str(obj.get(sev_key, "info")).lower() if sev_key else ""

            severity = _WINDOWS_LEVEL_MAP.get(sev_raw, None) or _guess_severity(sev_raw or msg)
            source = str(obj.get(src_key, "")) if src_key else ""

            logs.append(NormalizedLog(
                timestamp=ts,
                source=source,
                severity=severity,
                message=msg,
                raw=json.dumps(obj),
                log_type=LogType.JSON,
                source_file=source_file,
                metadata={k: v for k, v in obj.items() if k not in (ts_key, msg_key, sev_key, src_key)},
            ))
        return logs


# ── CSV Log Parser ────────────────────────────────────────────────────

class CsvLogParser:
    """Parse CSV log files with configurable column mapping."""

    DEFAULT_MAPPING = {
        "timestamp": ["timestamp", "time", "datetime", "date", "ts"],
        "source": ["source", "src", "src_ip", "host", "hostname", "origin"],
        "severity": ["severity", "level", "priority"],
        "message": ["message", "msg", "log", "description", "action"],
    }

    def __init__(self, column_mapping: Optional[dict[str, str]] = None):
        self.column_mapping = column_mapping or {}

    def parse(self, content: str, source_file: str = "") -> list[NormalizedLog]:
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames:
            return []

        # Auto-map columns
        mapping = dict(self.column_mapping)
        for field, candidates in self.DEFAULT_MAPPING.items():
            if field not in mapping:
                for c in candidates:
                    matches = [fn for fn in reader.fieldnames if fn.lower() == c.lower()]
                    if matches:
                        mapping[field] = matches[0]
                        break

        logs: list[NormalizedLog] = []
        for row in reader:
            ts_col = mapping.get("timestamp")
            ts = _parse_timestamp(row.get(ts_col, "")) if ts_col else datetime.utcnow()

            sev_col = mapping.get("severity")
            sev_raw = row.get(sev_col, "").lower() if sev_col else ""
            severity = _WINDOWS_LEVEL_MAP.get(sev_raw, None) or _guess_severity(sev_raw)

            msg_col = mapping.get("message")
            message = row.get(msg_col, "") if msg_col else ", ".join(f"{k}={v}" for k, v in row.items())

            src_col = mapping.get("source")
            source = row.get(src_col, "") if src_col else ""

            # Put remaining columns in metadata
            mapped_cols = set(mapping.values())
            metadata = {k: v for k, v in row.items() if k not in mapped_cols}

            # For firewall logs, try to build a better message if none exists
            if not msg_col and "action" in {k.lower() for k in row}:
                action_key = next(k for k in row if k.lower() == "action")
                message = row.get(action_key, "") + " " + message

            logs.append(NormalizedLog(
                timestamp=ts,
                source=source,
                severity=severity if sev_raw else _guess_severity(message),
                message=message,
                raw=json.dumps(row),
                log_type=LogType.CSV,
                source_file=source_file,
                metadata=metadata,
            ))
        return logs


# ── CEF Parser ────────────────────────────────────────────────────────

_CEF_HEADER = re.compile(
    r"^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
)

_CEF_SEVERITY_MAP: dict[str, Severity] = {
    "0": Severity.INFO, "1": Severity.INFO, "2": Severity.INFO, "3": Severity.LOW,
    "4": Severity.LOW, "5": Severity.MEDIUM, "6": Severity.MEDIUM, "7": Severity.HIGH,
    "8": Severity.HIGH, "9": Severity.CRITICAL, "10": Severity.CRITICAL,
}


class CefParser:
    """Parse Common Event Format (CEF) log lines."""

    def parse(self, content: str, source_file: str = "") -> list[NormalizedLog]:
        logs: list[NormalizedLog] = []
        for line in content.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            log = self._parse_line(line, source_file)
            if log:
                logs.append(log)
        return logs

    def _parse_line(self, line: str, source_file: str) -> Optional[NormalizedLog]:
        m = _CEF_HEADER.match(line)
        if not m:
            return None

        version, vendor, product, dev_version, sig_id, name, sev_raw, extension = m.groups()

        # Parse extension key=value pairs
        ext: dict[str, str] = {}
        for kv in re.finditer(r"(\w+)=((?:[^=](?!(?:\s\w+=)))*[^=]?)", extension):
            ext[kv.group(1)] = kv.group(2).strip()

        severity = _CEF_SEVERITY_MAP.get(sev_raw.strip(), _guess_severity(sev_raw))

        ts_raw = ext.get("rt") or ext.get("end") or ext.get("start", "")
        timestamp = _parse_timestamp(ts_raw) if ts_raw else datetime.utcnow()

        hostname = ext.get("dhost") or ext.get("shost") or ""
        source = ext.get("src") or ext.get("shost") or f"{vendor}/{product}"

        return NormalizedLog(
            timestamp=timestamp,
            hostname=hostname,
            source=source,
            severity=severity,
            message=name,
            raw=line,
            log_type=LogType.CEF,
            source_file=source_file,
            metadata={
                "cef_version": version,
                "vendor": vendor,
                "product": product,
                "device_version": dev_version,
                "signature_id": sig_id,
                **ext,
            },
        )


# ── Format Detection ─────────────────────────────────────────────────

def detect_log_format(content: str) -> LogType:
    """Auto-detect which log format the content is in."""
    stripped = content.strip()

    # CEF
    if stripped.startswith("CEF:") or "\nCEF:" in stripped:
        return LogType.CEF

    # JSON (array or object or JSONL)
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
            # Check if it looks like Windows Event Logs
            items = data if isinstance(data, list) else [data]
            if items and isinstance(items[0], dict):
                keys = set(items[0].keys())
                if keys & {"EventID", "eventId", "Level", "TimeCreated"}:
                    return LogType.WINDOWS_EVENT
            return LogType.JSON
        except json.JSONDecodeError:
            pass
    # JSONL check
    first_line = stripped.split("\n", 1)[0].strip()
    if first_line.startswith("{"):
        try:
            json.loads(first_line)
            return LogType.JSON
        except json.JSONDecodeError:
            pass

    # CSV — check if first line looks like a header
    lines = stripped.split("\n", 2)
    if len(lines) >= 2:
        first = lines[0]
        if "," in first and not first.startswith("<"):
            fields = first.split(",")
            # If all fields are simple words, it's probably a CSV header
            if all(re.match(r"^[\w_\- ]+$", f.strip()) for f in fields):
                return LogType.CSV

    # Syslog
    if re.match(r"^(<\d{1,3}>)?\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", stripped):
        return LogType.SYSLOG
    if re.match(r"^<\d{1,3}>\d+\s+", stripped):
        return LogType.SYSLOG

    return LogType.SYSLOG  # Default to syslog as most common


def parse_logs(content: str, log_type: Optional[LogType] = None, source_file: str = "") -> list[NormalizedLog]:
    """Parse log content using the appropriate parser."""
    if log_type is None:
        log_type = detect_log_format(content)

    parser_map = {
        LogType.SYSLOG: SyslogParser(),
        LogType.WINDOWS_EVENT: WindowsEventParser(),
        LogType.JSON: JsonLogParser(),
        LogType.CSV: CsvLogParser(),
        LogType.CEF: CefParser(),
    }

    parser = parser_map.get(log_type, SyslogParser())
    return parser.parse(content, source_file)
