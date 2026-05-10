"""Tests for log parsers."""

import json
from pathlib import Path

import pytest

from backend.ingestion.parser import (
    CefParser,
    CsvLogParser,
    JsonLogParser,
    SyslogParser,
    WindowsEventParser,
    detect_log_format,
    parse_logs,
)
from backend.models.log_entry import LogType, Severity

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_logs"


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser()
        self.content = (SAMPLE_DIR / "sample_syslog.log").read_text()

    def test_parses_all_lines(self):
        logs = self.parser.parse(self.content, source_file="sample_syslog.log")
        assert len(logs) == 30

    def test_ssh_failure_detected(self):
        logs = self.parser.parse(self.content)
        failures = [l for l in logs if "Failed password" in l.message]
        assert len(failures) == 5

    def test_hostname_extracted(self):
        logs = self.parser.parse(self.content)
        hostnames = {l.hostname for l in logs}
        assert "webserver01" in hostnames
        assert "firewall01" in hostnames

    def test_source_extracted(self):
        logs = self.parser.parse(self.content)
        sources = {l.source for l in logs}
        assert "sshd" in sources
        assert "kernel" in sources

    def test_severity_keywords(self):
        logs = self.parser.parse(self.content)
        # "Failed password" should get high severity
        failures = [l for l in logs if "Failed password" in l.message]
        for f in failures:
            assert f.severity in (Severity.HIGH, Severity.MEDIUM)

    def test_log_type_is_syslog(self):
        logs = self.parser.parse(self.content)
        for l in logs:
            assert l.log_type == LogType.SYSLOG


class TestWindowsEventParser:
    def setup_method(self):
        self.parser = WindowsEventParser()
        self.content = (SAMPLE_DIR / "sample_windows_events.json").read_text()

    def test_parses_all_events(self):
        logs = self.parser.parse(self.content, source_file="sample_windows_events.json")
        assert len(logs) == 15

    def test_event_id_in_metadata(self):
        logs = self.parser.parse(self.content)
        event_ids = [l.metadata.get("event_id") for l in logs]
        assert "4625" in event_ids
        assert "4624" in event_ids
        assert "4740" in event_ids

    def test_hostname_extracted(self):
        logs = self.parser.parse(self.content)
        hostnames = {l.hostname for l in logs}
        assert "DC01.corp.local" in hostnames

    def test_warning_event_severity(self):
        logs = self.parser.parse(self.content)
        warning_logs = [l for l in logs if l.metadata.get("event_id") == "1102"]
        assert len(warning_logs) == 1
        assert warning_logs[0].severity == Severity.MEDIUM

    def test_log_type_is_windows_event(self):
        logs = self.parser.parse(self.content)
        for l in logs:
            assert l.log_type == LogType.WINDOWS_EVENT


class TestCsvLogParser:
    def setup_method(self):
        self.parser = CsvLogParser()
        self.content = (SAMPLE_DIR / "sample_firewall.csv").read_text()

    def test_parses_all_rows(self):
        logs = self.parser.parse(self.content, source_file="sample_firewall.csv")
        assert len(logs) == 20

    def test_source_ip_in_source(self):
        logs = self.parser.parse(self.content)
        sources = {l.source for l in logs}
        assert "203.0.113.45" in sources

    def test_deny_entries_have_metadata(self):
        logs = self.parser.parse(self.content)
        deny_logs = [l for l in logs if "DENY" in l.message or "DENY" in l.raw]
        assert len(deny_logs) > 0

    def test_log_type_is_csv(self):
        logs = self.parser.parse(self.content)
        for l in logs:
            assert l.log_type == LogType.CSV


class TestJsonLogParser:
    def test_parses_jsonl(self):
        content = '{"timestamp": "2025-01-15T10:00:00", "message": "test event", "level": "error"}\n{"timestamp": "2025-01-15T10:01:00", "message": "another event", "level": "info"}'
        parser = JsonLogParser()
        logs = parser.parse(content)
        assert len(logs) == 2
        assert logs[0].severity == Severity.HIGH  # error -> high
        assert logs[1].severity == Severity.INFO


class TestCefParser:
    def test_parses_cef_line(self):
        line = "CEF:0|SecurityVendor|SecurityProduct|1.0|100|Suspicious Login|7|src=10.0.0.1 dst=10.0.0.2 dhost=webserver01 rt=Jan 15 2025 10:00:00"
        parser = CefParser()
        logs = parser.parse(line)
        assert len(logs) == 1
        assert logs[0].severity == Severity.HIGH
        assert logs[0].message == "Suspicious Login"
        assert logs[0].metadata["vendor"] == "SecurityVendor"


class TestFormatDetection:
    def test_detect_syslog(self):
        content = "Jan 15 08:23:01 webserver01 sshd[12345]: test message"
        assert detect_log_format(content) == LogType.SYSLOG

    def test_detect_json(self):
        content = '[{"timestamp": "2025-01-15", "message": "test"}]'
        assert detect_log_format(content) == LogType.JSON

    def test_detect_windows_event(self):
        content = (SAMPLE_DIR / "sample_windows_events.json").read_text()
        assert detect_log_format(content) == LogType.WINDOWS_EVENT

    def test_detect_csv(self):
        content = "timestamp,src_ip,dst_ip,action\n2025-01-15,10.0.0.1,10.0.0.2,ALLOW"
        assert detect_log_format(content) == LogType.CSV

    def test_detect_cef(self):
        content = "CEF:0|Vendor|Product|1.0|100|Name|5|key=value"
        assert detect_log_format(content) == LogType.CEF


class TestParseLogs:
    def test_auto_detect_and_parse(self):
        content = (SAMPLE_DIR / "sample_syslog.log").read_text()
        logs = parse_logs(content)
        assert len(logs) > 0
        assert all(l.log_type == LogType.SYSLOG for l in logs)
