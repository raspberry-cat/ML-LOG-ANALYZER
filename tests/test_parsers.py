from __future__ import annotations

import pytest

from services.parsers import LogParser


class TestParseJsonLine:
    def test_camelcase_json_format(self, json_log_line_camelcase: str):
        parser = LogParser()
        event = parser.parse_json_line(json_log_line_camelcase)
        assert event.remote_addr == "198.51.100.42"
        assert event.host == "web.example.com"
        assert event.method == "GET"
        assert event.path == "/api/v1/status"
        assert event.status == 200
        assert event.bytes_sent == 256
        assert event.request_time == pytest.approx(0.012)
        assert event.request_length == 128
        assert event.user_agent == "Mozilla/5.0 (X11; Linux x86_64)"

    def test_standard_json_format(self):
        parser = LogParser()
        line = (
            '{"timestamp":"2026-03-10T12:00:00+00:00","remote_addr":"10.0.0.1",'
            '"method":"POST","path":"/login","status":401,'
            '"bytes_sent":64,"user_agent":"curl/7.88"}'
        )
        event = parser.parse_json_line(line)
        assert event.remote_addr == "10.0.0.1"
        assert event.method == "POST"
        assert event.path == "/login"
        assert event.status == 401
        assert event.level == "WARNING"

    def test_dash_fields_become_none(self):
        parser = LogParser()
        line = (
            '{"time":"2026-03-10T12:00:00Z","method":"GET","url":"/",'
            '"statusCode":200,"remoteAddress":"1.2.3.4",'
            '"referer":"-","xForwardedFor":"-","userAgent":"-"}'
        )
        event = parser.parse_json_line(line)
        assert event.referrer is None
        assert event.x_forwarded_for is None
        assert event.user_agent is None

    def test_auto_message_construction(self, json_log_line_camelcase: str):
        parser = LogParser()
        event = parser.parse_json_line(json_log_line_camelcase)
        assert event.message != ""
        assert "GET" in event.message

    def test_iso_timestamp_parsing(self):
        parser = LogParser()
        line = '{"timestamp":"2026-03-10T08:00:00+03:00","method":"GET","path":"/","status":200}'
        event = parser.parse_json_line(line)
        assert event.timestamp.hour == 8

    def test_custom_field_mapping(self):
        parser = LogParser(
            json_field_mapping={
                "timestamp": ["ts"],
                "remote_addr": ["clientIp"],
                "path": ["requestPath"],
                "status": ["status_code"],
                "bytes_sent": ["bytes"],
                "request_time": ["latency"],
            }
        )
        line = (
            '{"ts":"2026-03-10T12:00:00+00:00","clientIp":"10.10.10.10",'
            '"method":"GET","requestPath":"/custom","status_code":202,'
            '"bytes":128,"latency":0.25}'
        )
        event = parser.parse_json_line(line)
        assert event.remote_addr == "10.10.10.10"
        assert event.path == "/custom"
        assert event.status == 202
        assert event.bytes_sent == 128
        assert event.request_time == pytest.approx(0.25)


class TestParsePlainText:
    def test_combined_log_format(self, plain_log_line: str):
        parser = LogParser()
        event = parser.parse_plain_text(plain_log_line)
        assert event.remote_addr == "198.51.100.42"
        assert event.remote_user == "admin"
        assert event.method == "POST"
        assert event.path == "/api/v1/data"
        assert event.protocol == "HTTP/1.1"
        assert event.status == 201
        assert event.bytes_sent == 512
        assert event.referrer == "https://example.com"
        assert event.request_time == pytest.approx(0.15)

    def test_level_from_status(self, plain_log_line: str):
        parser = LogParser()
        event = parser.parse_plain_text(plain_log_line)
        assert event.level == "INFO"

    def test_404_yields_warning(self):
        parser = LogParser()
        line = (
            "10.0.0.1 - - [10/Mar/2026:12:00:00 +0000] "
            '"GET /missing HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        )
        event = parser.parse_plain_text(line)
        assert event.status == 404
        assert event.level == "WARNING"

    def test_500_yields_error(self):
        parser = LogParser()
        line = (
            "10.0.0.1 - - [10/Mar/2026:12:00:00 +0000] "
            '"GET /crash HTTP/1.1" 500 0 "-" "Mozilla/5.0"'
        )
        event = parser.parse_plain_text(line)
        assert event.level == "ERROR"

    def test_invalid_format_raises(self):
        parser = LogParser()
        with pytest.raises(ValueError, match="did not match"):
            parser.parse_plain_text("this is not a log line")


class TestParseLines:
    def test_jsonl_batch(self, json_log_line_camelcase: str):
        parser = LogParser()
        lines = [json_log_line_camelcase, json_log_line_camelcase]
        events = parser.parse_lines(lines, "jsonl")
        assert len(events) == 2

    def test_plain_batch(self, plain_log_line: str):
        parser = LogParser()
        events = parser.parse_lines([plain_log_line], "plain")
        assert len(events) == 1
        assert events[0].method == "POST"

    def test_skips_blank_lines(self, json_log_line_camelcase: str):
        parser = LogParser()
        lines = ["", json_log_line_camelcase, "  ", json_log_line_camelcase]
        events = parser.parse_lines(lines, "jsonl")
        assert len(events) == 2

    def test_uses_default_source_format(self, plain_log_line: str):
        parser = LogParser(source_format="plain")
        events = parser.parse_lines([plain_log_line])
        assert len(events) == 1
        assert events[0].method == "POST"

    def test_unsupported_format_raises(self):
        parser = LogParser()
        with pytest.raises(ValueError, match="Unsupported format"):
            parser.parse_lines(["data"], "xml")
