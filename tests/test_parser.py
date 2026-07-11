import unittest
from datetime import datetime, timedelta, timezone

from access_log_analyzer.models import AccessLogRecord
from access_log_analyzer.parser import CombinedLogParser, ParseResult


class CombinedLogParserTests(unittest.TestCase):
    def test_parse_valid_combined_log_line(self) -> None:
        line = (
            '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] '
            '"GET /products/1877 HTTP/1.1" 200 5324 "-" '
            '"Mozilla/5.0"'
        )

        parser = CombinedLogParser()

        result = parser.parse(line)

        self.assertTrue(result.is_success)
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.record)

        record = result.record
        assert record is not None

        self.assertEqual(record.client_ip, "203.0.113.42")
        self.assertEqual(
            record.timestamp,
            datetime(2026, 6, 1, 9, 14, 22, tzinfo=timezone.utc),
        )
        self.assertEqual(record.method, "GET")
        self.assertEqual(record.request_target, "/products/1877")
        self.assertEqual(record.protocol, "HTTP/1.1")
        self.assertEqual(record.status_code, 200)
        self.assertEqual(record.response_size, 5324)
        self.assertEqual(record.referrer, "-")
        self.assertEqual(record.user_agent, "Mozilla/5.0")

    def test_parse_post_with_ipv6_timezone_and_missing_response_size(self) -> None:
        line = (
            '2001:db8::1 - - [31/Dec/2026:23:59:58 +0330] '
            '"POST /login HTTP/2" 401 - "https://example.com/start" '
            '"Example\\\"Agent"\r\n'
        )

        result = CombinedLogParser().parse(line)

        self.assertTrue(result.is_success)
        record = result.record
        assert record is not None
        self.assertEqual(record.client_ip, "2001:db8::1")
        self.assertEqual(record.method, "POST")
        self.assertEqual(record.status_code, 401)
        self.assertIsNone(record.response_size)
        self.assertEqual(record.referrer, "https://example.com/start")
        self.assertEqual(record.user_agent, 'Example"Agent')
        expected_offset = timezone(timedelta(hours=3, minutes=30)).utcoffset(None)
        self.assertEqual(record.timestamp.utcoffset(), expected_offset)

    def test_parse_rejects_malformed_lines_without_raising(self) -> None:
        malformed_lines = (
            "",
            "garbage-144 <<< malformed line",
            'not-an-ip - - [01/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1" 200 10 "-" "agent"',
            '203.0.113.42 - - [32/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1" 200 10 "-" "agent"',
            '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /" 200 10 "-" "agent"',
            '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET / FTP/1.0" 200 10 "-" "agent"',
            '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1" 999 10 "-" "agent"',
            '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] '
            '"GET / HTTP/1.1" 200 broken "-" "agent"',
            '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1" 200 10 "-"',
        )

        parser = CombinedLogParser()

        for line in malformed_lines:
            with self.subTest(line=line):
                result = parser.parse(line)
                self.assertFalse(result.is_success)
                self.assertIsNone(result.record)
                self.assertTrue(result.error)


class ParseResultTests(unittest.TestCase):
    def test_result_requires_exactly_one_of_record_or_error(self) -> None:
        with self.assertRaises(ValueError):
            ParseResult(record=None, error=None)
        with self.assertRaises(ValueError):
            ParseResult(record=None, error="")

        record = AccessLogRecord(
            client_ip="203.0.113.42",
            timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
            method="GET",
            request_target="/",
            protocol="HTTP/1.1",
            status_code=200,
            response_size=10,
            referrer="-",
            user_agent="agent",
        )
        with self.assertRaises(ValueError):
            ParseResult(record=record, error="unexpected error")
