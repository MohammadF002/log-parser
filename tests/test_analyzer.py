import unittest
from collections.abc import Iterator
from datetime import datetime, timezone

from access_log_analyzer.analyzer import LogAnalyzer, TimeRange
from access_log_analyzer.models import EndpointTraffic, HourlyTraffic


def make_log_line(
    client_ip: str,
    timestamp: str,
    request: str,
    status_code: int,
) -> str:
    return (
        f'{client_ip} - - [{timestamp}] "{request}" '
        f'{status_code} 100 "-" "test-agent"'
    )


class OneShotLines:
    def __init__(self, lines: tuple[str, ...]) -> None:
        self._lines = lines
        self._was_iterated = False

    def __iter__(self) -> Iterator[str]:
        if self._was_iterated:
            raise AssertionError("input was iterated more than once")
        self._was_iterated = True
        yield from self._lines


class LogAnalyzerTests(unittest.TestCase):
    def test_analyze_calculates_required_statistics_in_one_pass(self) -> None:
        lines = OneShotLines(
            (
                make_log_line(
                    "203.0.113.1",
                    "01/Jun/2026:09:14:22 +0000",
                    "GET /products?sort=price HTTP/1.1",
                    200,
                ),
                make_log_line(
                    "203.0.113.2",
                    "01/Jun/2026:09:45:00 +0000",
                    "GET /products?page=2 HTTP/1.1",
                    404,
                ),
                "garbage-3 <<< malformed line",
                make_log_line(
                    "203.0.113.1",
                    "01/Jun/2026:10:00:00 +0000",
                    "POST /login HTTP/1.1",
                    401,
                ),
                make_log_line(
                    "203.0.113.3",
                    "01/Jun/2026:10:15:00 +0000",
                    "GET /health HTTP/1.1",
                    500,
                ),
            )
        )

        result = LogAnalyzer().analyze(lines)

        self.assertEqual(result.processed_lines, 5)
        self.assertEqual(result.valid_requests, 4)
        self.assertEqual(result.malformed_lines, 1)
        self.assertEqual(result.unique_ip_count, 3)
        self.assertEqual(result.error_requests, 3)
        self.assertEqual(result.error_rate_percent, 75.0)
        self.assertEqual(
            result.endpoint_traffic,
            (
                EndpointTraffic(endpoint="/products", request_count=2),
                EndpointTraffic(endpoint="/health", request_count=1),
                EndpointTraffic(endpoint="/login", request_count=1),
            ),
        )
        self.assertEqual(
            result.hourly_traffic,
            (
                HourlyTraffic(
                    hour=datetime(2026, 6, 1, 9, tzinfo=timezone.utc),
                    request_count=2,
                ),
                HourlyTraffic(
                    hour=datetime(2026, 6, 1, 10, tzinfo=timezone.utc),
                    request_count=2,
                ),
            ),
        )

    def test_analyze_normalizes_hour_buckets_to_utc(self) -> None:
        lines = (
            make_log_line(
                "203.0.113.1",
                "01/Jun/2026:12:30:00 +0330",
                "GET / HTTP/1.1",
                200,
            ),
            make_log_line(
                "203.0.113.2",
                "01/Jun/2026:09:45:00 +0000",
                "GET / HTTP/1.1",
                200,
            ),
        )

        result = LogAnalyzer().analyze(lines)

        self.assertEqual(
            result.hourly_traffic,
            (
                HourlyTraffic(
                    hour=datetime(2026, 6, 1, 9, tzinfo=timezone.utc),
                    request_count=2,
                ),
            ),
        )

    def test_analyze_empty_input_returns_zero_statistics(self) -> None:
        result = LogAnalyzer().analyze(())

        self.assertEqual(result.processed_lines, 0)
        self.assertEqual(result.valid_requests, 0)
        self.assertEqual(result.malformed_lines, 0)
        self.assertEqual(result.unique_ip_count, 0)
        self.assertEqual(result.error_rate_percent, 0.0)
        self.assertEqual(result.endpoint_traffic, ())
        self.assertEqual(result.hourly_traffic, ())

    def test_analyze_filters_with_inclusive_start_and_exclusive_end(self) -> None:
        lines = (
            make_log_line(
                "203.0.113.1",
                "01/Jun/2026:08:59:59 +0000",
                "GET /before HTTP/1.1",
                500,
            ),
            make_log_line(
                "203.0.113.2",
                "01/Jun/2026:09:00:00 +0000",
                "GET /included HTTP/1.1",
                200,
            ),
            make_log_line(
                "203.0.113.3",
                "01/Jun/2026:09:59:59 +0000",
                "GET /included HTTP/1.1",
                404,
            ),
            make_log_line(
                "203.0.113.4",
                "01/Jun/2026:10:00:00 +0000",
                "GET /after HTTP/1.1",
                500,
            ),
            "malformed line",
        )
        time_range = TimeRange(
            since=datetime(2026, 6, 1, 9, tzinfo=timezone.utc),
            until=datetime(2026, 6, 1, 10, tzinfo=timezone.utc),
        )

        result = LogAnalyzer(time_range=time_range).analyze(lines)

        self.assertEqual(result.processed_lines, 5)
        self.assertEqual(result.valid_requests, 4)
        self.assertEqual(result.filtered_requests, 2)
        self.assertEqual(result.analyzed_requests, 2)
        self.assertEqual(result.malformed_lines, 1)
        self.assertEqual(result.unique_ip_count, 2)
        self.assertEqual(result.error_requests, 1)
        self.assertEqual(result.error_rate_percent, 50.0)
        self.assertEqual(
            result.endpoint_traffic,
            (EndpointTraffic(endpoint="/included", request_count=2),),
        )

    def test_time_range_requires_ordered_timezone_aware_boundaries(self) -> None:
        with self.assertRaises(ValueError):
            TimeRange(since=datetime(2026, 6, 1, 9))
        with self.assertRaises(ValueError):
            TimeRange(
                since=datetime(2026, 6, 1, 10, tzinfo=timezone.utc),
                until=datetime(2026, 6, 1, 9, tzinfo=timezone.utc),
            )

    def test_top_endpoints_returns_requested_number(self) -> None:
        lines = (
            make_log_line(
                "203.0.113.1",
                "01/Jun/2026:09:00:00 +0000",
                "GET /first HTTP/1.1",
                200,
            ),
            make_log_line(
                "203.0.113.2",
                "01/Jun/2026:09:00:01 +0000",
                "GET /second HTTP/1.1",
                200,
            ),
        )

        result = LogAnalyzer().analyze(lines)

        self.assertEqual(
            result.top_endpoints(1),
            (EndpointTraffic(endpoint="/first", request_count=1),),
        )
        with self.assertRaises(ValueError):
            result.top_endpoints(0)
