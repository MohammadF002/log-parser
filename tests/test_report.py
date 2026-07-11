import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from access_log_analyzer.models import (
    AnalysisResult,
    EndpointTraffic,
    HourlyTraffic,
)
from access_log_analyzer.report import JsonReportFormatter, TextReportFormatter


class TextReportFormatterTests(unittest.TestCase):
    def test_format_produces_summary_endpoint_table_and_histogram(self) -> None:
        result = AnalysisResult(
            processed_lines=5,
            valid_requests=4,
            malformed_lines=1,
            unique_ip_count=3,
            error_requests=2,
            endpoint_traffic=(
                EndpointTraffic(endpoint="/products", request_count=3),
                EndpointTraffic(endpoint="/login", request_count=1),
            ),
            hourly_traffic=(
                HourlyTraffic(
                    hour=datetime(2026, 6, 1, 9, tzinfo=timezone.utc),
                    request_count=1,
                ),
                HourlyTraffic(
                    hour=datetime(2026, 6, 1, 10, tzinfo=timezone.utc),
                    request_count=3,
                ),
            ),
        )

        report = TextReportFormatter(histogram_width=6).format(
            result=result,
            source_path=Path("access.log"),
            elapsed_seconds=1.25,
        )

        self.assertIn("Access Log Analysis", report)
        self.assertIn("Processed lines:    5", report)
        self.assertIn("Malformed lines:    1", report)
        self.assertIn("Error rate:         50.00%", report)
        self.assertIn("Elapsed time:       1.250 seconds", report)
        self.assertIn("Top 10 Endpoints", report)
        self.assertIn("/products", report)
        self.assertIn("Hourly Traffic (UTC)", report)
        self.assertIn("2026-06-01T10:00:00+00:00", report)
        self.assertIn("######", report)

    def test_format_handles_empty_analysis(self) -> None:
        result = AnalysisResult(
            processed_lines=0,
            valid_requests=0,
            malformed_lines=0,
            unique_ip_count=0,
            error_requests=0,
            endpoint_traffic=(),
            hourly_traffic=(),
        )

        report = TextReportFormatter().format(
            result=result,
            source_path=Path("empty.log"),
            elapsed_seconds=0.0,
        )

        self.assertEqual(report.count("(no valid requests)"), 2)
        self.assertIn("Error rate:         0.00%", report)


class JsonReportFormatterTests(unittest.TestCase):
    def test_format_produces_machine_readable_report_with_top_limit(self) -> None:
        result = AnalysisResult(
            processed_lines=4,
            valid_requests=4,
            malformed_lines=0,
            unique_ip_count=2,
            error_requests=1,
            endpoint_traffic=(
                EndpointTraffic(endpoint="/products", request_count=3),
                EndpointTraffic(endpoint="/login", request_count=1),
            ),
            hourly_traffic=(
                HourlyTraffic(
                    hour=datetime(2026, 6, 1, 9, tzinfo=timezone.utc),
                    request_count=4,
                ),
            ),
        )

        output = JsonReportFormatter(top_count=1).format(
            result=result,
            source_path=Path("access.log"),
            elapsed_seconds=1.25,
        )
        report = json.loads(output)

        self.assertEqual(report["source"], "access.log")
        self.assertEqual(report["valid_requests"], 4)
        self.assertEqual(report["error_rate_percent"], 25.0)
        self.assertEqual(report["elapsed_seconds"], 1.25)
        self.assertEqual(
            report["top_endpoints"],
            [{"endpoint": "/products", "request_count": 3}],
        )
        self.assertEqual(
            report["hourly_traffic"],
            [{"hour": "2026-06-01T09:00:00+00:00", "request_count": 4}],
        )
