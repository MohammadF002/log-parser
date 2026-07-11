import unittest
from datetime import datetime, timezone
from pathlib import Path

from access_log_analyzer.models import (
    AnalysisResult,
    EndpointTraffic,
    HourlyTraffic,
)
from access_log_analyzer.report import TextReportFormatter


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
